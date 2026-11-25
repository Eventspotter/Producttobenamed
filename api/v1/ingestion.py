"""
Ingestion & Normalization API Routes.
Handles PDF/Image/CSV upload, encrypted storage, OCR/parsing, flagged field review,
human-in-the-loop confirmation, and FairPulse CanonicalEHRRecord preview.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import DEFAULT_OWNER_ID, DEFAULT_OWNER_NAME
from core.database.models import AuditLog, HealthRecord, RawUpload
from core.database.session import get_db
from core.schemas.audit import AuditLogEntry
from core.schemas.health_record import (
    ConfirmExtractionRequest,
    ExtractionResult,
    FlaggedField,
    HealthRecordResponse,
    NormalizedHealthRecord,
)
from core.security.crypto import VaultCrypto
from services.audit_service import record_audit_event, serialize_audit_rows
from services.ingestion.fairpulse_bridge import to_fairpulse_canonical_record
from services.ingestion.parser import parse_health_report
from services.ingestion.validator import validate_and_flag_extraction
from services.storage_service import store_encrypted_raw_file
from .profiles import get_vault_profile

router = APIRouter(tags=["Ingestion & Normalization"])
MAX_REPORT_BYTES = 20 * 1024 * 1024


@router.post("/ingest/upload", response_model=ExtractionResult, status_code=201)
async def upload_and_parse_report(
    request: Request,
    profile_id: str = Form(...),
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    require_review: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    """
    Uploads a health report (PDF/Image/CSV or pasted lab text), checks consent compliance,
    encrypts raw payload at rest, normalizes units, and flags low-confidence/garbled fields.
    """
    profile = await get_vault_profile(db, profile_id)

    if file is not None:
        raw_bytes = await file.read(MAX_REPORT_BYTES + 1)
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        filename = file.filename or "report.bin"
        content_type = file.content_type or "application/octet-stream"
        ext = Path(filename).suffix.lstrip(".") or "bin"
    elif raw_text and raw_text.strip():
        raw_bytes = raw_text.encode("utf-8")
        filename = "pasted_lab_report.txt"
        content_type = "text/plain"
        ext = "txt"
    else:
        raise HTTPException(status_code=400, detail="Provide either a report file (PDF/Image/CSV) or raw_text.")

    if len(raw_bytes) > MAX_REPORT_BYTES:
        raise HTTPException(status_code=413, detail="Report files must be 20 MB or smaller.")

    parsed = parse_health_report(
        raw_bytes=raw_bytes,
        filename=filename,
        content_type=content_type,
        raw_text=raw_text if file is None else None,
    )

    upload_id, storage_uri, sha256_hex, expires_at = store_encrypted_raw_file(raw_bytes, ext)
    upload_row = RawUpload(
        id=upload_id,
        profile_id=profile.id,
        original_filename=filename,
        source_format=parsed.source_format,
        mime_type=content_type,
        storage_uri=storage_uri,
        sha256_hash=sha256_hex,
        size_bytes=len(raw_bytes),
        encrypted=True,
        expires_at=expires_at,
    )
    db.add(upload_row)
    await db.flush()

    normalized, flagged, overall_conf = validate_and_flag_extraction(
        parsed, profile_age=profile.age, profile_sex=profile.sex
    )
    requires_confirmation = require_review or bool(flagged)
    status = "needs_review" if requires_confirmation else "confirmed"
    completeness = normalized.completeness_pct()
    record_id = f"rec-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc)

    record_row = HealthRecord(
        id=record_id,
        profile_id=profile.id,
        upload_id=upload_id,
        status=status,
        completeness_pct=completeness,
        overall_confidence=overall_conf,
        encrypted_payload=VaultCrypto.encrypt_json(normalized.model_dump(mode="json")),
        flagged_fields_json=json.dumps([f.model_dump(mode="json") for f in flagged]),
        confirmed_at=None if requires_confirmation else now,
    )
    db.add(record_row)
    await db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile.id,
        action="UPLOAD_REPORT",
        resource_type="raw_upload",
        resource_id=upload_id,
        client_ip=client_ip,
        metadata={
            "source_format": parsed.source_format,
            "sha256": sha256_hex,
            "size_bytes": len(raw_bytes),
        },
    )
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile.id,
        action="NORMALIZE_EXTRACT",
        resource_type="health_record",
        resource_id=record_id,
        client_ip=client_ip,
        metadata={
            "flagged_count": len(flagged),
            "completeness_pct": completeness,
            "overall_confidence": overall_conf,
            "status": status,
        },
    )
    await db.commit()

    return ExtractionResult(
        upload_id=upload_id,
        profile_id=profile.id,
        record_id=record_id,
        source_format=parsed.source_format,
        raw_hash_sha256=sha256_hex,
        normalized_record=normalized,
        requires_user_confirmation=requires_confirmation,
        flagged_fields=flagged,
        raw_text_preview=parsed.raw_text_preview,
        overall_confidence=overall_conf,
        completeness_pct=completeness,
        status=status,  # type: ignore[arg-type]
        created_at=now,
    )


@router.post("/ingest/confirm", response_model=HealthRecordResponse)
async def confirm_extracted_record(
    payload: ConfirmExtractionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Accepts user-reviewed/corrected biomarker values for a pending HealthRecord,
    re-encrypts at rest, marks status='confirmed', and appends an audit event.
    """
    await get_vault_profile(db, payload.profile_id)
    res = await db.execute(
        select(HealthRecord).where(
            HealthRecord.id == payload.record_id,
            HealthRecord.profile_id == payload.profile_id,
        )
    )
    record_row = res.scalar_one_or_none()
    if record_row is None:
        raise HTTPException(status_code=404, detail="Health record not found for profile.")

    confirmed = payload.confirmed_record
    if payload.user_notes:
        confirmed.notes = payload.user_notes
    # Update confidence scores for fields confirmed by the human user
    for field_name in NormalizedHealthRecord.model_fields:
        if field_name in ("confidence_scores", "source_units", "notes", "current_medications"):
            continue
        if getattr(confirmed, field_name) is not None:
            confirmed.confidence_scores[field_name] = 1.0

    if record_row.status == "confirmed" and confirmed.model_dump(mode="json") == VaultCrypto.decrypt_json(record_row.encrypted_payload):
        return _record_response(record_row)

    completeness = confirmed.completeness_pct()
    now = datetime.now(timezone.utc)
    record_row.encrypted_payload = VaultCrypto.encrypt_json(confirmed.model_dump(mode="json"))
    record_row.flagged_fields_json = "[]"
    record_row.status = "confirmed"
    record_row.completeness_pct = completeness
    record_row.overall_confidence = 1.0
    record_row.confirmed_at = now

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=payload.profile_id,
        action="CONFIRM_RECORD",
        resource_type="health_record",
        resource_id=record_row.id,
        client_ip=client_ip,
        metadata={"completeness_pct": completeness},
    )
    await db.commit()
    await db.refresh(record_row)

    return _record_response(record_row)


def _record_response(row: HealthRecord) -> HealthRecordResponse:
    return HealthRecordResponse(
        record_id=row.id,
        profile_id=row.profile_id,
        upload_id=row.upload_id,
        status=row.status,  # type: ignore[arg-type]
        completeness_pct=row.completeness_pct,
        overall_confidence=row.overall_confidence,
        normalized_record=NormalizedHealthRecord(**VaultCrypto.decrypt_json(row.encrypted_payload)),
        flagged_fields=[FlaggedField(**item) for item in json.loads(row.flagged_fields_json or "[]")],
        created_at=row.created_at,
        confirmed_at=row.confirmed_at,
    )


@router.post("/profiles/{profile_id}/records/{record_id}/view", response_model=List[AuditLogEntry])
async def view_report_audit(
    profile_id: str, record_id: str, request: Request, db: AsyncSession = Depends(get_db)
):
    await get_vault_profile(db, profile_id)
    record = await db.scalar(select(HealthRecord).where(
        HealthRecord.id == record_id, HealthRecord.profile_id == profile_id
    ))
    if record is None:
        raise HTTPException(status_code=404, detail="Health record not found for profile.")

    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile_id,
        action="VIEW_RECORD",
        resource_type="health_record",
        resource_id=record_id,
        client_ip=request.client.host if request.client else "127.0.0.1",
        metadata={"viewer": DEFAULT_OWNER_NAME},
    )
    resource_ids = [record_id] + ([record.upload_id] if record.upload_id else [])
    rows = await db.scalars(select(AuditLog).where(
        AuditLog.profile_id == profile_id, AuditLog.resource_id.in_(resource_ids)
    ).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(100))
    await db.commit()
    return serialize_audit_rows(list(rows))


@router.get("/profiles/{profile_id}/records", response_model=List[HealthRecordResponse])
async def get_profile_records(
    profile_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    await get_vault_profile(db, profile_id)

    res = await db.execute(
        select(HealthRecord)
        .where(HealthRecord.profile_id == profile_id)
        .order_by(desc(HealthRecord.created_at))
    )
    rows = res.scalars().all()

    results = [_record_response(row) for row in rows]

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile_id,
        action="VIEW_RECORD",
        resource_type="health_record",
        client_ip=client_ip,
        metadata={"records_returned": len(results)},
    )
    await db.commit()
    return results


@router.get("/profiles/{profile_id}/uploads")
async def get_profile_uploads(profile_id: str, db: AsyncSession = Depends(get_db)) -> List[Dict[str, Any]]:
    await get_vault_profile(db, profile_id)
    res = await db.execute(
        select(RawUpload)
        .where(RawUpload.profile_id == profile_id)
        .order_by(desc(RawUpload.created_at))
    )
    rows = res.scalars().all()
    return [
        {
            "upload_id": r.id,
            "original_filename": r.original_filename,
            "source_format": r.source_format,
            "sha256_hash": r.sha256_hash,
            "size_bytes": r.size_bytes,
            "encrypted": r.encrypted,
            "expires_at": r.expires_at,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.get("/profiles/{profile_id}/fairpulse-preview")
async def preview_fairpulse_bridge(
    profile_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Translates the profile's latest confirmed (or pending) normalized record into
    FairPulse's CanonicalEHRRecord ready for Phase 2 Synthetic Cohort generation.
    """
    await get_vault_profile(db, profile_id)
    res = await db.execute(
        select(HealthRecord)
        .where(HealthRecord.profile_id == profile_id)
        .order_by(desc(HealthRecord.created_at))
        .limit(1)
    )
    rec = res.scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail="No ingested health records available for this profile.")

    normalized = NormalizedHealthRecord(**VaultCrypto.decrypt_json(rec.encrypted_payload))
    canonical = to_fairpulse_canonical_record(profile_id=profile_id, record=normalized)

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile_id,
        action="EXPORT_COHORT_INPUT",
        resource_type="fairpulse_canonical_ehr",
        resource_id=rec.id,
        client_ip=client_ip,
        metadata={"record_status": rec.status},
    )
    await db.commit()
    return {
        "source_record_id": rec.id,
        "source_status": rec.status,
        "fairpulse_canonical_ehr": canonical,
    }

"""
Profile & Consent Management API (max 5 linked profiles per account owner).
Implements DPDP Act / HIPAA explicit consent capture for non-self profiles.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import DEFAULT_OWNER_ID
from core.database.models import HealthRecord, PatientProfile, RawUpload, UserAccount
from core.database.session import get_db
from core.schemas.profile import (
    MAX_FAMILY_PROFILES_PER_OWNER,
    ConsentRecordRequest,
    ProfileCreate,
    ProfileResponse,
)
from core.security.crypto import VaultCrypto, sha256_bytes
from services.audit_service import record_audit_event

router = APIRouter(prefix="/profiles", tags=["Profiles & Consent"])

CONSENT_STATEMENT_TEMPLATE = (
    "I confirm I have explicit informed consent under India's DPDP Act / HIPAA "
    "to upload, normalize, encrypt, and analyze health records for this profile ({version})."
)


async def get_vault_profile(
    db: AsyncSession, profile_id: str, *, require_consent: bool = True
) -> PatientProfile:
    profile = await db.scalar(
        select(PatientProfile).where(
            PatientProfile.id == profile_id, PatientProfile.owner_id == DEFAULT_OWNER_ID
        )
    )
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    if require_consent and profile.relationship_type != "self" and not profile.consent_granted:
        raise HTTPException(status_code=403, detail="Consent is required to access this profile's records.")
    return profile


async def _build_profile_response(db: AsyncSession, profile: PatientProfile) -> ProfileResponse:
    upload_count = 0
    latest_hba1c = None
    latest_bp = None
    latest_status = None
    completeness = 0

    latest_rec = None
    if profile.relationship_type == "self" or profile.consent_granted:
        latest_rec = await db.scalar(
            select(HealthRecord)
            .where(HealthRecord.profile_id == profile.id)
            .order_by(desc(HealthRecord.created_at))
            .limit(1)
        )
        upload_count = await db.scalar(
            select(func.count(RawUpload.id)).where(RawUpload.profile_id == profile.id)
        ) or 0

    if latest_rec is not None:
        latest_status = latest_rec.status
        completeness = latest_rec.completeness_pct
        try:
            payload = VaultCrypto.decrypt_json(latest_rec.encrypted_payload)
            latest_hba1c = payload.get("hba1c")
            sbp = payload.get("systolic_bp")
            dbp = payload.get("diastolic_bp")
            if sbp is not None and dbp is not None:
                latest_bp = f"{int(round(sbp))}/{int(round(dbp))}"
        except Exception:
            pass

    return ProfileResponse(
        id=profile.id,
        owner_id=profile.owner_id,
        name_alias=profile.name_alias,
        relationship=profile.relationship_type,  # type: ignore[arg-type]
        age=profile.age,
        sex=profile.sex,  # type: ignore[arg-type]
        consent_granted=profile.consent_granted,
        consent_timestamp=profile.consent_timestamp,
        consent_version=profile.consent_version,
        latest_record_status=latest_status,
        completeness_pct=completeness,
        latest_hba1c=latest_hba1c,
        latest_bp=latest_bp,
        upload_count=upload_count,
        created_at=profile.created_at,
    )


@router.get("", response_model=List[ProfileResponse])
async def list_profiles(request: Request, db: AsyncSession = Depends(get_db)):
    res = await db.execute(
        select(PatientProfile)
        .where(PatientProfile.owner_id == DEFAULT_OWNER_ID)
        .order_by(PatientProfile.created_at.asc())
    )
    profiles = res.scalars().all()
    return [await _build_profile_response(db, p) for p in profiles]


@router.post("", response_model=ProfileResponse, status_code=201)
async def create_profile(
    payload: ProfileCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Serialize profile creation for this owner so concurrent requests share the same limit.
    await db.execute(
        update(UserAccount).where(UserAccount.id == DEFAULT_OWNER_ID)
        .values(display_name=UserAccount.display_name)
    )
    is_self = payload.relationship == "self"
    existing_count = await db.scalar(select(func.count(PatientProfile.id)).where(
        PatientProfile.owner_id == DEFAULT_OWNER_ID,
        PatientProfile.relationship_type == "self" if is_self else PatientProfile.relationship_type != "self",
    ))
    if is_self and existing_count:
        raise HTTPException(status_code=400, detail="The vault already has a self profile.")
    if not is_self and (existing_count or 0) >= MAX_FAMILY_PROFILES_PER_OWNER:
        raise HTTPException(
            status_code=400,
            detail=f"Profile limit reached: maximum {MAX_FAMILY_PROFILES_PER_OWNER} family members per account.",
        )

    now = datetime.now(timezone.utc)
    profile_id = f"prof-{uuid.uuid4().hex[:10]}"
    consent_hash = (
        sha256_bytes(CONSENT_STATEMENT_TEMPLATE.format(version=payload.consent_version).encode("utf-8"))
        if payload.consent_granted
        else None
    )

    profile = PatientProfile(
        id=profile_id,
        owner_id=DEFAULT_OWNER_ID,
        name_alias=payload.name_alias.strip(),
        relationship_type=payload.relationship,
        age=payload.age,
        sex=payload.sex,
        consent_granted=payload.consent_granted,
        consent_timestamp=now if payload.consent_granted else None,
        consent_version=payload.consent_version if payload.consent_granted else None,
        consent_text_hash=consent_hash,
    )
    db.add(profile)
    await db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile.id,
        action="CREATE_PROFILE",
        resource_type="patient_profile",
        resource_id=profile.id,
        client_ip=client_ip,
        metadata={
            "relationship": payload.relationship,
            "consent_granted": payload.consent_granted,
        },
    )
    if payload.consent_granted:
        await record_audit_event(
            db,
            user_id=DEFAULT_OWNER_ID,
            profile_id=profile.id,
            action="GRANT_CONSENT",
            resource_type="consent",
            resource_id=profile.id,
            client_ip=client_ip,
            metadata={"consent_version": payload.consent_version, "relationship": payload.relationship},
        )

    await db.commit()
    await db.refresh(profile)
    return await _build_profile_response(db, profile)


@router.post("/{profile_id}/consent", response_model=ProfileResponse)
async def update_consent(
    profile_id: str,
    payload: ConsentRecordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    profile = await get_vault_profile(db, profile_id, require_consent=False)

    if payload.consent_granted and not payload.acknowledged_by_uploader:
        raise HTTPException(
            status_code=400,
            detail="Uploader must explicitly acknowledge consent authority before granting consent.",
        )

    now = datetime.now(timezone.utc)
    profile.consent_granted = payload.consent_granted
    profile.consent_timestamp = now if payload.consent_granted else None
    profile.consent_version = payload.consent_version if payload.consent_granted else None
    profile.consent_text_hash = (
        sha256_bytes(CONSENT_STATEMENT_TEMPLATE.format(version=payload.consent_version).encode("utf-8"))
        if payload.consent_granted
        else None
    )

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile.id,
        action="GRANT_CONSENT" if payload.consent_granted else "REVOKE_CONSENT",
        resource_type="consent",
        resource_id=profile.id,
        client_ip=client_ip,
        metadata={"consent_version": payload.consent_version},
    )
    await db.commit()
    await db.refresh(profile)
    return await _build_profile_response(db, profile)


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(
    profile_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    profile = await get_vault_profile(db, profile_id, require_consent=False)

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_event(
        db,
        user_id=DEFAULT_OWNER_ID,
        profile_id=profile.id,
        action="DELETE_PROFILE",
        resource_type="patient_profile",
        resource_id=profile.id,
        client_ip=client_ip,
        metadata={"relationship": profile.relationship_type},
    )
    await db.delete(profile)
    await db.commit()

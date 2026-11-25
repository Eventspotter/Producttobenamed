"""Audit log inspection, cryptographic chain verification, and vault health endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database.models import AuditLog
from core.config import DEFAULT_OWNER_ID
from core.database.session import get_db
from core.schemas.audit import AuditLogListResponse
from services.audit_service import serialize_audit_rows, verify_chain_links
from .profiles import get_vault_profile

router = APIRouter(tags=["Audit & Compliance"])


@router.get("/health")
async def vault_health():
    return {
        "status": "healthy",
        "phase": "Phase 0 + Phase 1 (Ingestion & Data Layer)",
        "encryption_at_rest": "Fernet-AES128-HMAC",
        "dpdp_hipaa_consent_gate": True,
        "max_profiles_per_owner": 6,
        "max_family_profiles_per_owner": 5,
        "fairpulse_bridge": "ready",
    }


@router.get("/audit/logs", response_model=AuditLogListResponse)
async def list_audit_logs(
    profile_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    # Verify full chain chronologically
    all_asc_res = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()))
    all_asc = all_asc_res.scalars().all()
    chain_ok = verify_chain_links(list(all_asc))

    query = select(AuditLog).where(AuditLog.user_id == DEFAULT_OWNER_ID)
    count_query = select(func.count(AuditLog.id)).where(AuditLog.user_id == DEFAULT_OWNER_ID)
    if profile_id:
        await get_vault_profile(db, profile_id)
        query = query.where(AuditLog.profile_id == profile_id)
        count_query = count_query.where(AuditLog.profile_id == profile_id)
    if action:
        query = query.where(AuditLog.action == action)
        count_query = count_query.where(AuditLog.action == action)

    total = int((await db.execute(count_query)).scalar_one() or 0)
    rows_res = await db.execute(
        query.order_by(desc(AuditLog.timestamp), desc(AuditLog.id)).limit(limit)
    )
    rows = list(rows_res.scalars().all())
    return AuditLogListResponse(
        total=total,
        chain_verified=chain_ok,
        entries=serialize_audit_rows(rows),
    )

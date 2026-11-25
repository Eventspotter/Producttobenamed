"""
Immutable, hash-chained audit logging service.
Every view, upload, normalization, confirmation, and consent change is logged.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database.models import AuditLog
from core.schemas.audit import AuditAction, AuditLogEntry
from core.security.crypto import hash_identifier

GENESIS_HASH = "0" * 64


def _compute_entry_hash(
    *,
    entry_id: str,
    user_id: str,
    profile_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    ip_hash: str,
    timestamp_iso: str,
    prev_hash: str,
    metadata_json: str,
) -> str:
    payload = json.dumps(
        {
            "id": entry_id,
            "user_id": user_id,
            "profile_id": profile_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "ip_hash": ip_hash,
            "timestamp": timestamp_iso,
            "prev_hash": prev_hash,
            "metadata_json": metadata_json,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def record_audit_event(
    db: AsyncSession,
    *,
    user_id: str,
    action: AuditAction,
    resource_type: str,
    resource_id: Optional[str] = None,
    profile_id: Optional[str] = None,
    client_ip: str = "127.0.0.1",
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """Appends a hash-chained audit event to audit_logs."""
    last_row_res = await db.execute(
        select(AuditLog.entry_hash).order_by(desc(AuditLog.timestamp), desc(AuditLog.id)).limit(1)
    )
    prev_hash = last_row_res.scalar_one_or_none() or GENESIS_HASH

    entry_id = f"aud-{uuid.uuid4().hex[:12]}"
    ts = datetime.now(timezone.utc)
    ip_hash = hash_identifier(client_ip or "unknown")
    meta_str = json.dumps(metadata or {}, sort_keys=True, default=str)

    entry_hash = _compute_entry_hash(
        entry_id=entry_id,
        user_id=user_id,
        profile_id=profile_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_hash=ip_hash,
        timestamp_iso=ts.isoformat(),
        prev_hash=prev_hash,
        metadata_json=meta_str,
    )

    row = AuditLog(
        id=entry_id,
        user_id=user_id,
        profile_id=profile_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_hash=ip_hash,
        timestamp=ts,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        metadata_json=meta_str,
    )
    db.add(row)
    await db.flush()
    return row


def serialize_audit_rows(rows: List[AuditLog]) -> List[AuditLogEntry]:
    entries: List[AuditLogEntry] = []
    for row in rows:
        try:
            meta = json.loads(row.metadata_json or "{}")
        except json.JSONDecodeError:
            meta = {}
        entries.append(
            AuditLogEntry(
                id=row.id,
                user_id=row.user_id,
                profile_id=row.profile_id,
                action=row.action,  # type: ignore[arg-type]
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                ip_hash=row.ip_hash,
                timestamp=row.timestamp,
                entry_hash=row.entry_hash,
                prev_hash=row.prev_hash,
                metadata=meta,
            )
        )
    return entries


def verify_chain_links(rows_asc: List[AuditLog]) -> bool:
    """Verifies prev_hash linkage across chronological audit rows."""
    expected_prev = GENESIS_HASH
    for row in rows_asc:
        if row.prev_hash != expected_prev:
            return False
        expected_prev = row.entry_hash
    return True

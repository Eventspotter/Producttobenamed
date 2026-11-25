"""
Phase 0 Audit Log Contract.
Tracks every view, upload, normalization, confirmation, and export event.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

AuditAction = Literal[
    "CREATE_PROFILE",
    "VIEW_PROFILE",
    "DELETE_PROFILE",
    "GRANT_CONSENT",
    "REVOKE_CONSENT",
    "UPLOAD_REPORT",
    "NORMALIZE_EXTRACT",
    "CONFIRM_RECORD",
    "VIEW_RECORD",
    "EXPORT_COHORT_INPUT",
    "DELETE_UPLOAD",
]


class AuditLogEntry(BaseModel):
    """Immutable audit log record returned by the API."""

    id: str
    user_id: str
    profile_id: Optional[str] = None
    action: AuditAction
    resource_type: str
    resource_id: Optional[str] = None
    ip_hash: str
    timestamp: datetime
    entry_hash: str
    prev_hash: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuditLogListResponse(BaseModel):
    """Paginated audit log list with cryptographic chain verification flag."""

    total: int
    chain_verified: bool
    entries: List[AuditLogEntry]

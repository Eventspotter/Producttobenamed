"""
Phase 0 Profile & Consent Contracts.
Supports up to 5 linked profiles per account owner with explicit DPDP/HIPAA consent tracking.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator

MAX_FAMILY_PROFILES_PER_OWNER = 5

RelationshipType = Literal["self", "spouse", "child", "parent", "mother", "father", "sibling", "other"]


class ProfileCreate(BaseModel):
    """Request to register a new linked profile under the owner's vault."""

    name_alias: str = Field(..., min_length=1, max_length=80, description="Display label (e.g. 'Self', 'Mother')")
    relationship: RelationshipType = Field("self", description="Relationship to account owner")
    age: int = Field(..., ge=0, le=120)
    sex: Literal["M", "F", "O"] = "M"
    consent_granted: bool = Field(
        False,
        description="Must be True for non-self profiles before health reports can be uploaded",
    )
    consent_version: str = Field("dpdp-hipaa-v1.0", max_length=32)

    @model_validator(mode="after")
    def auto_self_consent(self) -> "ProfileCreate":
        if self.relationship == "self" and not self.consent_granted:
            # Self-profile uploader implies primary consent, though explicit toggle is supported
            self.consent_granted = True
        return self


class ConsentRecordRequest(BaseModel):
    """Explicit DPDP Act / HIPAA consent capture for a linked profile."""

    consent_granted: bool
    consent_version: str = Field("dpdp-hipaa-v1.0", max_length=32)
    acknowledged_by_uploader: bool = Field(
        True,
        description="Uploader confirms legal authority / explicit consent from the profile subject",
    )


class ProfileResponse(BaseModel):
    """Serialized profile summary with latest clinical ingestion state."""

    id: str
    owner_id: str
    name_alias: str
    relationship: RelationshipType
    age: int
    sex: Literal["M", "F", "O"]
    consent_granted: bool
    consent_timestamp: Optional[datetime] = None
    consent_version: Optional[str] = None
    latest_record_status: Optional[str] = None
    completeness_pct: int = 0
    latest_hba1c: Optional[float] = None
    latest_bp: Optional[str] = None
    upload_count: int = 0
    created_at: datetime

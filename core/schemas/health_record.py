"""
Phase 0 Canonical Health Record Schema.
Single source of truth for normalized lab reports, vitals, and lifestyle inputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator

SexType = Literal["M", "F", "O"]
SmokingStatus = Literal["never", "former", "active"]
AlcoholConsumption = Literal["none", "moderate", "heavy"]

CORE_BIOMARKER_FIELDS = (
    "age",
    "sex",
    "hba1c",
    "fasting_glucose",
    "total_cholesterol",
    "hdl",
    "ldl",
    "triglycerides",
    "systolic_bp",
    "diastolic_bp",
    "bmi",
    "smoking_status",
)


class NormalizedHealthRecord(BaseModel):
    """Canonical normalized biomarker and lifestyle profile."""

    # Demographics
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    sex: Optional[SexType] = Field(None, description="Biological sex (M, F, O)")
    ethnicity: Optional[str] = Field(None, max_length=64, description="Optional demographic ethnicity")

    # Glycemic panel
    hba1c: Optional[float] = Field(None, ge=3.0, le=20.0, description="Glycated Hemoglobin HbA1c (%)")
    fasting_glucose: Optional[float] = Field(None, ge=20.0, le=800.0, description="Fasting blood glucose (mg/dL)")
    postprandial_glucose: Optional[float] = Field(None, ge=20.0, le=900.0, description="Postprandial glucose (mg/dL)")

    # Lipid panel
    total_cholesterol: Optional[float] = Field(None, ge=50.0, le=600.0, description="Total cholesterol (mg/dL)")
    hdl: Optional[float] = Field(None, ge=10.0, le=150.0, description="HDL cholesterol (mg/dL)")
    ldl: Optional[float] = Field(None, ge=10.0, le=450.0, description="LDL cholesterol (mg/dL)")
    triglycerides: Optional[float] = Field(None, ge=20.0, le=2000.0, description="Triglycerides (mg/dL)")

    # Vitals & Anthropometrics
    systolic_bp: Optional[float] = Field(None, ge=50.0, le=280.0, description="Systolic blood pressure (mmHg)")
    diastolic_bp: Optional[float] = Field(None, ge=30.0, le=180.0, description="Diastolic blood pressure (mmHg)")
    heart_rate: Optional[float] = Field(None, ge=25.0, le=250.0, description="Resting heart rate (bpm)")
    weight_kg: Optional[float] = Field(None, ge=2.0, le=350.0, description="Weight in kg")
    height_cm: Optional[float] = Field(None, ge=40.0, le=260.0, description="Height in cm")
    bmi: Optional[float] = Field(None, ge=10.0, le=80.0, description="Body Mass Index (kg/m^2)")

    # Renal
    creatinine: Optional[float] = Field(None, ge=0.1, le=20.0, description="Serum creatinine (mg/dL)")
    egfr: Optional[float] = Field(None, ge=2.0, le=180.0, description="Estimated GFR (mL/min/1.73m^2)")

    # Lifestyle & Narrative Inputs
    smoking_status: Optional[SmokingStatus] = Field(None, description="never | former | active")
    alcohol_consumption: Optional[AlcoholConsumption] = Field(None, description="none | moderate | heavy")
    daily_activity_minutes: Optional[int] = Field(None, ge=0, le=600, description="Average daily exercise minutes")
    diet_type: Optional[str] = Field(None, max_length=64, description="e.g. Vegetarian, Mixed, Low-carb")
    added_sugar_intake: Optional[Literal["low", "moderate", "high"]] = None
    family_history_cvd: Optional[bool] = Field(None, description="Family history of cardiovascular disease")
    family_history_diabetes: Optional[bool] = Field(None, description="Family history of diabetes")
    current_medications: List[str] = Field(default_factory=list, description="Active medication names")

    # Extraction Provenance
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    source_units: Dict[str, str] = Field(default_factory=dict)
    notes: Optional[str] = Field(None, max_length=2000)

    @model_validator(mode="after")
    def validate_physiology_and_derive(self) -> "NormalizedHealthRecord":
        """Enforces physiological sanity and derives BMI if weight/height are available."""
        if self.systolic_bp is not None and self.diastolic_bp is not None:
            if self.systolic_bp <= self.diastolic_bp:
                raise ValueError(
                    f"Systolic BP ({self.systolic_bp}) must exceed Diastolic BP ({self.diastolic_bp})."
                )
        if self.bmi is None and self.weight_kg is not None and self.height_cm is not None:
            height_m = self.height_cm / 100.0
            if height_m > 0:
                computed = round(self.weight_kg / (height_m * height_m), 1)
                if 10.0 <= computed <= 80.0:
                    self.bmi = computed
        return self

    def completeness_pct(self) -> int:
        """Computes percentage of core schema fields populated."""
        populated = sum(1 for f in CORE_BIOMARKER_FIELDS if getattr(self, f) is not None)
        return round((populated / len(CORE_BIOMARKER_FIELDS)) * 100)


class FlaggedField(BaseModel):
    """Represents a missing, garbled, or low-confidence extraction requiring user confirmation."""

    field_name: str
    extracted_value: Optional[Any] = None
    unit: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str
    raw_snippet: Optional[str] = None
    suggested_range: Optional[str] = None
    severity: Literal["warning", "error"] = "warning"


class ExtractionResult(BaseModel):
    """Output from the Ingestion & Normalization Service for user verification."""

    upload_id: str
    profile_id: str
    record_id: str
    source_format: str
    raw_hash_sha256: str
    normalized_record: NormalizedHealthRecord
    requires_user_confirmation: bool
    flagged_fields: List[FlaggedField] = Field(default_factory=list)
    raw_text_preview: str = ""
    overall_confidence: float = Field(0.0, ge=0.0, le=1.0)
    completeness_pct: int = Field(0, ge=0, le=100)
    status: Literal["needs_review", "confirmed"] = "needs_review"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ConfirmExtractionRequest(BaseModel):
    """Payload submitted by client after user reviews/corrects flagged fields."""

    record_id: str
    profile_id: str
    confirmed_record: NormalizedHealthRecord
    user_notes: Optional[str] = None


class HealthRecordResponse(BaseModel):
    """Persisted normalized health record returned to the UI."""

    record_id: str
    profile_id: str
    upload_id: Optional[str] = None
    status: Literal["needs_review", "confirmed"]
    completeness_pct: int
    overall_confidence: float
    normalized_record: NormalizedHealthRecord
    flagged_fields: List[FlaggedField] = Field(default_factory=list)
    created_at: datetime
    confirmed_at: Optional[datetime] = None

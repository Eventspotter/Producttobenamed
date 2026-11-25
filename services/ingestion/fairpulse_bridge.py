"""
FairPulse Integration Shim.
Translates Phase 1 NormalizedHealthRecord into FairPulse.backend.enclave.schema.CanonicalEHRRecord
so the existing synthetic cohort generator consumes real normalized patient profiles seamlessly.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from core.schemas.health_record import NormalizedHealthRecord

FAIRPULSE_DIR = Path(__file__).resolve().parent.parent.parent / "FairPulse"
if str(FAIRPULSE_DIR) not in sys.path:
    sys.path.insert(0, str(FAIRPULSE_DIR))

from backend.enclave.schema import (  # type: ignore[import-not-found]
    CanonicalCondition,
    CanonicalEHRRecord,
    CanonicalObservation,
    CanonicalPatient,
)


def to_fairpulse_canonical_record(
    *,
    profile_id: str,
    record: NormalizedHealthRecord,
) -> Dict[str, Any]:
    """
    Converts a de-identified NormalizedHealthRecord into FairPulse CanonicalEHRRecord
    ready for synthetic cohort generation in Phase 2.
    """
    clamped_age = min(89, max(0, record.age or 40))
    gender = record.sex or "U"

    smoker_map = {"never": "No", "former": "Former", "active": "Yes"}
    smoker = smoker_map.get(record.smoking_status or "", None)

    has_diabetes = "Yes" if (record.hba1c is not None and record.hba1c >= 6.5) else "No"
    has_htn = (
        "Yes"
        if (
            (record.systolic_bp is not None and record.systolic_bp >= 140)
            or (record.diastolic_bp is not None and record.diastolic_bp >= 90)
        )
        else "No"
    )

    patient = CanonicalPatient(
        patient_id=f"ANON-{profile_id[-8:].upper()}",
        age=clamped_age,
        gender=gender,
        systolic_bp=record.systolic_bp,
        diastolic_bp=record.diastolic_bp,
        cholesterol=record.total_cholesterol,
        glucose=record.fasting_glucose,
        diabetes=has_diabetes,
        hba1c=record.hba1c,
        heart_rate=record.heart_rate,
        smoker=smoker,
        hypertension=has_htn,
        activity_level=float(record.daily_activity_minutes) if record.daily_activity_minutes is not None else None,
        free_text_notes=None,  # Keep raw narrative out unless redacted
    )

    observations = []
    obs_specs = [
        ("4548-4", "Hemoglobin A1c", record.hba1c, "%"),
        ("1558-6", "Fasting Glucose", record.fasting_glucose, "mg/dL"),
        ("2093-3", "Total Cholesterol", record.total_cholesterol, "mg/dL"),
        ("2085-9", "HDL Cholesterol", record.hdl, "mg/dL"),
        ("13457-7", "LDL Cholesterol", record.ldl, "mg/dL"),
        ("2571-8", "Triglycerides", record.triglycerides, "mg/dL"),
        ("8480-6", "Systolic Blood Pressure", record.systolic_bp, "mmHg"),
        ("8462-4", "Diastolic Blood Pressure", record.diastolic_bp, "mmHg"),
        ("39156-5", "Body Mass Index", record.bmi, "kg/m2"),
    ]
    now = datetime.now(timezone.utc)
    for loinc, name, val, unit in obs_specs:
        if val is not None:
            observations.append(
                CanonicalObservation(
                    observation_id=f"obs-{uuid.uuid4().hex[:8]}",
                    patient_id=patient.patient_id,
                    code=loinc,
                    display_name=name,
                    value_numeric=float(val),
                    unit=unit,
                    timestamp=now,
                )
            )

    conditions = []
    if has_diabetes == "Yes":
        conditions.append(
            CanonicalCondition(
                condition_id=f"cond-{uuid.uuid4().hex[:8]}",
                patient_id=patient.patient_id,
                code="E11.9",
                description="Type 2 diabetes mellitus (threshold inferred from HbA1c >= 6.5%)",
            )
        )
    if has_htn == "Yes":
        conditions.append(
            CanonicalCondition(
                condition_id=f"cond-{uuid.uuid4().hex[:8]}",
                patient_id=patient.patient_id,
                code="I10",
                description="Essential hypertension (threshold inferred from BP >= 140/90)",
            )
        )

    ehr = CanonicalEHRRecord(
        patient=patient,
        observations=observations,
        conditions=conditions,
    )
    return ehr.model_dump(mode="json")

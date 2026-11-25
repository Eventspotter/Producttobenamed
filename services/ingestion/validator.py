"""
Extraction Validator & Flagging Engine.
Produces human-in-the-loop FlaggedField alerts when extractions are missing,
garbled, low-confidence, or physiologically inconsistent.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from pydantic import ValidationError

from core.schemas.health_record import (
    CORE_BIOMARKER_FIELDS,
    FlaggedField,
    NormalizedHealthRecord,
)
from services.ingestion.parser import ParsedReportOutput

CONFIDENCE_THRESHOLD = 0.78

SUGGESTED_RANGES: Dict[str, str] = {
    "age": "0 – 120 years",
    "hba1c": "3.5 – 15.0 %",
    "fasting_glucose": "50 – 450 mg/dL",
    "total_cholesterol": "100 – 400 mg/dL",
    "hdl": "20 – 110 mg/dL",
    "ldl": "30 – 300 mg/dL",
    "triglycerides": "35 – 600 mg/dL",
    "systolic_bp": "70 – 240 mmHg",
    "diastolic_bp": "40 – 140 mmHg",
    "bmi": "12.0 – 60.0 kg/m^2",
    "heart_rate": "35 – 200 bpm",
}

CRITICAL_FOR_RISK_ENGINE = ("hba1c", "systolic_bp", "diastolic_bp", "total_cholesterol", "bmi")


def validate_and_flag_extraction(
    parsed: ParsedReportOutput,
    *,
    profile_age: int,
    profile_sex: str,
) -> Tuple[NormalizedHealthRecord, List[FlaggedField], float]:
    """
    Validates parsed dictionary against NormalizedHealthRecord and generates
    actionable FlaggedField items for user confirmation UX.
    """
    values: Dict[str, Any] = dict(parsed.extracted_values)
    confidence_scores: Dict[str, float] = dict(parsed.confidence_scores)

    # Backfill demographics from profile when omitted in lab report
    if "age" not in values or values["age"] is None:
        values["age"] = profile_age
        confidence_scores.setdefault("age", 0.95)
    if "sex" not in values or values["sex"] is None:
        values["sex"] = profile_sex
        confidence_scores.setdefault("sex", 0.95)

    flagged: List[FlaggedField] = []
    seen_flagged = set()

    # 1. Include parser-detected garbled or unparseable warnings
    for warn in parsed.parse_warnings:
        fname = warn["field_name"]
        seen_flagged.add(fname)
        flagged.append(
            FlaggedField(
                field_name=fname,
                extracted_value=values.get(fname),
                unit=parsed.source_units.get(fname),
                confidence=float(warn.get("confidence", 0.3)),
                reason=warn["reason"],
                raw_snippet=warn.get("raw_snippet"),
                suggested_range=SUGGESTED_RANGES.get(fname),
                severity="error" if warn.get("confidence", 0.3) < 0.4 else "warning",
            )
        )

    # 2. Check physiological boundary invert (SBP <= DBP)
    sbp = values.get("systolic_bp")
    dbp = values.get("diastolic_bp")
    if sbp is not None and dbp is not None and float(sbp) <= float(dbp):
        flagged.append(
            FlaggedField(
                field_name="systolic_bp",
                extracted_value=sbp,
                unit="mmHg",
                confidence=0.30,
                reason=f"Systolic BP ({sbp}) cannot be less than or equal to Diastolic BP ({dbp}). Please verify.",
                raw_snippet=parsed.raw_snippets.get("systolic_bp"),
                suggested_range=SUGGESTED_RANGES["systolic_bp"],
                severity="error",
            )
        )
        seen_flagged.add("systolic_bp")
        # Hold invalid inverted fields out of validated Pydantic instantiation so user fixes them
        values.pop("systolic_bp", None)
        values.pop("diastolic_bp", None)

    # 3. Validate individual numeric bounds before full model instantiation
    safe_values: Dict[str, Any] = {}
    for k, v in values.items():
        candidate_kwargs = {k: v}
        try:
            NormalizedHealthRecord(**candidate_kwargs)
            safe_values[k] = v
        except ValidationError as exc:
            if k not in seen_flagged:
                flagged.append(
                    FlaggedField(
                        field_name=k,
                        extracted_value=v,
                        unit=parsed.source_units.get(k),
                        confidence=0.25,
                        reason=f"Extracted value '{v}' is outside physiological range ({exc.errors()[0]['msg']}).",
                        raw_snippet=parsed.raw_snippets.get(k),
                        suggested_range=SUGGESTED_RANGES.get(k),
                        severity="error",
                    )
                )
                seen_flagged.add(k)

    # 4. Flag low-confidence extractions
    for fname, conf in confidence_scores.items():
        if conf < CONFIDENCE_THRESHOLD and fname not in seen_flagged and fname in safe_values:
            flagged.append(
                FlaggedField(
                    field_name=fname,
                    extracted_value=safe_values[fname],
                    unit=parsed.source_units.get(fname),
                    confidence=conf,
                    reason=f"OCR confidence ({int(conf * 100)}%) below threshold ({int(CONFIDENCE_THRESHOLD * 100)}%).",
                    raw_snippet=parsed.raw_snippets.get(fname),
                    suggested_range=SUGGESTED_RANGES.get(fname),
                    severity="warning",
                )
            )
            seen_flagged.add(fname)

    # 5. Flag missing critical biomarkers required for Phase 2 risk modeling
    for critical_field in CRITICAL_FOR_RISK_ENGINE:
        if safe_values.get(critical_field) is None and critical_field not in seen_flagged:
            flagged.append(
                FlaggedField(
                    field_name=critical_field,
                    extracted_value=None,
                    unit=None,
                    confidence=0.0,
                    reason=f"Missing critical biomarker '{critical_field}' needed for Phase 2 risk trajectory modeling.",
                    raw_snippet=None,
                    suggested_range=SUGGESTED_RANGES.get(critical_field),
                    severity="warning",
                )
            )
            seen_flagged.add(critical_field)

    normalized = NormalizedHealthRecord(
        **safe_values,
        confidence_scores=confidence_scores,
        source_units=parsed.source_units,
    )

    present_confs = [
        confidence_scores.get(f, 0.0)
        for f in CORE_BIOMARKER_FIELDS
        if getattr(normalized, f) is not None
    ]
    overall_conf = round(sum(present_confs) / len(present_confs), 2) if present_confs else 0.0

    return normalized, flagged, overall_conf

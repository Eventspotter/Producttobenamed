"""
Unit Normalizer and Clinical Lab Alias Mapper.
Standardizes international SI units (mmol/L, umol/L, lbs, inches) into canonical US/Indian clinical units.
"""

from __future__ import annotations

from typing import Optional, Tuple

FIELD_ALIASES = {
    "age": "age",
    "patient_age": "age",
    "sex": "sex",
    "gender": "sex",
    "hba1c": "hba1c",
    "a1c": "hba1c",
    "glycosylated_haemoglobin": "hba1c",
    "glycosylated_hemoglobin": "hba1c",
    "fasting_glucose": "fasting_glucose",
    "fasting_blood_sugar": "fasting_glucose",
    "fbs": "fasting_glucose",
    "glucose_fasting": "fasting_glucose",
    "glucose": "fasting_glucose",
    "postprandial_glucose": "postprandial_glucose",
    "ppbs": "postprandial_glucose",
    "pp_glucose": "postprandial_glucose",
    "total_cholesterol": "total_cholesterol",
    "cholesterol": "total_cholesterol",
    "serum_cholesterol": "total_cholesterol",
    "chol": "total_cholesterol",
    "hdl": "hdl",
    "hdl_cholesterol": "hdl",
    "ldl": "ldl",
    "ldl_cholesterol": "ldl",
    "triglycerides": "triglycerides",
    "tg": "triglycerides",
    "trigs": "triglycerides",
    "systolic_bp": "systolic_bp",
    "systolic": "systolic_bp",
    "sbp": "systolic_bp",
    "diastolic_bp": "diastolic_bp",
    "diastolic": "diastolic_bp",
    "dbp": "diastolic_bp",
    "heart_rate": "heart_rate",
    "pulse": "heart_rate",
    "hr": "heart_rate",
    "bmi": "bmi",
    "body_mass_index": "bmi",
    "weight": "weight_kg",
    "weight_kg": "weight_kg",
    "height": "height_cm",
    "height_cm": "height_cm",
    "creatinine": "creatinine",
    "serum_creatinine": "creatinine",
    "egfr": "egfr",
    "smoking_status": "smoking_status",
    "smoker": "smoking_status",
    "smoking": "smoking_status",
    "alcohol_consumption": "alcohol_consumption",
    "alcohol": "alcohol_consumption",
    "daily_activity_minutes": "daily_activity_minutes",
    "activity_minutes": "daily_activity_minutes",
    "activity_level": "daily_activity_minutes",
    "exercise_minutes": "daily_activity_minutes",
    "diet_type": "diet_type",
    "diet": "diet_type",
    "added_sugar_intake": "added_sugar_intake",
    "family_history_cvd": "family_history_cvd",
    "family_history_diabetes": "family_history_diabetes",
    "medications": "current_medications",
    "current_medications": "current_medications",
}

CANONICAL_UNITS = {
    "hba1c": "%",
    "fasting_glucose": "mg/dL",
    "postprandial_glucose": "mg/dL",
    "total_cholesterol": "mg/dL",
    "hdl": "mg/dL",
    "ldl": "mg/dL",
    "triglycerides": "mg/dL",
    "systolic_bp": "mmHg",
    "diastolic_bp": "mmHg",
    "heart_rate": "bpm",
    "weight_kg": "kg",
    "height_cm": "cm",
    "bmi": "kg/m^2",
    "creatinine": "mg/dL",
    "egfr": "mL/min/1.73m^2",
}


def normalize_unit(field_name: str, value: float, raw_unit: Optional[str]) -> Tuple[float, str]:
    """Converts common lab units into canonical units."""
    unit = (raw_unit or "").strip().lower()
    canonical_unit = CANONICAL_UNITS.get(field_name, raw_unit or "")

    if field_name in ("fasting_glucose", "postprandial_glucose"):
        if "mmol" in unit:
            return round(value * 18.0182, 1), "mg/dL"
        return round(value, 1), "mg/dL"

    if field_name in ("total_cholesterol", "hdl", "ldl"):
        if "mmol" in unit:
            return round(value * 38.67, 1), "mg/dL"
        return round(value, 1), "mg/dL"

    if field_name == "triglycerides":
        if "mmol" in unit:
            return round(value * 88.57, 1), "mg/dL"
        return round(value, 1), "mg/dL"

    if field_name == "creatinine":
        if "umol" in unit or "µmol" in unit:
            return round(value / 88.4, 2), "mg/dL"
        return round(value, 2), "mg/dL"

    if field_name == "weight_kg":
        if unit in ("lb", "lbs", "pound", "pounds"):
            return round(value * 0.453592, 1), "kg"
        return round(value, 1), "kg"

    if field_name == "height_cm":
        if unit in ("m", "meter", "meters") and value < 3.0:
            return round(value * 100.0, 1), "cm"
        if unit in ("in", "inch", "inches"):
            return round(value * 2.54, 1), "cm"
        return round(value, 1), "cm"

    return round(value, 2) if isinstance(value, float) else value, canonical_unit


def normalize_field_value(raw_key: str, raw_value: str) -> Optional[str]:
    """Maps a raw header or label to canonical field name."""
    cleaned = raw_key.strip().lower().replace("-", "_").replace(" ", "_")
    return FIELD_ALIASES.get(cleaned)

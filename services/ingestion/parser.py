"""
Multi-Format Health Report Parser (CSV, PDF, Scanned Image, Plain Text).
Extracts biomarkers, source units, raw snippets, and field-level confidence scores.
Garbage or ambiguous tokens are preserved in raw_issues rather than hallucinated.
"""

from __future__ import annotations

import csv
import io
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pdfplumber
from PIL import Image

from core.security.crypto import redact_pii
from services.ingestion.normalizer import FIELD_ALIASES, normalize_unit


@dataclass
class ParsedReportOutput:
    source_format: str
    raw_text_preview: str
    extracted_values: Dict[str, Any] = field(default_factory=dict)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    source_units: Dict[str, str] = field(default_factory=dict)
    raw_snippets: Dict[str, str] = field(default_factory=dict)
    parse_warnings: List[Dict[str, Any]] = field(default_factory=list)


_REGEX_SPECS: List[Tuple[str, re.Pattern[str], float]] = [
    (
        "hba1c",
        re.compile(r"(?:hb\s*a1c|a1c|glycosylated\s*ha?emoglobin)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(%)?", re.I),
        0.93,
    ),
    (
        "fasting_glucose",
        re.compile(r"(?:fasting\s*(?:blood\s*)?(?:glucose|sugar)|fbs)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|mmol/[lL])?", re.I),
        0.92,
    ),
    (
        "postprandial_glucose",
        re.compile(r"(?:post\s*prandial\s*(?:glucose|sugar)|ppbs|pp\s*glucose)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|mmol/[lL])?", re.I),
        0.90,
    ),
    (
        "total_cholesterol",
        re.compile(r"(?:total\s*cholesterol|serum\s*cholesterol)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|mmol/[lL])?", re.I),
        0.92,
    ),
    (
        "hdl",
        re.compile(r"(?:hdl(?:\s*cholesterol)?)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|mmol/[lL])?", re.I),
        0.90,
    ),
    (
        "ldl",
        re.compile(r"(?:ldl(?:\s*cholesterol)?)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|mmol/[lL])?", re.I),
        0.90,
    ),
    (
        "triglycerides",
        re.compile(r"(?:triglycerides?|trigs)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|mmol/[lL])?", re.I),
        0.90,
    ),
    (
        "heart_rate",
        re.compile(r"(?:heart\s*rate|pulse(?:\s*rate)?)\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(bpm|/min)?", re.I),
        0.89,
    ),
    (
        "bmi",
        re.compile(r"\bbmi\b\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(kg/m2|kg/m\^2)?", re.I),
        0.91,
    ),
    (
        "weight_kg",
        re.compile(r"(?:body\s*)?weight\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(kg|kgs|lbs?|pounds?)?", re.I),
        0.88,
    ),
    (
        "height_cm",
        re.compile(r"height\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(cm|m|in|inches)?", re.I),
        0.88,
    ),
    (
        "creatinine",
        re.compile(r"(?:serum\s*)?creatinine\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(mg/d[lL]|umol/[lL]|µmol/[lL])?", re.I),
        0.89,
    ),
    (
        "egfr",
        re.compile(r"\begfr\b\s*[:\-=]?\s*([0-9]+(?:\.[0-9]+)?)", re.I),
        0.88,
    ),
    (
        "daily_activity_minutes",
        re.compile(r"(?:daily\s*activity|exercise)\s*[:\-=]?\s*([0-9]+)\s*(?:min|mins|minutes)?", re.I),
        0.84,
    ),
]

_BP_REGEX = re.compile(
    r"(?:blood\s*pressure|b\.?p\.?)\s*[:\-=]?\s*([0-9]{2,3})\s*/\s*([0-9]{2,3})\s*(mmhg)?",
    re.I,
)
_AGE_REGEX = re.compile(r"\bage\b\s*[:\-=]?\s*([0-9]{1,3})\s*(?:yrs?|years?)?", re.I)
_SEX_REGEX = re.compile(r"\b(?:sex|gender)\b\s*[:\-=]?\s*(male|female|other|m|f|o)\b", re.I)
_SMOKING_REGEX = re.compile(r"\b(?:smoking|smoker)\b\s*[:\-=]?\s*(never|no|non-smoker|former|ex-smoker|active|yes|current)\b", re.I)
_ADDED_SUGAR_REGEX = re.compile(r"\badded\s+sugar(?:\s+intake)?\s*[:\-=]?\s*(low|moderate|high)\b", re.I)

# Detects OCR-garbled tokens like "HbA1c: 6.x%", "BP: 12O/8O", "FBS: ??? mg/dL"
_GARBLED_LINE_REGEX = re.compile(
    r"(?im)^.*(?:hba1c|glucose|fbs|cholesterol|hdl|ldl|triglycerides|bp|blood\s*pressure|bmi|creatinine).*$"
)


def _normalize_sex(val: str) -> Optional[str]:
    v = val.strip().lower()
    if v in ("m", "male"):
        return "M"
    if v in ("f", "female"):
        return "F"
    if v in ("o", "other"):
        return "O"
    return None


def _normalize_smoking(val: str) -> Optional[str]:
    v = val.strip().lower()
    if v in ("never", "no", "non-smoker", "none"):
        return "never"
    if v in ("former", "ex-smoker", "past"):
        return "former"
    if v in ("active", "yes", "current"):
        return "active"
    return None


def _parse_text_block(text: str, base_confidence_penalty: float = 0.0) -> ParsedReportOutput:
    out = ParsedReportOutput(
        source_format="TEXT",
        raw_text_preview=redact_pii(text[:2500]),
    )

    # 1. Blood pressure pair
    bp_match = _BP_REGEX.search(text)
    if bp_match:
        sbp_val = float(bp_match.group(1))
        dbp_val = float(bp_match.group(2))
        conf = max(0.35, round(0.93 - base_confidence_penalty, 2))
        out.extracted_values["systolic_bp"] = sbp_val
        out.extracted_values["diastolic_bp"] = dbp_val
        out.confidence_scores["systolic_bp"] = conf
        out.confidence_scores["diastolic_bp"] = conf
        out.source_units["systolic_bp"] = bp_match.group(3) or "mmHg"
        out.source_units["diastolic_bp"] = bp_match.group(3) or "mmHg"
        out.raw_snippets["systolic_bp"] = bp_match.group(0).strip()
        out.raw_snippets["diastolic_bp"] = bp_match.group(0).strip()

    # 2. Age, sex, smoking
    age_match = _AGE_REGEX.search(text)
    if age_match:
        out.extracted_values["age"] = int(age_match.group(1))
        out.confidence_scores["age"] = max(0.4, round(0.94 - base_confidence_penalty, 2))
        out.raw_snippets["age"] = age_match.group(0).strip()

    sex_match = _SEX_REGEX.search(text)
    if sex_match:
        sex_norm = _normalize_sex(sex_match.group(1))
        if sex_norm:
            out.extracted_values["sex"] = sex_norm
            out.confidence_scores["sex"] = max(0.4, round(0.95 - base_confidence_penalty, 2))
            out.raw_snippets["sex"] = sex_match.group(0).strip()

    smoke_match = _SMOKING_REGEX.search(text)
    if smoke_match:
        smoke_norm = _normalize_smoking(smoke_match.group(1))
        if smoke_norm:
            out.extracted_values["smoking_status"] = smoke_norm
            out.confidence_scores["smoking_status"] = max(0.4, round(0.88 - base_confidence_penalty, 2))
            out.raw_snippets["smoking_status"] = smoke_match.group(0).strip()

    sugar_match = _ADDED_SUGAR_REGEX.search(text)
    if sugar_match:
        out.extracted_values["added_sugar_intake"] = sugar_match.group(1).lower()
        out.confidence_scores["added_sugar_intake"] = round(0.9 - base_confidence_penalty, 2)

    # 3. Quantitative biomarkers
    for field_name, pattern, default_conf in _REGEX_SPECS:
        m = pattern.search(text)
        if m:
            raw_num = float(m.group(1))
            raw_unit = m.group(2) if m.lastindex and m.lastindex >= 2 else None
            norm_val, norm_unit = normalize_unit(field_name, raw_num, raw_unit)
            conf = max(0.35, round(default_conf - base_confidence_penalty, 2))
            out.extracted_values[field_name] = int(norm_val) if field_name == "daily_activity_minutes" else norm_val
            out.confidence_scores[field_name] = conf
            out.source_units[field_name] = f"{raw_unit or norm_unit} -> {norm_unit}" if raw_unit and raw_unit != norm_unit else norm_unit
            out.raw_snippets[field_name] = m.group(0).strip()

    # 4. Scan for garbled lines where a clinical term exists without a clean valid number
    for line_match in _GARBLED_LINE_REGEX.finditer(text):
        line = line_match.group(0).strip()
        if any(tok in line for tok in ("?", "~", "garbled", "illegible", "x%", "O/")):
            lower = line.lower()
            lipid = re.search(r"\b(ldl|hdl)\b", lower)
            guessed_field = lipid.group(1) if lipid else "hba1c" if "a1c" in lower else (
                "systolic_bp" if "bp" in lower or "pressure" in lower else (
                    "fasting_glucose" if "glucose" in lower or "fbs" in lower else (
                        "total_cholesterol" if "cholesterol" in lower else "unknown_biomarker"
                    )
                )
            )
            if guessed_field in ("ldl", "hdl"):
                out.extracted_values.pop(guessed_field, None)
                out.source_units.pop(guessed_field, None)
            out.parse_warnings.append(
                {
                    "field_name": guessed_field,
                    "raw_snippet": redact_pii(line[:140]),
                    "reason": "Garbled or ambiguous characters detected in lab report line; user confirmation required.",
                    "confidence": 0.35,
                }
            )
            if guessed_field in out.confidence_scores:
                out.confidence_scores[guessed_field] = min(out.confidence_scores[guessed_field], 0.45)

    return out


def _parse_csv_bytes(raw_bytes: bytes) -> ParsedReportOutput:
    text = raw_bytes.decode("utf-8", errors="replace").strip()
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    out = ParsedReportOutput(source_format="CSV", raw_text_preview=redact_pii(text[:2500]))
    if not rows:
        out.parse_warnings.append(
            {
                "field_name": "file",
                "raw_snippet": "",
                "reason": "CSV file contained no data rows.",
                "confidence": 0.0,
            }
        )
        return out

    row = rows[0]
    for raw_col, raw_val in row.items():
        if not raw_col or raw_val is None:
            continue
        col_norm = raw_col.strip().lower().replace(" ", "_").replace("-", "_")
        canonical = FIELD_ALIASES.get(col_norm)
        if not canonical:
            continue
        val_str = str(raw_val).strip()
        if not val_str or val_str.lower() in ("na", "n/a", "null", "none", "nan", "?", "-"):
            out.parse_warnings.append(
                {
                    "field_name": canonical,
                    "raw_snippet": f"{raw_col}: {val_str}",
                    "reason": f"Missing or placeholder value '{val_str}' in CSV column '{raw_col}'.",
                    "confidence": 0.25,
                }
            )
            continue

        if canonical == "sex":
            sx = _normalize_sex(val_str)
            if sx:
                out.extracted_values["sex"] = sx
                out.confidence_scores["sex"] = 0.99
            else:
                out.parse_warnings.append(
                    {
                        "field_name": "sex",
                        "raw_snippet": f"{raw_col}: {val_str}",
                        "reason": f"Unrecognized sex value '{val_str}'. Expected M, F, or O.",
                        "confidence": 0.3,
                    }
                )
        elif canonical == "smoking_status":
            sm = _normalize_smoking(val_str)
            if sm:
                out.extracted_values["smoking_status"] = sm
                out.confidence_scores["smoking_status"] = 0.98
            else:
                out.parse_warnings.append(
                    {
                        "field_name": "smoking_status",
                        "raw_snippet": f"{raw_col}: {val_str}",
                        "reason": f"Ambiguous smoking status '{val_str}'.",
                        "confidence": 0.4,
                    }
                )
        elif canonical in ("family_history_cvd", "family_history_diabetes"):
            out.extracted_values[canonical] = val_str.lower() in ("yes", "true", "1", "y")
            out.confidence_scores[canonical] = 0.98
        elif canonical == "current_medications":
            out.extracted_values[canonical] = [m.strip() for m in val_str.split(";") if m.strip()]
            out.confidence_scores[canonical] = 0.96
        elif canonical == "added_sugar_intake" and val_str.lower() in ("low", "moderate", "high"):
            out.extracted_values[canonical] = val_str.lower()
            out.confidence_scores[canonical] = 0.99
        elif canonical == "diet_type":
            out.extracted_values[canonical] = val_str
            out.confidence_scores[canonical] = 0.96
        else:
            # Parse numeric value possibly carrying unit e.g. "6.8 mmol/L"
            num_match = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z/%µ^0-9]+)?\s*$", val_str)
            if not num_match:
                out.parse_warnings.append(
                    {
                        "field_name": canonical,
                        "raw_snippet": f"{raw_col}: {val_str}",
                        "reason": f"Could not parse numeric biomarker value '{val_str}'.",
                        "confidence": 0.25,
                    }
                )
                continue
            num_val = float(num_match.group(1))
            raw_unit = num_match.group(2)
            norm_val, norm_unit = normalize_unit(canonical, num_val, raw_unit)
            out.extracted_values[canonical] = int(norm_val) if canonical in ("age", "daily_activity_minutes") else norm_val
            out.confidence_scores[canonical] = 0.98
            out.source_units[canonical] = norm_unit
            out.raw_snippets[canonical] = f"{raw_col}: {val_str}"

    return out


def _parse_pdf_bytes(raw_bytes: bytes) -> ParsedReportOutput:
    extracted_chunks: List[str] = []
    with pdfplumber.open(io.BytesIO(raw_bytes)) as pdf:
        for page in pdf.pages[:10]:
            page_text = page.extract_text() or ""
            if page_text:
                extracted_chunks.append(page_text)
            for table in page.extract_tables() or []:
                for row in table:
                    cleaned_cells = [c.strip() for c in row if c and c.strip()]
                    if cleaned_cells:
                        extracted_chunks.append(" : ".join(cleaned_cells))

    full_text = "\n".join(extracted_chunks).strip()
    if not full_text:
        return ParsedReportOutput(
            source_format="PDF",
            raw_text_preview="",
            parse_warnings=[
                {
                    "field_name": "document",
                    "raw_snippet": "Scanned / image-only PDF with no selectable text layer.",
                    "reason": "No extractable text layer found in PDF; please verify or enter biomarkers manually.",
                    "confidence": 0.2,
                }
            ],
        )
    out = _parse_text_block(full_text, base_confidence_penalty=0.04)
    out.source_format = "PDF"
    return out


def _parse_image_bytes(raw_bytes: bytes) -> ParsedReportOutput:
    with Image.open(io.BytesIO(raw_bytes)) as img:
        width, height = img.size
        img_info = f"Image {width}x{height} ({img.format or 'UNKNOWN'})"

    tesseract_bin = shutil.which("tesseract")
    if tesseract_bin:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=True) as tmp:
            with Image.open(io.BytesIO(raw_bytes)) as img:
                img.convert("RGB").save(tmp.name, format="PNG")
            proc = subprocess.run(
                [tesseract_bin, tmp.name, "stdout", "--psm", "6"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            ocr_text = proc.stdout.strip()
            if ocr_text:
                out = _parse_text_block(ocr_text, base_confidence_penalty=0.14)
                out.source_format = "IMAGE"
                return out

    return ParsedReportOutput(
        source_format="IMAGE",
        raw_text_preview=f"[{img_info}] Local OCR binary unavailable or produced empty text; manual confirmation required.",
        parse_warnings=[
            {
                "field_name": "document",
                "raw_snippet": img_info,
                "reason": "Scanned image requires visual verification/manual entry before vault commit.",
                "confidence": 0.3,
            }
        ],
    )


def parse_health_report(
    *,
    raw_bytes: Optional[bytes] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
    raw_text: Optional[str] = None,
) -> ParsedReportOutput:
    """Dispatches report parsing based on extension, MIME type, or pasted lab text."""
    if raw_text and not raw_bytes:
        return _parse_text_block(raw_text)

    if not raw_bytes:
        raise ValueError("Either file bytes or raw_text must be provided.")

    ext = Path(filename or "").suffix.lower()
    mime = (content_type or "").lower()

    if ext == ".csv" or "csv" in mime:
        return _parse_csv_bytes(raw_bytes)
    if ext == ".pdf" or "pdf" in mime:
        return _parse_pdf_bytes(raw_bytes)
    if ext in (".png", ".jpg", ".jpeg", ".webp", ".tiff") or mime.startswith("image/"):
        return _parse_image_bytes(raw_bytes)

    # Fallback to text decode
    decoded = raw_bytes.decode("utf-8", errors="replace")
    return _parse_text_block(decoded)

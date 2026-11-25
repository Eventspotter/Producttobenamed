"""
End-to-end automated verification suite for Phase 0 & Phase 1:
- Canonical schema & unit conversion (mmol/L -> mg/dL)
- Physiological sanity & garbled extraction flagging
- 5-profile cap & DPDP/HIPAA consent enforcement
- Encrypted storage at rest & PII redaction
- Human confirmation workflow & FairPulse CanonicalEHR bridge
- Hash-chained immutable audit log integrity
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


@pytest_asyncio.fixture
async def test_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "test_vault.db"
    storage_dir = tmp_path / "uploads"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.setenv("STORAGE_DIR", str(storage_dir))

    # Reload config, db session, storage, and app cleanly against isolated temp DB
    import core.config as cfg
    import core.database.session as db_sess
    import services.storage_service as store_svc
    import app.main as app_main

    importlib.reload(cfg)
    importlib.reload(db_sess)
    importlib.reload(store_svc)
    importlib.reload(app_main)

    await db_sess.init_db()

    transport = ASGITransport(app=app_main.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client, storage_dir

    await db_sess.engine.dispose()


@pytest.mark.asyncio
async def test_profile_limit_and_consent_gate(test_client):
    client, _ = test_client

    # Create one self profile and four family members.
    created_ids = []
    for idx in range(5):
        rel = "self" if idx == 0 else "parent"
        resp = await client.post(
            "/api/v1/profiles",
            json={
                "name_alias": f"Member {idx + 1}",
                "relationship": rel,
                "age": 30 + idx * 5,
                "sex": "M" if idx % 2 == 0 else "F",
                "consent_granted": idx == 0,  # non-self profiles start without consent
            },
        )
        assert resp.status_code == 201, resp.text
        created_ids.append(resp.json()["id"])

    # Exactly one of two concurrent requests can take the last slot.
    candidates = await asyncio.gather(
        *(client.post("/api/v1/profiles", json={
            "name_alias": f"Extra Member {idx}", "relationship": "other", "age": 42, "sex": "F",
        }) for idx in range(2))
    )
    assert sorted(candidate.status_code for candidate in candidates) == [201, 400]
    extra = next(candidate for candidate in candidates if candidate.status_code == 400)
    assert "maximum 5" in extra.json()["detail"].lower()

    # Non-self profile without consent must block upload (HTTP 403)
    non_self_id = created_ids[1]
    blocked_upload = await client.post(
        "/api/v1/ingest/upload",
        data={"profile_id": non_self_id, "raw_text": "HbA1c: 6.2%\nBP: 120/80 mmHg"},
    )
    assert blocked_upload.status_code == 403

    # Grant explicit DPDP/HIPAA consent -> upload now succeeds
    consent_resp = await client.post(
        f"/api/v1/profiles/{non_self_id}/consent",
        json={"consent_granted": True, "acknowledged_by_uploader": True},
    )
    assert consent_resp.status_code == 200
    assert consent_resp.json()["consent_granted"] is True

    ok_upload = await client.post(
        "/api/v1/ingest/upload",
        data={"profile_id": non_self_id, "raw_text": "HbA1c: 6.2%\nBP: 120/80 mmHg"},
    )
    assert ok_upload.status_code == 201

    uploaded = ok_upload.json()
    await client.post(f"/api/v1/profiles/{non_self_id}/consent", json={"consent_granted": False})
    for path in ("records", "uploads", "fairpulse-preview"):
        assert (await client.get(f"/api/v1/profiles/{non_self_id}/{path}")).status_code == 403
    view_path = f"/api/v1/profiles/{non_self_id}/records/{uploaded['record_id']}/view"
    assert (await client.post(view_path)).status_code == 403
    assert (await client.post("/api/v1/ingest/confirm", json={
        "profile_id": non_self_id,
        "record_id": uploaded["record_id"],
        "confirmed_record": uploaded["normalized_record"],
    })).status_code == 403
    profiles = (await client.get("/api/v1/profiles")).json()
    hidden = next(profile for profile in profiles if profile["id"] == non_self_id)
    assert hidden["latest_hba1c"] is None and hidden["upload_count"] == 0


@pytest.mark.asyncio
async def test_csv_unit_normalization_and_encryption_at_rest(test_client):
    client, storage_dir = test_client

    prof_resp = await client.post(
        "/api/v1/profiles",
        json={"name_alias": "Self Test", "relationship": "self", "age": 48, "sex": "M"},
    )
    prof_id = prof_resp.json()["id"]

    csv_payload = (
        "age,sex,hba1c,fasting_glucose,total_cholesterol,hdl,ldl,triglycerides,systolic_bp,diastolic_bp,bmi,smoking\n"
        "48,M,6.7,7.0 mmol/L,5.5 mmol/L,42,135,160,136,84,27.1,former\n"
    ).encode("utf-8")

    up_resp = await client.post(
        "/api/v1/ingest/upload",
        data={"profile_id": prof_id},
        files={"file": ("panel.csv", csv_payload, "text/csv")},
    )
    assert up_resp.status_code == 201, up_resp.text
    body = up_resp.json()

    nr = body["normalized_record"]
    # 7.0 mmol/L glucose -> ~126.1 mg/dL
    assert abs(nr["fasting_glucose"] - 126.1) < 0.2
    # 5.5 mmol/L cholesterol -> ~212.7 mg/dL
    assert abs(nr["total_cholesterol"] - 212.7) < 0.2
    assert nr["hba1c"] == 6.7
    assert body["requires_user_confirmation"] is False
    assert body["status"] == "confirmed"

    # Verify raw file stored encrypted on disk (raw plaintext CSV must NOT appear on disk)
    enc_files = list(storage_dir.glob("*.enc"))
    assert len(enc_files) == 1
    assert b"fasting_glucose" not in enc_files[0].read_bytes()

    # Verify FairPulse CanonicalEHRRecord bridge
    fp_resp = await client.get(f"/api/v1/profiles/{prof_id}/fairpulse-preview")
    assert fp_resp.status_code == 200
    fp_data = fp_resp.json()["fairpulse_canonical_ehr"]
    assert fp_data["patient"]["patient_id"].startswith("ANON-")
    assert fp_data["patient"]["diabetes"] == "Yes"
    assert len(fp_data["observations"]) >= 7


@pytest.mark.asyncio
async def test_garbled_flagging_confirmation_and_audit_chain(test_client):
    client, _ = test_client

    prof_resp = await client.post(
        "/api/v1/profiles",
        json={"name_alias": "Parent Check", "relationship": "parent", "age": 62, "sex": "F", "consent_granted": True},
    )
    prof_id = prof_resp.json()["id"]

    messy_report = (
        "Patient Name: Jane Confidential\n"
        "Phone: 9876543210\n"
        "HbA1c: 6.x% garbled\n"
        "BP: 82/138 mmHg\n"
        "Total Cholesterol: 210 mg/dL\n"
    )
    up_resp = await client.post(
        "/api/v1/ingest/upload",
        data={"profile_id": prof_id, "raw_text": messy_report},
    )
    assert up_resp.status_code == 201
    res = up_resp.json()

    # PII must be redacted in preview
    assert "Jane Confidential" not in res["raw_text_preview"]
    assert "9876543210" not in res["raw_text_preview"]
    assert res["requires_user_confirmation"] is True
    assert res["status"] == "needs_review"
    flagged_names = {f["field_name"] for f in res["flagged_fields"]}
    assert "systolic_bp" in flagged_names or "hba1c" in flagged_names

    # User corrects values and confirms
    corrected = dict(res["normalized_record"])
    corrected["hba1c"] = 6.9
    corrected["systolic_bp"] = 138
    corrected["diastolic_bp"] = 82
    corrected["bmi"] = 25.4

    conf_resp = await client.post(
        "/api/v1/ingest/confirm",
        json={
            "record_id": res["record_id"],
            "profile_id": prof_id,
            "confirmed_record": corrected,
            "user_notes": "Verified against printed report",
        },
    )
    assert conf_resp.status_code == 200
    conf_data = conf_resp.json()
    assert conf_data["status"] == "confirmed"
    assert conf_data["overall_confidence"] == 1.0
    assert conf_data["normalized_record"]["hba1c"] == 6.9

    # Audit trail must capture all actions with verified hash chain
    audit_resp = await client.get("/api/v1/audit/logs")
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert audit_data["chain_verified"] is True
    actions = {entry["action"] for entry in audit_data["entries"]}
    assert {"CREATE_PROFILE", "GRANT_CONSENT", "UPLOAD_REPORT", "NORMALIZE_EXTRACT", "CONFIRM_RECORD"}.issubset(actions)


@pytest.mark.asyncio
async def test_dashboard_review_workflow(test_client):
    client, _ = test_client
    dashboard = await client.get("/")
    assert dashboard.status_code == 200
    assert "PulseVault" in dashboard.text
    assert "Profile Health Overview" in dashboard.text

    self_profile = await client.post("/api/v1/profiles", json={
        "name_alias": "Dashboard Test", "relationship": "self", "age": 42, "sex": "F",
    })
    profile_id = self_profile.json()["id"]
    uploaded = await client.post(
        "/api/v1/ingest/upload",
        data={"profile_id": profile_id, "require_review": "true"},
        files={"file": ("dashboard.csv", (
            "hba1c,fasting_glucose,hdl,ldl,total_cholesterol,systolic_bp,diastolic_bp,bmi,added_sugar_intake,daily_activity_minutes,smoking\n"
            "6.1,110,52,142,200,128,84,27.4,moderate,25,never\n"
        ), "text/csv")},
    )
    assert uploaded.status_code == 201
    report = uploaded.json()
    assert report["status"] == "needs_review" and report["flagged_fields"] == []
    assert report["normalized_record"]["added_sugar_intake"] == "moderate"
    payload = {
        "record_id": report["record_id"], "profile_id": profile_id,
        "confirmed_record": dict(report["normalized_record"], ldl=146.9),
    }
    for _ in range(2):
        confirmed = await client.post("/api/v1/ingest/confirm", json=payload)
        assert confirmed.status_code == 200
        assert confirmed.json()["status"] == "confirmed"
    views = await client.post(f"/api/v1/profiles/{profile_id}/records/{report['record_id']}/view")
    assert views.status_code == 200
    assert [event["action"] for event in views.json()] == [
        "VIEW_RECORD", "CONFIRM_RECORD", "NORMALIZE_EXTRACT", "UPLOAD_REPORT",
    ]
    records = (await client.get(f"/api/v1/profiles/{profile_id}/records")).json()
    assert records[0]["normalized_record"]["ldl"] == 146.9

    garbled = await client.post("/api/v1/ingest/upload", data={
        "profile_id": profile_id, "raw_text": "LDL cholesterol: 14? ???\nHbA1c: 6.1%",
    })
    assert garbled.status_code == 201
    assert garbled.json()["normalized_record"]["ldl"] is None
    assert any(flag["field_name"] == "ldl" for flag in garbled.json()["flagged_fields"])

"""
VERITAS — tests/test_photo_cv_wiring.py

Integration tests for cv_checker.verify_photo() wired into
POST /arrivals/{arrival_id}/photo.

Coverage:
  1. test_photo_upload_returns_cv_fields       — happy path: all cv_* fields present
  2. test_hash_mismatch_sets_fraud_flag        — cv_hash_mismatch flag persisted
  3. test_category_mismatch_advisory           — cv_category_mismatch flagged but 200 returned
  4. test_good_photo_passes_no_flags           — matching hash + category → no cv fraud flags
  5. test_fail_closed_on_bad_input             — empty body → cv_matched=False, save still succeeded
  6. test_cv_category_mismatch_no_block        — mismatch does NOT raise 4xx/5xx (advisory only)
  7. test_update_arrival_fraud_flags_helper    — database helper appends without duplicates
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend import database
from backend.auth import create_token
from backend.cv_checker import CVResult
from backend.main import app

# ---------------------------------------------------------------------------
# JWT secret used across all API tests
# ---------------------------------------------------------------------------

JWT_SECRET = "test-secret-veritas-32chars-ok!!"  # 32 chars


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path: Path):
    """Fresh SQLite DB with schema. Yields (db_path, connection)."""
    db_path = tmp_path / "veritas_test.db"
    database.init_db(db_path)
    conn = database.get_connection(db_path)
    yield db_path, conn
    conn.close()


@pytest.fixture()
def seeded_facility_arrival(tmp_db):
    """Insert one facility + one arrival. Returns (db_path, conn, facility, arrival)."""
    db_path, conn = tmp_db
    facility = database.register_facility(
        conn,
        name="Test Recycler",
        capacity_kg=1000.0,
        waste_category="plastic",
        pubkey_hex="a" * 64,
    )
    conn.commit()

    arrival = database.insert_arrival(
        conn,
        facility_id=facility["id"],
        device_id="gate-001",
        weight_kg=50.0,
        photo_hash_hex="deadbeef" * 8,
        timestamp_iso="2026-09-18T10:00:00+00:00",
        record_hash_hex="a" * 64,
        signature_hex="b" * 128,
        fraud_flags=[],
    )
    conn.commit()
    return db_path, conn, facility, arrival


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """TestClient with a real JWT token (veritas_admin) and an isolated DB."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("VERITAS_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("VERITAS_DB_PATH", str(db_path))
    monkeypatch.setenv("VERITAS_PHOTOS_DIR", str(tmp_path / "photos"))
    with TestClient(app) as client:
        yield client, db_path


def _admin_token() -> str:
    return create_token(role="veritas_admin", facility_id="", secret=JWT_SECRET)


def _make_arrival_via_db(db_path: Path, waste_category: str = "plastic") -> tuple[dict, dict]:
    """Insert facility + arrival directly in the DB and return both."""
    conn = database.get_connection(db_path)
    facility = database.register_facility(
        conn,
        name=f"Facility-{uuid.uuid4().hex[:6]}",
        capacity_kg=500.0,
        waste_category=waste_category,
        pubkey_hex="c" * 64,
    )
    image_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 256
    photo_hash = hashlib.sha256(image_bytes).hexdigest()
    arrival = database.insert_arrival(
        conn,
        facility_id=facility["id"],
        device_id="gate-002",
        weight_kg=20.0,
        photo_hash_hex=photo_hash,
        timestamp_iso="2026-09-18T12:00:00+00:00",
        record_hash_hex="d" * 64,
        signature_hex="e" * 128,
        fraud_flags=[],
    )
    conn.commit()
    conn.close()
    return facility, arrival


# ---------------------------------------------------------------------------
# Test 1 — Photo upload returns all cv_* fields in the response
# ---------------------------------------------------------------------------


def test_photo_upload_returns_cv_fields(api_client) -> None:
    """POST /arrivals/{id}/photo must include cv_matched, cv_confidence,
    cv_reason, and cv_detected_category in the JSON response."""
    client, db_path = api_client
    _, arrival = _make_arrival_via_db(db_path, waste_category="plastic")
    image_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 256

    resp = client.post(
        f"/arrivals/{arrival['id']}/photo",
        content=image_bytes,
        headers={
            "Authorization": f"Bearer {_admin_token()}",
            "Content-Type": "application/octet-stream",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "cv_matched" in body
    assert "cv_confidence" in body
    assert "cv_reason" in body
    assert "cv_detected_category" in body
    assert "arrival_id" in body
    assert "photo_sha256" in body


# ---------------------------------------------------------------------------
# Test 2 — Hash mismatch (tampered bytes) sets cv_hash_mismatch fraud flag
# ---------------------------------------------------------------------------


def test_hash_mismatch_sets_fraud_flag(api_client) -> None:
    """When cv_checker returns matched=False due to photo_hash_mismatch,
    the endpoint must write 'cv_hash_mismatch' into the arrival's fraud_flags."""
    client, db_path = api_client
    _, arrival = _make_arrival_via_db(db_path, waste_category="metal")

    mocked_result = CVResult(
        matched=False,
        detected_category=None,
        confidence=0.0,
        reason="photo_hash_mismatch",
    )
    with patch("backend.main.cv_checker.verify_photo", return_value=mocked_result):
        resp = client.post(
            f"/arrivals/{arrival['id']}/photo",
            content=b"tampered bytes",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cv_matched"] is False

    # Verify the flag was persisted
    conn = database.get_connection(db_path)
    refreshed = database.get_arrival(conn, arrival["id"])
    conn.close()
    assert "cv_hash_mismatch" in refreshed["fraud_flags"]


# ---------------------------------------------------------------------------
# Test 3 — Category mismatch is advisory: flag set but 200 returned
# ---------------------------------------------------------------------------


def test_category_mismatch_advisory(api_client) -> None:
    """category_mismatch CV result must set cv_category_mismatch flag
    in the DB but must still return HTTP 200 (advisory, not blocking)."""
    client, db_path = api_client
    _, arrival = _make_arrival_via_db(db_path, waste_category="paper")

    mocked_result = CVResult(
        matched=True,
        detected_category="plastic",
        confidence=0.72,
        reason="category_mismatch: detected 'plastic' does not match declared 'paper'",
    )
    with patch("backend.main.cv_checker.verify_photo", return_value=mocked_result):
        resp = client.post(
            f"/arrivals/{arrival['id']}/photo",
            content=b"\xff\xd8\xff\xe0" + b"\x00" * 100,
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cv_matched"] is True
    assert body["cv_reason"].startswith("category_mismatch")

    conn = database.get_connection(db_path)
    refreshed = database.get_arrival(conn, arrival["id"])
    conn.close()
    assert "cv_category_mismatch" in refreshed["fraud_flags"]
    assert "cv_hash_mismatch" not in refreshed["fraud_flags"]


# ---------------------------------------------------------------------------
# Test 4 — Good photo: matching hash + category → no cv fraud flags added
# ---------------------------------------------------------------------------


def test_good_photo_passes_no_cv_flags(api_client) -> None:
    """A photo whose hash and category both match must not add any cv_*
    fraud flags to the arrival record."""
    client, db_path = api_client
    _, arrival = _make_arrival_via_db(db_path, waste_category="plastic")

    mocked_result = CVResult(
        matched=True,
        detected_category="plastic",
        confidence=0.85,
        reason="category_match: detected 'plastic' matches declared 'plastic'",
    )
    with patch("backend.main.cv_checker.verify_photo", return_value=mocked_result):
        resp = client.post(
            f"/arrivals/{arrival['id']}/photo",
            content=b"\xff\xd8\xff\xe0" + b"\x00" * 200,
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cv_matched"] is True

    conn = database.get_connection(db_path)
    refreshed = database.get_arrival(conn, arrival["id"])
    conn.close()
    cv_flags = [f for f in refreshed["fraud_flags"] if f.startswith("cv_")]
    assert cv_flags == [], f"Expected no CV fraud flags, got: {cv_flags}"


# ---------------------------------------------------------------------------
# Test 5 — Fail-closed on bad input: empty body → matched=False, save still ok
# ---------------------------------------------------------------------------


def test_fail_closed_on_bad_input(api_client) -> None:
    """Sending an empty body triggers the cv_checker fail-closed path
    (matched=False). The endpoint must still return 200 — the save
    already completed, the CV check is advisory."""
    client, db_path = api_client
    _, arrival = _make_arrival_via_db(db_path, waste_category="glass")

    mocked_result = CVResult(
        matched=False,
        detected_category=None,
        confidence=0.0,
        reason="cv_check_failed_closed",
    )
    with patch("backend.main.cv_checker.verify_photo", return_value=mocked_result):
        resp = client.post(
            f"/arrivals/{arrival['id']}/photo",
            content=b"",
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cv_matched"] is False
    assert body["cv_reason"] == "cv_check_failed_closed"
    assert body["arrival_id"] == arrival["id"]


# ---------------------------------------------------------------------------
# Test 6 — Category mismatch does NOT raise any 4xx/5xx (advisory contract)
# ---------------------------------------------------------------------------


def test_cv_category_mismatch_no_block(api_client) -> None:
    """Regardless of the CV result, the endpoint must never raise a 4xx or
    5xx because of a category mismatch (Invariant #4 — advisory only)."""
    client, db_path = api_client
    _, arrival = _make_arrival_via_db(db_path, waste_category="e_waste")

    for reason in [
        "category_mismatch: detected 'metal' does not match declared 'e_waste'",
        "photo_hash_mismatch",
        "cv_check_failed_closed",
        "image_decode_failed_hash_matched",
        "pillow_not_installed_skipped",
    ]:
        matched = reason not in ("photo_hash_mismatch", "cv_check_failed_closed")
        mocked = CVResult(
            matched=matched,
            detected_category=None,
            confidence=0.0,
            reason=reason,
        )
        with patch("backend.main.cv_checker.verify_photo", return_value=mocked):
            resp = client.post(
                f"/arrivals/{arrival['id']}/photo",
                content=b"\xff\xd8\xff\xe0" + b"\x00" * 50,
                headers={"Authorization": f"Bearer {_admin_token()}"},
            )
        assert resp.status_code == 200, (
            f"Expected 200 for reason={reason!r}, got {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# Test 7 — database.update_arrival_fraud_flags helper: append + dedup
# ---------------------------------------------------------------------------


def test_update_arrival_fraud_flags_helper(seeded_facility_arrival) -> None:
    """update_arrival_fraud_flags() appends new flags, does not duplicate,
    and is a no-op when new_flags is empty."""
    _db_path, conn, _facility, arrival = seeded_facility_arrival
    arrival_id = arrival["id"]

    # Initial state: no flags
    assert arrival["fraud_flags"] == []

    # Append one flag
    database.update_arrival_fraud_flags(conn, arrival_id, ["cv_hash_mismatch"])
    conn.commit()
    refreshed = database.get_arrival(conn, arrival_id)
    assert refreshed["fraud_flags"] == ["cv_hash_mismatch"]

    # Append the same flag again — must not duplicate
    database.update_arrival_fraud_flags(conn, arrival_id, ["cv_hash_mismatch"])
    conn.commit()
    refreshed = database.get_arrival(conn, arrival_id)
    assert refreshed["fraud_flags"] == ["cv_hash_mismatch"]

    # Append a different flag
    database.update_arrival_fraud_flags(conn, arrival_id, ["cv_category_mismatch"])
    conn.commit()
    refreshed = database.get_arrival(conn, arrival_id)
    assert set(refreshed["fraud_flags"]) == {"cv_hash_mismatch", "cv_category_mismatch"}

    # No-op on empty list
    database.update_arrival_fraud_flags(conn, arrival_id, [])
    conn.commit()
    refreshed = database.get_arrival(conn, arrival_id)
    assert len(refreshed["fraud_flags"]) == 2  # unchanged

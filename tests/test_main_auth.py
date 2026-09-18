"""
VERITAS — Route authentication and tenant isolation tests (test_main_auth.py).

Tests FastAPI HTTP endpoints with TestClient:
- Unauthenticated access to public endpoints (health, root)
- Role enforcement across all protected endpoints (401 on missing, 403 on forbidden)
- Route acceptance on valid tokens (400/422 on bad body, not 401/403)
- Invariant #9 tenant isolation: facility_operator token cannot access another facility's data
- Invariant #10: secret loaded from VERITAS_JWT_SECRET environment variable
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import crypto, database, service
from backend.auth import create_token
from backend.main import app

JWT_SECRET = "test-secret-veritas-32chars-ok!!"  # exactly 32 chars


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """FastAPI TestClient fixture with isolated temp DB and JWT secret."""
    monkeypatch.setenv("VERITAS_JWT_SECRET", JWT_SECRET)
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("VERITAS_DB_PATH", str(db_file))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    """Path to the test SQLite database used by TestClient."""
    return tmp_path / "test.db"


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


def test_health_no_auth(client: TestClient) -> None:
    """GET /health returns 200 without token."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "ok"
    assert data.get("service") == "veritas"


def test_root_no_auth(client: TestClient) -> None:
    """GET / returns 200 without token (or 404 if dashboard missing, not 401)."""
    resp = client.get("/")
    assert resp.status_code in (200, 404)
    assert resp.status_code != 401
    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# Facilities endpoints
# ---------------------------------------------------------------------------


def test_register_facility_requires_admin(client: TestClient) -> None:
    """POST /facilities with facility_operator token returns 403 Forbidden."""
    token = create_token(role="facility_operator", facility_id="fac-001", secret=JWT_SECRET)
    resp = client.post(
        "/facilities",
        json={
            "name": "Operator Recycling",
            "capacity_kg": 1000.0,
            "waste_category": "plastic",
            "pubkey_hex": "a" * 64,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "not permitted" in resp.json().get("detail", "").lower()


def test_register_facility_no_token(client: TestClient) -> None:
    """POST /facilities without token returns 401 Unauthorized."""
    resp = client.post(
        "/facilities",
        json={
            "name": "No Auth Recycling",
            "capacity_kg": 1000.0,
            "waste_category": "plastic",
            "pubkey_hex": "a" * 64,
        },
    )
    assert resp.status_code == 401


def test_register_facility_admin_token_accepted(client: TestClient) -> None:
    """With veritas_admin token, route handler is reached (400 or 422 on bad body, NOT 401/403)."""
    token = create_token(role="veritas_admin", facility_id=None, secret=JWT_SECRET)
    resp = client.post(
        "/facilities",
        json={"bad": "payload"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code not in (401, 403)
    assert resp.status_code in (400, 422)


def test_get_facility_requires_auth(client: TestClient) -> None:
    """GET /facilities/{id} without token returns 401 Unauthorized."""
    resp = client.get("/facilities/any-id")
    assert resp.status_code == 401


def test_facility_status_requires_auth(client: TestClient) -> None:
    """GET /facilities/{id}/status without token returns 401 Unauthorized."""
    resp = client.get("/facilities/any-id/status")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Arrivals endpoints
# ---------------------------------------------------------------------------


def test_arrivals_requires_auth(client: TestClient) -> None:
    """POST /arrivals without token returns 401 Unauthorized."""
    resp = client.post("/arrivals", json={})
    assert resp.status_code == 401


def test_arrivals_operator_token_accepted(client: TestClient) -> None:
    """With facility_operator token, route is reached (400/422 on bad body, NOT 401/403)."""
    token = create_token(role="facility_operator", facility_id="fac-001", secret=JWT_SECRET)
    resp = client.post(
        "/arrivals",
        json={"bad": "payload"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code not in (401, 403)
    assert resp.status_code in (400, 422)


def test_list_arrivals_requires_auth(client: TestClient) -> None:
    """GET /arrivals?facility_id=x without token returns 401 Unauthorized."""
    resp = client.get("/arrivals?facility_id=fac-001")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Certificates endpoints
# ---------------------------------------------------------------------------


def test_mint_requires_auth(client: TestClient) -> None:
    """POST /certificates/mint without token returns 401 Unauthorized."""
    resp = client.post("/certificates/mint", json={})
    assert resp.status_code == 401


def test_verify_cert_requires_auth(client: TestClient) -> None:
    """GET /certificates/{cert_id}/verify without token returns 401 Unauthorized."""
    resp = client.get("/certificates/cert-001/verify")
    assert resp.status_code == 401


def test_list_certificates_requires_auth(client: TestClient) -> None:
    """GET /certificates?facility_id=x without token returns 401 Unauthorized."""
    resp = client.get("/certificates?facility_id=fac-001")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tenant isolation (Invariant #9)
# ---------------------------------------------------------------------------


def test_tenant_isolation_list_arrivals(client: TestClient, test_db_path: Path) -> None:
    """
    Tenant isolation (Invariant #9):
    facility_operator token with facility_id=A cannot list facility B's arrivals.
    Query param facility_id=B is IGNORED; the token's facility_id=A is used.
    """
    conn = database.get_connection(test_db_path)
    try:
        pub_a, priv_a = crypto.generate_keypair()
        pub_b, priv_b = crypto.generate_keypair()

        fac_a = service.register_facility(conn, "Facility A", 1000.0, "plastic", pub_a).data
        fac_b = service.register_facility(conn, "Facility B", 1000.0, "plastic", pub_b).data

        # Submit arrival for Facility B only
        ts = datetime.now(timezone.utc).isoformat()
        photo_hash = "ab" * 32
        device_id = "device-b-001"
        rec_hash = crypto.canonical_hash(
            weight_kg=150.0,
            facility_id=fac_b["id"],
            timestamp_iso=ts,
            photo_hash_hex=photo_hash,
            device_id=device_id,
        )
        sig = crypto.sign_payload(priv_b, rec_hash)

        arr_b = service.submit_arrival(
            db=conn,
            facility_id=fac_b["id"],
            device_id=device_id,
            weight_kg=150.0,
            photo_hash_hex=photo_hash,
            timestamp_iso=ts,
            record_hash_hex=rec_hash.hex(),
            signature_hex=sig,
        )
        assert arr_b.success
    finally:
        conn.close()

    # Facility operator A token
    token_op_a = create_token(role="facility_operator", facility_id=fac_a["id"], secret=JWT_SECRET)

    # Operator A attempts to list Facility B's arrivals by supplying facility_id=B in query param
    resp = client.get(
        f"/arrivals?facility_id={fac_b['id']}",
        headers={"Authorization": f"Bearer {token_op_a}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Query param facility_id=B was ignored; token's facility_id=A was used
    # Facility A has 0 arrivals, so count MUST be 0 and arrivals list empty
    assert data["count"] == 0
    assert data["arrivals"] == []

    # In contrast, admin can query Facility B explicitly and sees the arrival
    token_admin = create_token(role="veritas_admin", facility_id=None, secret=JWT_SECRET)
    resp_admin = client.get(
        f"/arrivals?facility_id={fac_b['id']}",
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert resp_admin.status_code == 200
    data_admin = resp_admin.json()
    assert data_admin["count"] == 1
    assert data_admin["arrivals"][0]["facility_id"] == fac_b["id"]


def test_tenant_isolation_list_certificates(client: TestClient, test_db_path: Path) -> None:
    """
    Tenant isolation (Invariant #9) for certificates:
    facility_operator token with facility_id=A cannot list facility B's certificates.
    Query param facility_id=B is IGNORED; token's facility_id=A is used.
    """
    conn = database.get_connection(test_db_path)
    try:
        pub_a, priv_a = crypto.generate_keypair()
        pub_b, priv_b = crypto.generate_keypair()

        fac_a = service.register_facility(conn, "Facility A", 1000.0, "plastic", pub_a).data
        fac_b = service.register_facility(conn, "Facility B", 1000.0, "plastic", pub_b).data

        # Submit arrival and mint certificate for Facility B
        ts = datetime.now(timezone.utc).isoformat()
        photo_hash = "cd" * 32
        device_id = "device-b-002"
        rec_hash = crypto.canonical_hash(
            weight_kg=200.0,
            facility_id=fac_b["id"],
            timestamp_iso=ts,
            photo_hash_hex=photo_hash,
            device_id=device_id,
        )
        sig = crypto.sign_payload(priv_b, rec_hash)

        arr_b = service.submit_arrival(
            db=conn,
            facility_id=fac_b["id"],
            device_id=device_id,
            weight_kg=200.0,
            photo_hash_hex=photo_hash,
            timestamp_iso=ts,
            record_hash_hex=rec_hash.hex(),
            signature_hex=sig,
        )
        assert arr_b.success

        mint_res = service.mint_certificate(
            db=conn,
            arrival_id=arr_b.data["id"],
            quantity_kg=200.0,
            waste_category="plastic",
        )
        assert mint_res.success
    finally:
        conn.close()

    # Operator A token
    token_op_a = create_token(role="facility_operator", facility_id=fac_a["id"], secret=JWT_SECRET)

    # Operator A attempts to query Facility B's certificates
    resp = client.get(
        f"/certificates?facility_id={fac_b['id']}",
        headers={"Authorization": f"Bearer {token_op_a}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0
    assert data["certificates"] == []

    # Admin querying Facility B sees the minted certificate
    token_admin = create_token(role="veritas_admin", facility_id=None, secret=JWT_SECRET)
    resp_admin = client.get(
        f"/certificates?facility_id={fac_b['id']}",
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert resp_admin.status_code == 200
    data_admin = resp_admin.json()
    assert data_admin["count"] == 1
    assert data_admin["certificates"][0]["facility_id"] == fac_b["id"]

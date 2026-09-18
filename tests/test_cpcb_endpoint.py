"""
VERITAS — CPCB audit-export endpoint tests (test_cpcb_endpoint.py).

Tests for GET /export/audit:
- 401 without token
- 403 for facility_operator role
- 200 with regulator_auditor token (JSON)
- 200 with regulator_auditor token (CSV)
- 200 with veritas_admin token
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.auth import create_token
from backend.main import app

JWT_SECRET = "test-secret-veritas-32chars-ok!!"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """FastAPI TestClient with isolated temp DB and JWT secret."""
    monkeypatch.setenv("VERITAS_JWT_SECRET", JWT_SECRET)
    db_file = tmp_path / "test_cpcb.db"
    monkeypatch.setenv("VERITAS_DB_PATH", str(db_file))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auditor_token() -> str:
    return create_token(role="regulator_auditor", facility_id=None, secret=JWT_SECRET)


@pytest.fixture
def admin_token() -> str:
    return create_token(role="veritas_admin", facility_id=None, secret=JWT_SECRET)


@pytest.fixture
def operator_token() -> str:
    return create_token(role="facility_operator", facility_id="fac-001", secret=JWT_SECRET)


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


def test_audit_export_requires_auth(client: TestClient) -> None:
    """GET /export/audit without a token returns 401 Unauthorized."""
    resp = client.get("/export/audit?facility_id=fac-001")
    assert resp.status_code == 401


def test_audit_export_requires_auditor_role(
    client: TestClient, operator_token: str
) -> None:
    """GET /export/audit with facility_operator token returns 403 Forbidden."""
    resp = client.get(
        "/export/audit?facility_id=fac-001",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Successful responses
# ---------------------------------------------------------------------------


def test_audit_export_json_returns_200(
    client: TestClient, auditor_token: str
) -> None:
    """GET /export/audit?format=json with regulator_auditor token returns 200 JSON."""
    resp = client.get(
        "/export/audit?facility_id=fac-001&format=json",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp.status_code == 200
    # Response must be valid JSON
    body = resp.json()
    assert isinstance(body, dict)


def test_audit_export_csv_returns_200(
    client: TestClient, auditor_token: str
) -> None:
    """GET /export/audit?format=csv returns 200 with CSV Content-Disposition header."""
    resp = client.get(
        "/export/audit?facility_id=fac-001&format=csv",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp.status_code == 200
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "veritas_audit.csv" in cd
    # Body must contain a CSV header row
    assert "certificate_id" in resp.text


def test_audit_export_admin_can_access(
    client: TestClient, admin_token: str
) -> None:
    """GET /export/audit with veritas_admin token returns 200."""
    resp = client.get(
        "/export/audit?facility_id=fac-001",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, dict)

"""
VERITAS — Phase 16 observability tests (test_observability.py).

Tests:
  1. test_json_formatter_output_is_valid_json
  2. test_get_logger_returns_logger
  3. test_increment_counter_thread_safe
  4. test_get_metrics_returns_dict
  5. test_metrics_endpoint_returns_200
  6. test_metrics_endpoint_no_auth_required
  7. test_arrivals_metric_increments
  8. test_errors_metric_increments_on_bad_arrival
"""
from __future__ import annotations

import json
import logging
import os
import threading
from io import StringIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import crypto, database, service
from backend.auth import create_token
from backend.main import app
from backend.observability import (
    JSONFormatter,
    get_logger,
    get_metrics,
    increment_counter,
    reset_metrics,
)

JWT_SECRET = "test-secret-veritas-32chars-ok!!"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Reset all metrics counters before every test to avoid cross-test pollution."""
    reset_metrics()
    yield
    reset_metrics()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """FastAPI TestClient with isolated DB and JWT secret."""
    monkeypatch.setenv("VERITAS_JWT_SECRET", JWT_SECRET)
    db_file = tmp_path / "obs_test.db"
    monkeypatch.setenv("VERITAS_DB_PATH", str(db_file))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db(tmp_path: Path):
    """Temporary SQLite DB connection."""
    p = tmp_path / "obs.db"
    database.init_db(p)
    conn = database.get_connection(p)
    yield conn
    conn.close()


@pytest.fixture
def keypair():
    return crypto.generate_keypair()


@pytest.fixture
def facility(db, keypair):
    pubkey_hex, _ = keypair
    result = service.register_facility(
        db=db,
        name="Obs Test Recycler",
        capacity_kg=500.0,
        waste_category="plastic",
        pubkey_hex=pubkey_hex,
    )
    assert result.success
    return result.data


# ---------------------------------------------------------------------------
# 1. test_json_formatter_output_is_valid_json
# ---------------------------------------------------------------------------


def test_json_formatter_output_is_valid_json() -> None:
    """JSONFormatter must produce valid JSON for a basic INFO record."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="veritas.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    line = formatter.format(record)
    parsed = json.loads(line)  # raises if not valid JSON

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "veritas.test"
    assert parsed["message"] == "hello world"
    assert "timestamp" in parsed


def test_json_formatter_includes_extra_kwargs() -> None:
    """Extra kwargs passed via `extra=` are present in the JSON output."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="veritas.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="arrival rejected",
        args=(),
        exc_info=None,
    )
    record.facility_id = "fac-123"
    record.weight_kg = 42.5
    line = formatter.format(record)
    parsed = json.loads(line)

    assert parsed.get("facility_id") == "fac-123"
    assert parsed.get("weight_kg") == 42.5


# ---------------------------------------------------------------------------
# 2. test_get_logger_returns_logger
# ---------------------------------------------------------------------------


def test_get_logger_returns_logger() -> None:
    """get_logger returns a logging.Logger instance with the correct name."""
    logger = get_logger("veritas.obs_test")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "veritas.obs_test"


def test_get_logger_is_idempotent() -> None:
    """Calling get_logger twice with the same name does not double-add handlers."""
    logger1 = get_logger("veritas.idempotent_test")
    handler_count = len(logger1.handlers)
    logger2 = get_logger("veritas.idempotent_test")
    assert logger1 is logger2
    assert len(logger2.handlers) == handler_count


def test_get_logger_writes_json(capsys) -> None:  # type: ignore[no-untyped-def]
    """Logger emits valid JSON lines to stderr."""
    logger = get_logger("veritas.capsys_test")
    logger.info("capsys check", extra={"key": "val"})
    captured = capsys.readouterr()
    line = captured.err.strip().splitlines()[-1]
    parsed = json.loads(line)
    assert parsed["message"] == "capsys check"


# ---------------------------------------------------------------------------
# 3. test_increment_counter_thread_safe
# ---------------------------------------------------------------------------


def test_increment_counter_thread_safe() -> None:
    """10 threads each calling increment_counter 100 times yield 1000 total."""
    n_threads = 10
    n_increments = 100

    def _worker():
        for _ in range(n_increments):
            increment_counter("arrivals_submitted_total")

    threads = [threading.Thread(target=_worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert get_metrics()["arrivals_submitted_total"] == n_threads * n_increments


# ---------------------------------------------------------------------------
# 4. test_get_metrics_returns_dict
# ---------------------------------------------------------------------------


def test_get_metrics_returns_dict() -> None:
    """get_metrics() returns a plain dict with all expected top-level keys."""
    m = get_metrics()
    assert isinstance(m, dict)
    for key in (
        "requests_total",
        "arrivals_submitted_total",
        "certificates_minted_total",
        "fraud_flags_total",
        "errors_total",
    ):
        assert key in m, f"Missing key: {key}"


def test_get_metrics_requests_total_is_dict() -> None:
    """requests_total is a dict (keyed by 'METHOD /route')."""
    m = get_metrics()
    assert isinstance(m["requests_total"], dict)


# ---------------------------------------------------------------------------
# 5. test_metrics_endpoint_returns_200
# ---------------------------------------------------------------------------


def test_metrics_endpoint_returns_200(client: TestClient) -> None:
    """GET /metrics returns HTTP 200."""
    resp = client.get("/metrics")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 6. test_metrics_endpoint_no_auth_required
# ---------------------------------------------------------------------------


def test_metrics_endpoint_no_auth_required(client: TestClient) -> None:
    """GET /metrics is public — no Authorization header needed."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "arrivals_submitted_total" in body
    assert "certificates_minted_total" in body
    assert "fraud_flags_total" in body
    assert "errors_total" in body
    assert "requests_total" in body


# ---------------------------------------------------------------------------
# 7. test_arrivals_metric_increments
# ---------------------------------------------------------------------------


def test_arrivals_metric_increments(db, facility, keypair) -> None:
    """arrivals_submitted_total increments by 1 after a valid submit_arrival call."""
    _, privkey_hex = keypair
    facility_id = facility["id"]
    device_id = "device-obs-01"
    weight_kg = 55.0
    photo_hash_hex = "a" * 64
    timestamp_iso = "2026-09-18T10:00:00+00:00"

    record_hash = crypto.canonical_hash(
        weight_kg=weight_kg,
        facility_id=facility_id,
        timestamp_iso=timestamp_iso,
        photo_hash_hex=photo_hash_hex,
        device_id=device_id,
    )
    signature_hex = crypto.sign_payload(privkey_hex=privkey_hex, message_bytes=record_hash)

    before = get_metrics()["arrivals_submitted_total"]

    result = service.submit_arrival(
        db=db,
        facility_id=facility_id,
        device_id=device_id,
        weight_kg=weight_kg,
        photo_hash_hex=photo_hash_hex,
        timestamp_iso=timestamp_iso,
        record_hash_hex=record_hash.hex(),
        signature_hex=signature_hex,
    )
    assert result.success, f"Expected success but got: {result.error}"

    after = get_metrics()["arrivals_submitted_total"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# 8. test_errors_metric_increments_on_bad_arrival
# ---------------------------------------------------------------------------


def test_errors_metric_increments_on_bad_arrival(db, facility, keypair) -> None:
    """errors_total increments when submit_arrival is called with an invalid signature."""
    _, privkey_hex = keypair
    facility_id = facility["id"]
    device_id = "device-obs-02"
    weight_kg = 30.0
    photo_hash_hex = "b" * 64
    timestamp_iso = "2026-09-18T11:00:00+00:00"

    record_hash = crypto.canonical_hash(
        weight_kg=weight_kg,
        facility_id=facility_id,
        timestamp_iso=timestamp_iso,
        photo_hash_hex=photo_hash_hex,
        device_id=device_id,
    )
    # Use the real hash but a garbage signature → sig_valid == False → errors_total ++
    bad_signature_hex = "de" * 64

    before = get_metrics()["errors_total"]

    result = service.submit_arrival(
        db=db,
        facility_id=facility_id,
        device_id=device_id,
        weight_kg=weight_kg,
        photo_hash_hex=photo_hash_hex,
        timestamp_iso=timestamp_iso,
        record_hash_hex=record_hash.hex(),
        signature_hex=bad_signature_hex,
    )
    assert not result.success

    after = get_metrics()["errors_total"]
    assert after == before + 1

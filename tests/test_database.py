"""
Tests for VERITAS database.py — Phase 2.

All tests use a real SQLite file under pytest's tmp_path fixture.
No mocking of sqlite3 is used anywhere.

Test catalogue
--------------
1. test_init_db_creates_tables          — init_db succeeds and creates all 4 tables
2. test_register_and_get_facility       — register_facility → get_facility roundtrip
3. test_insert_and_get_arrival          — insert_arrival → get_arrival roundtrip
4. test_atomic_mint_succeeds            — atomic_mint returns a certificate dict
5. test_atomic_mint_idempotent_none     — second mint on same arrival_id returns None
6. test_atomic_mint_concurrency         — 20 threads race; exactly 1 wins (×3 repetitions)
7. test_log_action                      — log_action writes to audit_log without raising
8. test_get_certificates_for_facility   — period filter returns correct certificates
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Optional

import pytest

from backend.database import (
    atomic_mint,
    get_arrival,
    get_certificates_for_facility,
    get_connection,
    get_db,
    get_facility,
    init_db,
    insert_arrival,
    log_action,
    register_facility,
)

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

_PUBKEY = "a" * 64  # 32-byte dummy Ed25519 public key, hex-encoded
_PHOTO_HASH = "b" * 64
_RECORD_HASH = "c" * 64
_SIG = "d" * 128


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    """Return a path to a freshly initialised VERITAS test database."""
    path = tmp_path / "veritas_test.db"
    init_db(path)
    return path


@pytest.fixture()
def facility_id(db_path: Path) -> str:
    """Register a test facility and return its UUID."""
    with get_db(db_path) as db:
        fac = register_facility(
            db,
            name="Test Recycler",
            capacity_kg=10_000.0,
            waste_category="plastic",
            pubkey_hex=_PUBKEY,
        )
    return fac["id"]


@pytest.fixture()
def arrival_id(db_path: Path, facility_id: str) -> str:
    """Insert a test arrival and return its UUID."""
    with get_db(db_path) as db:
        arr = insert_arrival(
            db,
            facility_id=facility_id,
            device_id="pod-001",
            weight_kg=500.0,
            photo_hash_hex=_PHOTO_HASH,
            timestamp_iso="2026-09-18T12:00:00+00:00",
            record_hash_hex=_RECORD_HASH,
            signature_hex=f"{_SIG}-{uuid.uuid4().hex}",
            fraud_flags=[],
        )
    return arr["id"]


# ---------------------------------------------------------------------------
# Test 1: init_db
# ---------------------------------------------------------------------------


def test_init_db_creates_tables(tmp_path: Path) -> None:
    """init_db must create all four required tables without error."""
    path = tmp_path / "fresh.db"
    init_db(path)

    conn = get_connection(path)
    try:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        # Exclude SQLite-internal tables (e.g. sqlite_sequence created by AUTOINCREMENT)
        tables = {
            row["name"]
            for row in cursor.fetchall()
            if not row["name"].startswith("sqlite_")
        }
    finally:
        conn.close()

    assert tables == {"arrivals", "audit_log", "certificates", "facilities"}


def test_init_db_is_idempotent(tmp_path: Path) -> None:
    """Calling init_db twice must not raise or corrupt data."""
    path = tmp_path / "idempotent.db"
    init_db(path)
    init_db(path)  # second call must be safe

    conn = get_connection(path)
    try:
        row_count = conn.execute("SELECT COUNT(*) FROM facilities;").fetchone()[0]
    finally:
        conn.close()

    assert row_count == 0


# ---------------------------------------------------------------------------
# Test 2: register_facility / get_facility roundtrip
# ---------------------------------------------------------------------------


def test_register_and_get_facility(db_path: Path) -> None:
    """register_facility must persist and get_facility must retrieve the same data."""
    with get_db(db_path) as db:
        fac = register_facility(
            db,
            name="Ocean Plastics Ltd",
            capacity_kg=25_000.0,
            waste_category="plastic",
            pubkey_hex=_PUBKEY,
        )

    assert fac["name"] == "Ocean Plastics Ltd"
    assert fac["capacity_kg"] == pytest.approx(25_000.0)
    assert fac["waste_category"] == "plastic"
    assert fac["pubkey_hex"] == _PUBKEY
    assert "id" in fac
    assert "created_at" in fac

    # Verify retrieval across a fresh connection
    with get_db(db_path) as db:
        fetched = get_facility(db, fac["id"])

    assert fetched is not None
    assert fetched["id"] == fac["id"]
    assert fetched["name"] == "Ocean Plastics Ltd"


def test_get_facility_missing_returns_none(db_path: Path) -> None:
    """get_facility must return None for an unknown ID."""
    with get_db(db_path) as db:
        result = get_facility(db, "00000000-0000-0000-0000-000000000000")
    assert result is None


# ---------------------------------------------------------------------------
# Test 3: insert_arrival / get_arrival roundtrip
# ---------------------------------------------------------------------------


def test_insert_and_get_arrival(db_path: Path, facility_id: str) -> None:
    """insert_arrival must persist and get_arrival must retrieve the same data."""
    with get_db(db_path) as db:
        arr = insert_arrival(
            db,
            facility_id=facility_id,
            device_id="pod-42",
            weight_kg=750.5,
            photo_hash_hex=_PHOTO_HASH,
            timestamp_iso="2026-09-18T09:00:00+00:00",
            record_hash_hex=_RECORD_HASH,
            signature_hex=f"{_SIG}-{uuid.uuid4().hex}",
            fraud_flags=["weight_spike"],
        )

    assert arr["device_id"] == "pod-42"
    assert arr["weight_kg"] == pytest.approx(750.5)
    assert arr["fraud_flags"] == ["weight_spike"]
    assert arr["used"] == 0

    with get_db(db_path) as db:
        fetched = get_arrival(db, arr["id"])

    assert fetched is not None
    assert fetched["id"] == arr["id"]
    assert fetched["fraud_flags"] == ["weight_spike"]
    assert isinstance(fetched["fraud_flags"], list)


def test_get_arrival_missing_returns_none(db_path: Path) -> None:
    """get_arrival must return None for an unknown ID."""
    with get_db(db_path) as db:
        result = get_arrival(db, "00000000-0000-0000-0000-000000000000")
    assert result is None


# ---------------------------------------------------------------------------
# Test 4: atomic_mint succeeds once
# ---------------------------------------------------------------------------


def test_atomic_mint_succeeds(db_path: Path, arrival_id: str, facility_id: str) -> None:
    """atomic_mint must return a certificate dict on first call."""
    with get_db(db_path) as db:
        cert = atomic_mint(
            db,
            arrival_id=arrival_id,
            quantity_kg=500.0,
            waste_category="plastic",
            ledger_hash_hex="",
        )

    assert cert is not None
    assert cert["arrival_id"] == arrival_id
    assert cert["facility_id"] == facility_id
    assert cert["quantity_kg"] == pytest.approx(500.0)
    assert cert["waste_category"] == "plastic"
    assert "id" in cert
    assert "minted_at" in cert

    # The arrival must now be marked used=1
    with get_db(db_path) as db:
        arr = get_arrival(db, arrival_id)
    assert arr is not None
    assert arr["used"] == 1


# ---------------------------------------------------------------------------
# Test 5: atomic_mint idempotency (second call returns None)
# ---------------------------------------------------------------------------


def test_atomic_mint_idempotent_none(db_path: Path, arrival_id: str) -> None:
    """atomic_mint on an already-used arrival must return None (no double-mint)."""
    with get_db(db_path) as db:
        first = atomic_mint(db, arrival_id=arrival_id, quantity_kg=500.0, waste_category="plastic")
    assert first is not None

    with get_db(db_path) as db:
        second = atomic_mint(db, arrival_id=arrival_id, quantity_kg=500.0, waste_category="plastic")
    assert second is None

    # Confirm only one certificate exists in the DB
    conn = get_connection(db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE arrival_id = ?", (arrival_id,)
        ).fetchone()[0]
    finally:
        conn.close()

    assert count == 1


# ---------------------------------------------------------------------------
# Test 6: CONCURRENCY — 20 threads race to mint the same arrival
# ---------------------------------------------------------------------------


def test_atomic_mint_concurrency(db_path: Path, facility_id: str) -> None:
    """Exactly 1 of 20 concurrent threads must succeed; 19 must get None.

    Run 3 times to catch flaky races. Each iteration uses a fresh arrival so
    threads truly race from scratch.
    """
    NUM_THREADS = 20
    NUM_ITERATIONS = 3

    for iteration in range(NUM_ITERATIONS):
        # Fresh arrival for each iteration
        with get_db(db_path) as db:
            arr = insert_arrival(
                db,
                facility_id=facility_id,
                device_id=f"pod-race-{iteration}",
                weight_kg=100.0,
                photo_hash_hex=_PHOTO_HASH,
                timestamp_iso=f"2026-09-18T{10 + iteration:02d}:00:00+00:00",
                record_hash_hex=_RECORD_HASH,
                signature_hex=f"{_SIG}-{uuid.uuid4().hex}",
                fraud_flags=[],
            )
        race_arrival_id = arr["id"]

        results: list[Optional[dict]] = [None] * NUM_THREADS
        errors: list[Optional[Exception]] = [None] * NUM_THREADS
        barrier = threading.Barrier(NUM_THREADS)  # synchronise thread start

        def _mint_worker(index: int) -> None:
            barrier.wait()  # all threads start simultaneously
            try:
                with get_db(db_path) as db:
                    results[index] = atomic_mint(
                        db,
                        arrival_id=race_arrival_id,
                        quantity_kg=100.0,
                        waste_category="plastic",
                    )
            except Exception as exc:
                errors[index] = exc

        threads = [
            threading.Thread(target=_mint_worker, args=(i,), daemon=True)
            for i in range(NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        # Surface any unexpected exceptions from worker threads
        thread_errors = [e for e in errors if e is not None]
        assert not thread_errors, f"Iteration {iteration}: worker exceptions: {thread_errors}"

        # Exactly one winner
        successes = [r for r in results if r is not None]
        nones = [r for r in results if r is None]

        assert len(successes) == 1, (
            f"Iteration {iteration}: expected 1 success, got {len(successes)}"
        )
        assert len(nones) == NUM_THREADS - 1, (
            f"Iteration {iteration}: expected {NUM_THREADS - 1} None results, "
            f"got {len(nones)}"
        )

        # Database invariant: only one certificate per arrival
        conn = get_connection(db_path)
        try:
            cert_count = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE arrival_id = ?",
                (race_arrival_id,),
            ).fetchone()[0]
        finally:
            conn.close()

        assert cert_count == 1, (
            f"Iteration {iteration}: expected 1 certificate, got {cert_count}"
        )


# ---------------------------------------------------------------------------
# Test 7: log_action writes to audit_log
# ---------------------------------------------------------------------------


def test_log_action(db_path: Path, facility_id: str) -> None:
    """log_action must insert a row into audit_log without raising."""
    with get_db(db_path) as db:
        log_action(
            db,
            action="mint",
            actor="service:veritas",
            result="ok",
            target_id=facility_id,
            detail="test log entry",
        )

    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM audit_log;").fetchall()
    finally:
        conn.close()

    assert len(rows) == 1
    entry = dict(rows[0])
    assert entry["action"] == "mint"
    assert entry["actor"] == "service:veritas"
    assert entry["result"] == "ok"
    assert entry["target_id"] == facility_id
    assert entry["detail"] == "test log entry"
    assert entry["created_at"] is not None


def test_log_action_with_nulls(db_path: Path) -> None:
    """log_action with no target_id or detail must not raise."""
    with get_db(db_path) as db:
        log_action(db, action="health_check", actor="cron", result="ok")

    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM audit_log;").fetchone()
    finally:
        conn.close()

    assert dict(row)["target_id"] is None
    assert dict(row)["detail"] is None


# ---------------------------------------------------------------------------
# Test 8: get_certificates_for_facility period filter
# ---------------------------------------------------------------------------


def test_get_certificates_for_facility(db_path: Path, facility_id: str) -> None:
    """get_certificates_for_facility must respect the period_start/period_end filter."""
    # Insert two arrivals and mint both
    def _make_arrival(device: str, ts: str) -> str:
        with get_db(db_path) as db:
            arr = insert_arrival(
                db,
                facility_id=facility_id,
                device_id=device,
                weight_kg=200.0,
                photo_hash_hex=_PHOTO_HASH,
                timestamp_iso=ts,
                record_hash_hex=_RECORD_HASH,
                signature_hex=f"{_SIG}-{uuid.uuid4().hex}",
                fraud_flags=[],
            )
        return arr["id"]

    arr1_id = _make_arrival("pod-1", "2026-09-18T08:00:00+00:00")
    arr2_id = _make_arrival("pod-2", "2026-09-18T10:00:00+00:00")

    with get_db(db_path) as db:
        cert1 = atomic_mint(db, arrival_id=arr1_id, quantity_kg=200.0, waste_category="plastic")
    with get_db(db_path) as db:
        cert2 = atomic_mint(db, arrival_id=arr2_id, quantity_kg=200.0, waste_category="plastic")

    assert cert1 is not None
    assert cert2 is not None

    # Both certificates fall in the wide window
    with get_db(db_path) as db:
        all_certs = get_certificates_for_facility(
            db,
            facility_id=facility_id,
            period_start="2026-01-01T00:00:00+00:00",
            period_end="2027-01-01T00:00:00+00:00",
        )

    assert len(all_certs) == 2
    assert {c["id"] for c in all_certs} == {cert1["id"], cert2["id"]}

    # Future window returns empty list
    with get_db(db_path) as db:
        future_certs = get_certificates_for_facility(
            db,
            facility_id=facility_id,
            period_start="2030-01-01T00:00:00+00:00",
            period_end="2030-12-31T00:00:00+00:00",
        )

    assert future_certs == []

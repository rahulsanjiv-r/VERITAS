"""
VERITAS — tests/test_fraud.py

Eight tests for backend/fraud.py, covering all three fraud checks:
  * capacity_ceiling
  * ghost_facility
  * circular_trucking

Test structure per check
-------------------------
1. fires     — bad data inserted via real SQLite rows; assert flagged=True
2. no_false_positive — legitimate data; assert flagged=False

Additional tests
----------------
7. test_check_exception_fails_closed — closed DB connection → flagged (invariant #14)
8. test_run_all_checks_returns_list   — smoke test for the aggregate runner

All tests use real in-memory SQLite (via tmp_path fixture) populated through
the same database.py helpers used by production code.  No mocking of DB calls
inside fraud.py is used.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.database import (
    atomic_mint,
    get_connection,
    init_db,
    insert_arrival,
    register_facility,
)
from backend.fraud import (
    FraudResult,
    check_capacity_ceiling,
    check_circular_trucking,
    check_ghost_facility,
    run_all_checks,
)

# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------

_PUBKEY = "a" * 64  # 32-byte placeholder hex Ed25519 public key
_PHOTO = "b" * 64   # 32-byte placeholder photo hash
_RECORD = "c" * 64  # 32-byte placeholder record hash
_SIG = "d" * 128    # 64-byte placeholder Ed25519 signature

# A fixed accounting period wide enough to contain all test rows.
_PERIOD_START = "2026-01-01T00:00:00+00:00"
_PERIOD_END   = "2026-12-31T23:59:59+00:00"

# A timestamp well inside the period.
_TS = "2026-06-15T12:00:00+00:00"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path) -> sqlite3.Connection:
    """Create a fresh, schema-initialised SQLite DB and return an open connection."""
    db_path = tmp_path / "test_veritas.db"
    init_db(str(db_path))
    return get_connection(str(db_path))


def _register(db: sqlite3.Connection, capacity_kg: float = 10_000.0) -> str:
    """Register a facility and return its ID."""
    row = register_facility(
        db,
        name="Test Facility",
        capacity_kg=capacity_kg,
        waste_category="plastic",
        pubkey_hex=_PUBKEY,
    )
    db.commit()
    return row["id"]


def _arrive(
    db: sqlite3.Connection,
    facility_id: str,
    device_id: str = "dev-001",
    weight_kg: float = 1_000.0,
    timestamp_iso: str = _TS,
) -> str:
    """Insert one arrival row and return its ID."""
    row = insert_arrival(
        db,
        facility_id=facility_id,
        device_id=device_id,
        weight_kg=weight_kg,
        photo_hash_hex=_PHOTO,
        timestamp_iso=timestamp_iso,
        record_hash_hex=_RECORD,
        signature_hex=_SIG,
        fraud_flags=[],
    )
    db.commit()
    return row["id"]


def _mint(db: sqlite3.Connection, arrival_id: str, quantity_kg: float = 1_000.0) -> None:
    """Atomically mint a certificate from ``arrival_id``."""
    result = atomic_mint(
        db,
        arrival_id=arrival_id,
        quantity_kg=quantity_kg,
        waste_category="plastic",
    )
    db.commit()
    assert result is not None, "test setup: mint should succeed"


# ---------------------------------------------------------------------------
# 1 & 2 — capacity_ceiling
# ---------------------------------------------------------------------------


def test_capacity_ceiling_fires(tmp_path: Path) -> None:
    """Capacity check fires when cumulative minted kg would exceed registered limit."""
    db = _make_db(tmp_path)
    # Facility with a 5 000 kg ceiling.
    fid = _register(db, capacity_kg=5_000.0)

    # Mint 4 000 kg already this period.
    aid1 = _arrive(db, fid, weight_kg=4_000.0)
    _mint(db, aid1, quantity_kg=4_000.0)

    # Now claim 2 000 kg more → total would be 6 000 > 5 000.
    result = check_capacity_ceiling(db, fid, claimed_kg=2_000.0,
                                    period_start=_PERIOD_START, period_end=_PERIOD_END)

    assert result.flagged is True
    assert result.reason == "capacity_exceeded"
    assert result.details["total_kg"] == pytest.approx(6_000.0)


def test_capacity_ceiling_no_false_positive(tmp_path: Path) -> None:
    """Capacity check does NOT fire when cumulative total stays under the limit."""
    db = _make_db(tmp_path)
    fid = _register(db, capacity_kg=5_000.0)

    # Mint 1 000 kg.
    aid1 = _arrive(db, fid, weight_kg=1_000.0)
    _mint(db, aid1, quantity_kg=1_000.0)

    # Claim 2 000 kg more → total would be 3 000 < 5 000.
    result = check_capacity_ceiling(db, fid, claimed_kg=2_000.0,
                                    period_start=_PERIOD_START, period_end=_PERIOD_END)

    assert result.flagged is False
    assert result.reason is None


# ---------------------------------------------------------------------------
# 3 & 4 — ghost_facility
# ---------------------------------------------------------------------------


def test_ghost_facility_fires(tmp_path: Path) -> None:
    """Ghost-facility check fires when certificates exist but no arrivals do."""
    db = _make_db(tmp_path)
    fid = _register(db)

    # Insert an arrival OUTSIDE the test period so it won't be counted.
    old_ts = "2025-01-01T00:00:00+00:00"
    aid = _arrive(db, fid, timestamp_iso=old_ts)
    _mint(db, aid, quantity_kg=500.0)

    # The certificate's minted_at will be now (inside the period), but the
    # arrival's timestamp_iso is outside it → arrivals == 0, certs == 1.
    result = check_ghost_facility(db, fid, period_start=_PERIOD_START, period_end=_PERIOD_END)

    assert result.flagged is True
    assert result.reason == "ghost_facility"
    assert result.details["arrivals"] == 0
    assert result.details["certificates"] >= 1


def test_ghost_facility_no_false_positive(tmp_path: Path) -> None:
    """Ghost-facility check does NOT fire when arrivals back the certificates."""
    db = _make_db(tmp_path)
    fid = _register(db)

    # One arrival inside the period, one certificate minted from it.
    aid = _arrive(db, fid, timestamp_iso=_TS, weight_kg=1_000.0)
    _mint(db, aid, quantity_kg=1_000.0)

    result = check_ghost_facility(db, fid, period_start=_PERIOD_START, period_end=_PERIOD_END)

    assert result.flagged is False


# ---------------------------------------------------------------------------
# 5 & 6 — circular_trucking
# ---------------------------------------------------------------------------


def test_circular_trucking_fires(tmp_path: Path) -> None:
    """Circular-trucking check fires when the same device has a used arrival within the window."""
    db = _make_db(tmp_path)
    fid = _register(db)

    device = "pod-truck-42"
    # First arrival 1 hour ago — mint it so used=1.
    current_dt = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    first_ts = (current_dt - timedelta(hours=1)).isoformat()

    aid = _arrive(db, fid, device_id=device, timestamp_iso=first_ts, weight_kg=5_000.0)
    _mint(db, aid, quantity_kg=5_000.0)

    # Now the same device submits again at current_dt — within the 4-hour window.
    result = check_circular_trucking(
        db,
        device_id=device,
        current_timestamp_iso=current_dt.isoformat(),
        window_hours=4.0,
    )

    assert result.flagged is True
    assert result.reason == "circular_trucking"
    assert result.details["hours_since"] == pytest.approx(1.0, abs=0.01)


def test_circular_trucking_no_false_positive(tmp_path: Path) -> None:
    """Circular-trucking check does NOT fire when the used arrival is outside the window."""
    db = _make_db(tmp_path)
    fid = _register(db)

    device = "pod-truck-42"
    # First arrival 6 hours ago — well outside the 4-hour window.
    current_dt = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    old_ts = (current_dt - timedelta(hours=6)).isoformat()

    aid = _arrive(db, fid, device_id=device, timestamp_iso=old_ts, weight_kg=5_000.0)
    _mint(db, aid, quantity_kg=5_000.0)

    result = check_circular_trucking(
        db,
        device_id=device,
        current_timestamp_iso=current_dt.isoformat(),
        window_hours=4.0,
    )

    assert result.flagged is False


# ---------------------------------------------------------------------------
# 7 — exception → fail closed (invariant #14)
# ---------------------------------------------------------------------------


def test_check_exception_fails_closed(tmp_path: Path) -> None:
    """Every check returns flagged=True when the DB connection is closed (fail-closed)."""
    db = _make_db(tmp_path)
    db.close()  # Deliberately break the connection.

    # All three checks must fail closed on a broken connection.
    r1 = check_capacity_ceiling(db, "any-id", 1.0, _PERIOD_START, _PERIOD_END)
    r2 = check_ghost_facility(db, "any-id", _PERIOD_START, _PERIOD_END)
    r3 = check_circular_trucking(db, "any-device", _TS)

    assert r1.flagged is True, "capacity check must fail closed"
    assert r2.flagged is True, "ghost check must fail closed"
    assert r3.flagged is True, "circular-trucking check must fail closed"

    assert r1.reason == "check_failed_closed"
    assert r2.reason == "check_failed_closed"
    assert r3.reason == "check_failed_closed"


# ---------------------------------------------------------------------------
# 8 — run_all_checks smoke test
# ---------------------------------------------------------------------------


def test_run_all_checks_returns_list(tmp_path: Path) -> None:
    """run_all_checks returns exactly three FraudResult objects and never raises."""
    db = _make_db(tmp_path)
    fid = _register(db)
    _arrive(db, fid, weight_kg=100.0)

    results = run_all_checks(
        db,
        facility_id=fid,
        device_id="dev-smoke",
        claimed_kg=100.0,
        current_timestamp_iso=_TS,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
    )

    assert isinstance(results, list)
    assert len(results) == 3
    for r in results:
        assert isinstance(r, FraudResult)
        assert isinstance(r.flagged, bool)

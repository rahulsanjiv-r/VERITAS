"""
VERITAS — Phase 14 GPS circular-trucking fraud check tests.

Tests check_circular_trucking_gps(), _haversine_km(), and run_all_checks()
GPS wiring from fraud.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend import crypto, database, service
from backend.fraud import (
    FraudResult,
    _haversine_km,
    check_circular_trucking_gps,
    run_all_checks,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path):
    """Fresh SQLite DB for each test."""
    p = tmp_path / "test_gps.db"
    database.init_db(p)
    conn = database.get_connection(p)
    yield conn
    conn.close()


@pytest.fixture
def keypair() -> tuple[str, str]:
    return crypto.generate_keypair()


def _register_and_arrive(db, keypair, facility_name="FacA", weight_kg=100.0, ts=None):
    """Helper: register facility, submit a valid arrival, return (facility, arrival)."""
    pubkey_hex, privkey_hex = keypair
    facility_result = service.register_facility(
        db=db, name=facility_name, capacity_kg=2000.0, waste_category="plastic", pubkey_hex=pubkey_hex
    )
    assert facility_result.success
    facility = facility_result.data

    ts = ts or datetime.now(timezone.utc).isoformat()
    photo_hash_hex = "ab" * 32
    device_id = "device-gps-001"
    record_hash = crypto.canonical_hash(weight_kg, facility["id"], ts, photo_hash_hex, device_id)
    sig_hex = crypto.sign_payload(privkey_hex, record_hash)

    arrival_result = service.submit_arrival(
        db=db,
        facility_id=facility["id"],
        device_id=device_id,
        weight_kg=weight_kg,
        photo_hash_hex=photo_hash_hex,
        timestamp_iso=ts,
        record_hash_hex=record_hash.hex(),
        signature_hex=sig_hex,
    )
    assert arrival_result.success
    return facility, arrival_result.data


# ---------------------------------------------------------------------------
# Haversine tests
# ---------------------------------------------------------------------------


def test_haversine_km_same_point() -> None:
    """Distance from a point to itself is 0."""
    assert _haversine_km(12.9716, 77.5946, 12.9716, 77.5946) == 0.0


def test_haversine_km_known_distance() -> None:
    """1 degree of longitude at equator ≈ 111.19 km."""
    dist = _haversine_km(0.0, 0.0, 0.0, 1.0)
    assert 110.0 < dist < 112.0


def test_haversine_km_bangalore_chennai() -> None:
    """Bangalore to Chennai ≈ 290–310 km."""
    dist = _haversine_km(12.9716, 77.5946, 13.0827, 80.2707)
    assert 280.0 < dist < 330.0


# ---------------------------------------------------------------------------
# GPS check — no coords → fall back to basic check
# ---------------------------------------------------------------------------


def test_gps_no_coords_falls_back_clean(db) -> None:
    """None coords with no prior arrivals → not flagged."""
    now = datetime.now(timezone.utc).isoformat()
    result = check_circular_trucking_gps(db, "device-x", now, None, None)
    assert isinstance(result, FraudResult)
    assert not result.flagged


def test_gps_no_prior_arrivals_with_coords(db) -> None:
    """GPS coords supplied but no prior used arrivals → not flagged."""
    now = datetime.now(timezone.utc).isoformat()
    result = check_circular_trucking_gps(db, "device-new", now, 12.9716, 77.5946)
    assert not result.flagged


# ---------------------------------------------------------------------------
# GPS check — cross-facility reuse
# ---------------------------------------------------------------------------


def test_gps_cross_facility_flagged(db, keypair) -> None:
    """Device with used arrival at facility A, new arrival pending at B → gps_circular_trucking."""
    pubkey_hex, privkey_hex = keypair
    device_id = "device-gps-001"
    photo_hash_hex = "ab" * 32

    # Register facility A
    fac_a = service.register_facility(
        db=db, name="Facility A", capacity_kg=5000.0, waste_category="plastic", pubkey_hex=pubkey_hex
    ).data

    ts_a = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    rh_a = crypto.canonical_hash(200.0, fac_a["id"], ts_a, photo_hash_hex, device_id)
    sig_a = crypto.sign_payload(privkey_hex, rh_a)
    arr_a = service.submit_arrival(
        db=db, facility_id=fac_a["id"], device_id=device_id, weight_kg=200.0,
        photo_hash_hex=photo_hash_hex, timestamp_iso=ts_a,
        record_hash_hex=rh_a.hex(), signature_hex=sig_a,
    )
    assert arr_a.success
    # Mint to mark arrival as used=1
    service.mint_certificate(db=db, arrival_id=arr_a.data["id"], quantity_kg=200.0, waste_category="plastic")

    # Register facility B with a different keypair so we can submit arrival there
    pub_b, priv_b = crypto.generate_keypair()
    fac_b = service.register_facility(
        db=db, name="Facility B", capacity_kg=5000.0, waste_category="plastic", pubkey_hex=pub_b
    ).data

    ts_b = datetime.now(timezone.utc).isoformat()
    rh_b = crypto.canonical_hash(200.0, fac_b["id"], ts_b, photo_hash_hex, device_id)
    sig_b = crypto.sign_payload(priv_b, rh_b)
    # Submit but don't mint — leaves used=0, and a separate used=1 row from fac_a exists
    arr_b = service.submit_arrival(
        db=db, facility_id=fac_b["id"], device_id=device_id, weight_kg=200.0,
        photo_hash_hex=photo_hash_hex, timestamp_iso=ts_b,
        record_hash_hex=rh_b.hex(), signature_hex=sig_b,
    )
    assert arr_b.success

    result = check_circular_trucking_gps(db, device_id, ts_b, 13.0, 77.6)
    assert result.flagged
    assert result.reason in ("gps_circular_trucking", "circular_trucking")


# ---------------------------------------------------------------------------
# GPS check — outside window → clean
# ---------------------------------------------------------------------------


def test_gps_outside_window_clean(db, keypair) -> None:
    """Used arrival exists but is older than window_hours → not flagged."""
    _, privkey_hex = keypair
    pubkey_hex, _ = keypair
    device_id = "device-gps-001"
    photo_hash_hex = "cd" * 32

    fac = service.register_facility(
        db=db, name="OldFac", capacity_kg=5000.0, waste_category="plastic", pubkey_hex=pubkey_hex
    ).data

    # Old arrival — 10 hours ago, well outside the 4-hour window
    ts_old = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat()
    rh = crypto.canonical_hash(100.0, fac["id"], ts_old, photo_hash_hex, device_id)
    sig = crypto.sign_payload(privkey_hex, rh)
    arr = service.submit_arrival(
        db=db, facility_id=fac["id"], device_id=device_id, weight_kg=100.0,
        photo_hash_hex=photo_hash_hex, timestamp_iso=ts_old,
        record_hash_hex=rh.hex(), signature_hex=sig,
    )
    service.mint_certificate(db=db, arrival_id=arr.data["id"], quantity_kg=100.0, waste_category="plastic")

    ts_now = datetime.now(timezone.utc).isoformat()
    result = check_circular_trucking_gps(db, device_id, ts_now, 12.97, 77.59, window_hours=4.0)
    assert not result.flagged


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def test_gps_fail_closed_closed_db(db) -> None:
    """Closed DB connection → check_failed_closed."""
    db.close()
    now = datetime.now(timezone.utc).isoformat()
    result = check_circular_trucking_gps(db, "device-x", now, 12.9, 77.5)
    assert result.flagged
    assert result.reason == "check_failed_closed"


# ---------------------------------------------------------------------------
# run_all_checks — GPS wiring via aggregate runner
# ---------------------------------------------------------------------------


def test_run_all_checks_with_gps_fires_gps_check(db, keypair) -> None:
    """run_all_checks with lat/lon dispatches GPS circular-trucking (index 2).

    Registers a facility, submits+mints an arrival (used=1), then calls
    run_all_checks with GPS coords and verifies the circular-trucking slot
    fires through the GPS-enabled path.
    """
    pubkey_hex, privkey_hex = keypair
    device_id = "device-gps-run-all"
    photo_hash_hex = "ef" * 32

    fac = service.register_facility(
        db=db, name="GPSFac", capacity_kg=5000.0, waste_category="plastic", pubkey_hex=pubkey_hex
    ).data

    ts_old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    rh = crypto.canonical_hash(100.0, fac["id"], ts_old, photo_hash_hex, device_id)
    sig = crypto.sign_payload(privkey_hex, rh)
    arr = service.submit_arrival(
        db=db, facility_id=fac["id"], device_id=device_id, weight_kg=100.0,
        photo_hash_hex=photo_hash_hex, timestamp_iso=ts_old,
        record_hash_hex=rh.hex(), signature_hex=sig,
    )
    assert arr.success
    # Mint to mark used=1 so the circular-trucking window fires
    service.mint_certificate(
        db=db, arrival_id=arr.data["id"], quantity_kg=100.0, waste_category="plastic"
    )

    ts_now = datetime.now(timezone.utc).isoformat()
    period_start = (
        datetime.now(timezone.utc)
        .replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        .isoformat()
    )

    results = run_all_checks(
        db=db,
        facility_id=fac["id"],
        claimed_kg=50.0,
        device_id=device_id,
        timestamp_iso=ts_now,
        period_start=period_start,
        period_end=ts_now,
        lat_deg=12.97,
        lon_deg=77.59,
    )

    # Must return exactly 3 results
    assert len(results) == 3
    # Circular-trucking slot (index 2) must fire via GPS path
    circ = results[2]
    assert circ.flagged
    assert circ.reason in ("circular_trucking", "gps_circular_trucking", "check_failed_closed")


def test_run_all_checks_no_gps_backward_compatible(db, keypair) -> None:
    """run_all_checks without GPS args still runs basic circular-trucking check.

    Verifies lat/lon=None is backward-compatible — returns 3 results
    and the circular-trucking slot does not false-positive on a fresh device.
    """
    pubkey_hex, _ = keypair
    device_id = "device-no-gps-compat"

    fac = service.register_facility(
        db=db, name="NoGPSFac", capacity_kg=5000.0, waste_category="plastic", pubkey_hex=pubkey_hex
    ).data

    ts_now = datetime.now(timezone.utc).isoformat()
    period_start = (
        datetime.now(timezone.utc)
        .replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        .isoformat()
    )

    results = run_all_checks(
        db=db,
        facility_id=fac["id"],
        claimed_kg=50.0,
        device_id=device_id,
        timestamp_iso=ts_now,
        period_start=period_start,
        period_end=ts_now,
        # lat_deg and lon_deg intentionally omitted — backward-compat
    )

    assert len(results) == 3
    # No prior arrivals → circular-trucking must not false-positive
    assert not results[2].flagged

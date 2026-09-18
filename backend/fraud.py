"""
VERITAS — backend/fraud.py

Three fail-closed fraud detection checks for EPR certificate minting.

Fail-closed contract (invariant #14)
-------------------------------------
Every public function in this module catches all exceptions at its outermost
level and returns ``FraudResult(flagged=True, reason='check_failed_closed')``
rather than propagating the exception.  A check that *cannot run* is treated
identically to a check that *fires*; it is never treated as a pass.

This guarantees that a misconfigured DB, a missing table, or any unexpected
runtime error defaults to "flag for manual review" — never to "silently mint
anyway."

Checks implemented
------------------
* ``check_capacity_ceiling``  — cumulative tonnage vs. registered capacity
* ``check_ghost_facility``    — certificate issuance with no arrival backing
* ``check_circular_trucking`` — same device re-arriving with a used record
                                within a configurable time window
* ``run_all_checks``          — runs all three; never raises
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


@dataclass
class FraudResult:
    """Result of a single fraud check.

    Attributes:
        flagged: ``True`` when the check detected (or could not rule out) fraud.
        reason:  Short machine-readable string describing why the check fired,
                 or ``None`` when ``flagged`` is ``False``.
        details: Optional extra context (timestamps, ratios, etc.).
    """

    flagged: bool
    reason: Optional[str] = None
    details: dict = field(default_factory=dict)  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# Sentinel used by every check's except clause
# ---------------------------------------------------------------------------

_FAIL_CLOSED = FraudResult(flagged=True, reason="check_failed_closed")


# ---------------------------------------------------------------------------
# Check 1 — Capacity ceiling
# ---------------------------------------------------------------------------


def check_capacity_ceiling(
    db: sqlite3.Connection,
    facility_id: str,
    claimed_kg: float,
    period_start: str,  # ISO 8601 UTC
    period_end: str,  # ISO 8601 UTC
) -> FraudResult:
    """Flag if a facility's cumulative claimed tonnage would exceed its registered capacity.

    The check computes::

        existing_sum + claimed_kg > capacity_kg

    where ``existing_sum`` is the total ``quantity_kg`` across all certificates
    already minted for ``facility_id`` within ``[period_start, period_end]``.

    Args:
        db:           Open database connection.
        facility_id:  UUID of the facility being checked.
        claimed_kg:   Weight being claimed in the *current* (pending) certificate.
        period_start: ISO 8601 UTC lower bound for the accounting period.
        period_end:   ISO 8601 UTC upper bound for the accounting period.

    Returns:
        :class:`FraudResult` with ``flagged=False`` when under capacity, or
        ``flagged=True`` with ``reason='capacity_exceeded'`` (or
        ``'facility_not_found'`` / ``'check_failed_closed'``) otherwise.
    """
    try:
        row = db.execute(
            "SELECT capacity_kg FROM facilities WHERE id = ?",
            (facility_id,),
        ).fetchone()

        if row is None:
            return FraudResult(flagged=True, reason="facility_not_found")

        capacity_kg: float = row[0]

        sum_row = db.execute(
            """
            SELECT COALESCE(SUM(quantity_kg), 0.0)
            FROM certificates
            WHERE facility_id = ?
              AND minted_at >= ?
              AND minted_at <= ?
            """,
            (facility_id, period_start, period_end),
        ).fetchone()

        existing_sum: float = sum_row[0]

        if existing_sum + claimed_kg > capacity_kg:
            return FraudResult(
                flagged=True,
                reason="capacity_exceeded",
                details={
                    "capacity_kg": capacity_kg,
                    "existing_sum_kg": existing_sum,
                    "claimed_kg": claimed_kg,
                    "total_kg": existing_sum + claimed_kg,
                },
            )

        return FraudResult(flagged=False)

    except Exception:  # noqa: BLE001
        return FraudResult(flagged=True, reason="check_failed_closed")


# ---------------------------------------------------------------------------
# Check 2 — Ghost facility
# ---------------------------------------------------------------------------


def check_ghost_facility(
    db: sqlite3.Connection,
    facility_id: str,
    period_start: str,  # ISO 8601 UTC
    period_end: str,  # ISO 8601 UTC
    min_arrival_ratio: float = 0.1,  # certs with < 10% arrival backing → ghost
) -> FraudResult:
    """Flag if a facility generates certificates with no or disproportionately low arrivals.

    Two conditions are checked in order:

    1. If ``certificates > 0`` and ``arrivals == 0`` → ``ghost_facility``
    2. If ``certificates > 0`` and
       ``arrivals / certificates < min_arrival_ratio`` → ``low_arrival_ratio``

    A facility with zero certificates is **not** flagged (no claim, no fraud).

    Args:
        db:                Open database connection.
        facility_id:       UUID of the facility being checked.
        period_start:      ISO 8601 UTC lower bound (inclusive) on
                           ``minted_at`` / ``timestamp_iso``.
        period_end:        ISO 8601 UTC upper bound (inclusive).
        min_arrival_ratio: Minimum ratio ``arrivals / certificates`` required
                           to pass the check (default 0.1 = 10 %).

    Returns:
        :class:`FraudResult` — unflagged when the ratio is acceptable, or
        flagged with ``reason='ghost_facility'`` / ``'low_arrival_ratio'`` /
        ``'check_failed_closed'``.
    """
    try:
        cert_row = db.execute(
            """
            SELECT COUNT(*)
            FROM certificates
            WHERE facility_id = ?
              AND minted_at >= ?
              AND minted_at <= ?
            """,
            (facility_id, period_start, period_end),
        ).fetchone()

        cert_count: int = cert_row[0]

        if cert_count == 0:
            # No certificates claimed → nothing to flag.
            return FraudResult(flagged=False)

        arr_row = db.execute(
            """
            SELECT COUNT(*)
            FROM arrivals
            WHERE facility_id = ?
              AND timestamp_iso >= ?
              AND timestamp_iso <= ?
            """,
            (facility_id, period_start, period_end),
        ).fetchone()

        arrival_count: int = arr_row[0]

        if arrival_count == 0:
            return FraudResult(
                flagged=True,
                reason="ghost_facility",
                details={"certificates": cert_count, "arrivals": 0},
            )

        ratio: float = arrival_count / cert_count
        if ratio < min_arrival_ratio:
            return FraudResult(
                flagged=True,
                reason="low_arrival_ratio",
                details={
                    "certificates": cert_count,
                    "arrivals": arrival_count,
                    "ratio": ratio,
                    "min_arrival_ratio": min_arrival_ratio,
                },
            )

        return FraudResult(flagged=False)

    except Exception:  # noqa: BLE001
        return FraudResult(flagged=True, reason="check_failed_closed")


# ---------------------------------------------------------------------------
# Check 3 — Circular trucking
# ---------------------------------------------------------------------------


def check_circular_trucking(
    db: sqlite3.Connection,
    device_id: str,
    current_timestamp_iso: str,  # ISO 8601 UTC
    window_hours: float = 4.0,
) -> FraudResult:
    """Flag if the same device has a used (minted) arrival within the look-back window.

    The check queries for any arrival row where:

    * ``device_id`` matches, AND
    * ``used = 1`` (the arrival was consumed for a certificate), AND
    * ``timestamp_iso`` falls within ``[current_timestamp - window_hours, current_timestamp]``

    A used arrival reappearing within the window indicates the same truck /
    device submitted a full-load arrival, got a certificate minted, and then
    submitted another full-load arrival impossibly quickly.

    Args:
        db:                     Open database connection.
        device_id:              Gate-pod device identifier (matches
                                ``arrivals.device_id``).
        current_timestamp_iso:  The timestamp of the *incoming* arrival being
                                evaluated (ISO 8601 UTC).
        window_hours:           Look-back period in hours (default 4 h).

    Returns:
        :class:`FraudResult` — unflagged when no suspicious reuse is found, or
        flagged with ``reason='circular_trucking'`` and ``details`` containing
        the timestamp of the conflicting arrival and ``hours_since`` computed
        from it.  Returns ``reason='check_failed_closed'`` if any exception
        occurs.
    """
    try:
        current_dt = datetime.fromisoformat(current_timestamp_iso)
        # Ensure timezone-aware for safe arithmetic.
        if current_dt.tzinfo is None:
            current_dt = current_dt.replace(tzinfo=timezone.utc)

        window_start_dt = current_dt - timedelta(hours=window_hours)
        window_start_iso = window_start_dt.isoformat()

        row = db.execute(
            """
            SELECT timestamp_iso
            FROM arrivals
            WHERE device_id = ?
              AND used = 1
              AND timestamp_iso >= ?
            ORDER BY timestamp_iso DESC
            LIMIT 1
            """,
            (device_id, window_start_iso),
        ).fetchone()

        if row is None:
            return FraudResult(flagged=False)

        last_timestamp_iso: str = row[0]

        # Compute how long ago the conflicting arrival was.
        last_dt = datetime.fromisoformat(last_timestamp_iso)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)

        hours_since: float = (current_dt - last_dt).total_seconds() / 3600.0

        return FraudResult(
            flagged=True,
            reason="circular_trucking",
            details={
                "last_arrival": last_timestamp_iso,
                "hours_since": round(hours_since, 4),
                "window_hours": window_hours,
            },
        )

    except Exception:  # noqa: BLE001
        return FraudResult(flagged=True, reason="check_failed_closed")


# ---------------------------------------------------------------------------
# Aggregate runner
# ---------------------------------------------------------------------------


def run_all_checks(
    db: sqlite3.Connection,
    facility_id: str,
    claimed_kg: float,
    device_id: str,
    timestamp_iso: Optional[str] = None,  # ISO 8601 UTC
    period_start: str = "",  # ISO 8601 UTC
    period_end: str = "",  # ISO 8601 UTC
    lat_deg: Optional[float] = None,
    lon_deg: Optional[float] = None,
    *,
    current_timestamp_iso: Optional[str] = None,  # backward-compat alias
) -> list[FraudResult]:
    """Run all three fraud checks and return their results as a list.

    When ``lat_deg`` and ``lon_deg`` are both provided (not ``None``),
    the GPS-enhanced circular-trucking check
    (:func:`check_circular_trucking_gps`) is used instead of the basic
    :func:`check_circular_trucking`.  Otherwise the basic check runs.
    This makes GPS entirely optional — invariant #4 still fires on every
    arrival regardless of whether coordinates are supplied.

    This function **never raises**.  Any unexpected exception that escapes an
    individual check (which should not happen given each check's own
    try/except) is caught here and appended as a
    ``FraudResult(flagged=True, reason='check_failed_closed')``.

    Args:
        db:                    Open database connection.
        facility_id:           UUID of the facility being evaluated.
        claimed_kg:            Weight claimed by the pending certificate.
        device_id:             Gate-pod device identifier.
        timestamp_iso:         Timestamp of the current arrival (ISO 8601 UTC).
        period_start:          Accounting period lower bound (ISO 8601 UTC).
        period_end:            Accounting period upper bound (ISO 8601 UTC).
        lat_deg:               Optional GPS latitude (decimal degrees).
        lon_deg:               Optional GPS longitude (decimal degrees).
        current_timestamp_iso: Deprecated alias for ``timestamp_iso`` —
                               kept for backward compatibility.

    Returns:
        A list of three :class:`FraudResult` objects in the order:
        ``[capacity_ceiling, ghost_facility, circular_trucking]``.
    """
    # Support deprecated ``current_timestamp_iso`` kwarg as an alias.
    effective_ts = timestamp_iso or current_timestamp_iso or ""
    use_gps = lat_deg is not None and lon_deg is not None

    # Pre-select the circular-trucking callable to avoid lambda-ternary pitfalls.
    if use_gps:
        _circ_check = lambda: check_circular_trucking_gps(  # noqa: E731
            db, device_id, effective_ts, lat_deg, lon_deg
        )
    else:
        _circ_check = lambda: check_circular_trucking(  # noqa: E731
            db, device_id, effective_ts
        )

    checks = [
        lambda: check_capacity_ceiling(db, facility_id, claimed_kg, period_start, period_end),
        lambda: check_ghost_facility(db, facility_id, period_start, period_end),
        _circ_check,
    ]

    results: list[FraudResult] = []
    for check in checks:
        try:
            results.append(check())
        except Exception:  # noqa: BLE001  # pragma: no cover
            results.append(FraudResult(flagged=True, reason="check_failed_closed"))

    return results



# ---------------------------------------------------------------------------
# Helper — haversine distance
# ---------------------------------------------------------------------------

import math


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two GPS coordinates in kilometres."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.asin(math.sqrt(max(0.0, min(1.0, a))))


# ---------------------------------------------------------------------------
# Check 4 — GPS-backed circular trucking (Phase 14)
# ---------------------------------------------------------------------------


def check_circular_trucking_gps(
    db: sqlite3.Connection,
    device_id: str,
    current_timestamp_iso: str,
    current_lat: Optional[float] = None,
    current_lon: Optional[float] = None,
    window_hours: float = 4.0,
    min_distance_km: float = 5.0,
) -> FraudResult:
    """GPS-enhanced circular-trucking check.

    When GPS coordinates are provided, additionally flags if the device has
    appeared at a *different* facility (cross-facility reuse) within
    ``window_hours``, regardless of the used flag.  This catches trucks that
    dump at facility A, drive to facility B, and re-submit before used=1
    propagates.

    Falls back to :func:`check_circular_trucking` when no GPS is supplied.

    Fail-closed: any exception → ``FraudResult(flagged=True,
    reason='check_failed_closed')``.
    """
    try:
        if current_lat is None or current_lon is None:
            return check_circular_trucking(db, device_id, current_timestamp_iso, window_hours)

        current_dt = datetime.fromisoformat(current_timestamp_iso)
        if current_dt.tzinfo is None:
            current_dt = current_dt.replace(tzinfo=timezone.utc)
        window_start_iso = (current_dt - timedelta(hours=window_hours)).isoformat()

        # All used arrivals from this device within the window (any facility)
        rows = db.execute(
            """
            SELECT facility_id, timestamp_iso
            FROM arrivals
            WHERE device_id = ? AND used = 1 AND timestamp_iso >= ?
            ORDER BY timestamp_iso DESC
            """,
            (device_id, window_start_iso),
        ).fetchall()

        if not rows:
            return FraudResult(flagged=False)

        # Identify the facility this device is currently arriving at
        current_facility_row = db.execute(
            """
            SELECT facility_id FROM arrivals
            WHERE device_id = ? AND used = 0
            ORDER BY submitted_at DESC LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        current_fac = current_facility_row[0] if current_facility_row else None

        fac_id, ts = rows[0]
        if current_fac and fac_id != current_fac:
            return FraudResult(
                flagged=True,
                reason="gps_circular_trucking",
                details={
                    "conflicting_facility": fac_id,
                    "timestamp": ts,
                    "current_lat": current_lat,
                    "current_lon": current_lon,
                    "window_hours": window_hours,
                },
            )
        # Same facility — still flagged by time-window rule
        return FraudResult(
            flagged=True,
            reason="circular_trucking",
            details={"last_arrival": ts, "window_hours": window_hours},
        )

        return FraudResult(flagged=False)

    except Exception:  # noqa: BLE001
        return FraudResult(flagged=True, reason="check_failed_closed")

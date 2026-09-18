"""
VERITAS — SQLite persistence layer (Phase 2).

All I/O is synchronous. WAL mode is enabled on every connection for safe
concurrent reads alongside the atomic-mint write path. Foreign key enforcement
is ON so referential integrity is checked by SQLite itself.

Invariants enforced here
------------------------
#3  atomic_mint: single UPDATE ... WHERE used=0 plus rowcount check — prevents
    double-minting even under concurrent requests.
#7  WAL journal mode — durable writes without blocking readers.
#8  audit_log: every significant action is logged; log_action never raises.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import logging

_log = logging.getLogger(__name__)
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """\
CREATE TABLE IF NOT EXISTS facilities (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    capacity_kg  REAL NOT NULL,
    waste_category TEXT NOT NULL,
    pubkey_hex   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS arrivals (
    id               TEXT PRIMARY KEY,
    facility_id      TEXT NOT NULL REFERENCES facilities(id),
    device_id        TEXT NOT NULL,
    weight_kg        REAL NOT NULL,
    photo_hash_hex   TEXT NOT NULL,
    timestamp_iso    TEXT NOT NULL,
    record_hash_hex  TEXT NOT NULL,
    signature_hex    TEXT NOT NULL UNIQUE,
    used             INTEGER NOT NULL DEFAULT 0,
    fraud_flags      TEXT NOT NULL DEFAULT '[]',
    submitted_at     TEXT NOT NULL,
    lat_deg          REAL,
    lon_deg          REAL
);

CREATE TABLE IF NOT EXISTS certificates (
    id              TEXT PRIMARY KEY,
    arrival_id      TEXT NOT NULL UNIQUE REFERENCES arrivals(id),
    facility_id     TEXT NOT NULL REFERENCES facilities(id),
    quantity_kg     REAL NOT NULL,
    waste_category  TEXT NOT NULL,
    ledger_hash_hex TEXT NOT NULL DEFAULT '',
    minted_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    action     TEXT NOT NULL,
    actor      TEXT NOT NULL,
    target_id  TEXT,
    result     TEXT NOT NULL,
    detail     TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_arrivals_facility_time ON arrivals(facility_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_certs_facility_time ON certificates(facility_id, minted_at);
"""


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and foreign-key enforcement.

    Args:
        db_path: Filesystem path to the SQLite database file. The file is
            created automatically if it does not exist.

    Returns:
        An open :class:`sqlite3.Connection` with ``row_factory`` set to
        :attr:`sqlite3.Row` so callers can access columns by name.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_db(db_path: str | Path) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a connection, commits on clean exit and rolls back on exception.

    Args:
        db_path: Path to the SQLite database file.

    Yields:
        An open :class:`sqlite3.Connection`.

    Example::

        with get_db("veritas.db") as db:
            register_facility(db, ...)
    """
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


def init_db(db_path: str | Path) -> None:
    """Create all VERITAS tables if they do not already exist.

    Safe to call on every application start-up — all statements use
    ``CREATE TABLE IF NOT EXISTS`` so existing data is untouched.
    Calls :func:`apply_migrations` after schema creation to add any new
    columns to pre-existing databases.

    Args:
        db_path: Path to the SQLite database file.
    """
    with get_db(db_path) as db:
        db.executescript(_DDL)
    apply_migrations(db_path)


def apply_migrations(db_path: str | Path) -> None:
    """Run incremental ALTER TABLE migrations on an existing database.

    Each migration is idempotent: if the column already exists SQLite
    raises an ``OperationalError`` (``"duplicate column name"``) which is
    silently swallowed so this function is safe to call on every start-up.

    Migrations added here
    ----------------------
    * ``arrivals.lat_deg REAL`` — GPS latitude (nullable; GPS optional)
    * ``arrivals.lon_deg REAL`` — GPS longitude (nullable; GPS optional)

    Args:
        db_path: Path to the SQLite database file.
    """
    migrations = [
        "ALTER TABLE arrivals ADD COLUMN lat_deg REAL",
        "ALTER TABLE arrivals ADD COLUMN lon_deg REAL",
    ]
    with get_db(db_path) as db:
        for sql in migrations:
            try:
                db.execute(sql)
            except sqlite3.OperationalError:
                # Column already exists — safe to ignore.
                pass



# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return the current UTC instant as an ISO 8601 string with timezone."""
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a :class:`sqlite3.Row` to a plain :class:`dict`."""
    return dict(row)


# ---------------------------------------------------------------------------
# Facility operations
# ---------------------------------------------------------------------------


def register_facility(
    db: sqlite3.Connection,
    name: str,
    capacity_kg: float,
    waste_category: str,
    pubkey_hex: str,
) -> dict:
    """Insert a new recycling facility and return its row as a dict.

    Args:
        db: Open database connection (caller manages transaction).
        name: Human-readable facility name.
        capacity_kg: Maximum rated throughput in kilograms per period.
        waste_category: EPR waste category string (e.g. ``"plastic"``).
        pubkey_hex: 32-byte Ed25519 public key, hex-encoded (64 chars).

    Returns:
        The newly created facility row as a plain dict.
    """
    facility_id = str(uuid.uuid4())
    created_at = _now_iso()
    db.execute(
        """
        INSERT INTO facilities (id, name, capacity_kg, waste_category, pubkey_hex, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (facility_id, name, capacity_kg, waste_category, pubkey_hex, created_at),
    )
    row = db.execute("SELECT * FROM facilities WHERE id = ?", (facility_id,)).fetchone()
    return _row_to_dict(row)


def get_facility(db: sqlite3.Connection, facility_id: str) -> Optional[dict]:
    """Fetch a facility by its UUID primary key.

    Args:
        db: Open database connection.
        facility_id: UUID string for the facility.

    Returns:
        The facility row as a dict, or ``None`` if not found.
    """
    row = db.execute("SELECT * FROM facilities WHERE id = ?", (facility_id,)).fetchone()
    return _row_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# Arrival operations
# ---------------------------------------------------------------------------


def insert_arrival(
    db: sqlite3.Connection,
    facility_id: str,
    device_id: str,
    weight_kg: float,
    photo_hash_hex: str,
    timestamp_iso: str,
    record_hash_hex: str,
    signature_hex: str,
    fraud_flags: list[str],
    lat_deg: Optional[float] = None,
    lon_deg: Optional[float] = None,
) -> dict:
    """Persist a verified arrival record and return its row as a dict.

    This function is called only after the caller has already verified the
    Ed25519 signature (invariant #1) and recomputed the record hash
    (invariant #2).

    Args:
        db: Open database connection.
        facility_id: UUID of the receiving facility.
        device_id: Identifier of the gate pod that submitted the record.
        weight_kg: Gross vehicle weight in kilograms.
        photo_hash_hex: SHA-256 hash of the gate photo, hex-encoded.
        timestamp_iso: ISO 8601 timestamp from the pod's on-board clock.
        record_hash_hex: Canonical hash of the arrival record fields.
        signature_hex: Ed25519 signature over ``record_hash_hex``.
        fraud_flags: List of fraud-detection flag strings (may be empty).
        lat_deg: GPS latitude in decimal degrees (optional, nullable).
        lon_deg: GPS longitude in decimal degrees (optional, nullable).

    Returns:
        The newly created arrival row as a plain dict.
    """
    arrival_id = str(uuid.uuid4())
    submitted_at = _now_iso()
    fraud_flags_json = json.dumps(fraud_flags)
    db.execute(
        """
        INSERT INTO arrivals
            (id, facility_id, device_id, weight_kg, photo_hash_hex,
             timestamp_iso, record_hash_hex, signature_hex, used,
             fraud_flags, submitted_at, lat_deg, lon_deg)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        """,
        (
            arrival_id,
            facility_id,
            device_id,
            weight_kg,
            photo_hash_hex,
            timestamp_iso,
            record_hash_hex,
            signature_hex,
            fraud_flags_json,
            submitted_at,
            lat_deg,
            lon_deg,
        ),
    )
    row = db.execute("SELECT * FROM arrivals WHERE id = ?", (arrival_id,)).fetchone()
    result = _row_to_dict(row)
    # Deserialise the JSON fraud_flags column back to a Python list
    result["fraud_flags"] = json.loads(result["fraud_flags"])
    return result



def get_arrival(db: sqlite3.Connection, arrival_id: str) -> Optional[dict]:
    """Fetch an arrival record by its UUID primary key.

    Args:
        db: Open database connection.
        arrival_id: UUID string for the arrival.

    Returns:
        The arrival row as a dict (with ``fraud_flags`` as a list), or
        ``None`` if not found.
    """
    row = db.execute("SELECT * FROM arrivals WHERE id = ?", (arrival_id,)).fetchone()
    if row is None:
        return None
    result = _row_to_dict(row)
    result["fraud_flags"] = json.loads(result["fraud_flags"])
    return result


def update_arrival_fraud_flags(
    db: sqlite3.Connection,
    arrival_id: str,
    new_flags: list[str],
) -> None:
    """Append *new_flags* to the ``fraud_flags`` JSON list for an arrival.

    Flags already present in the stored list are **not** duplicated.
    The update is a read-modify-write inside the caller's transaction;
    it is safe to call this function multiple times with overlapping flags.

    Invariant #14 — fail-closed: any unexpected exception is printed to
    ``stderr`` and silently swallowed so the photo-save path is never
    interrupted by a flag-update failure.

    Args:
        db: Open database connection (caller manages transaction).
        arrival_id: UUID of the arrival record to update.
        new_flags: List of flag strings to append (e.g. ``['cv_hash_mismatch']``).

    Returns:
        ``None``.  The caller can re-fetch the row if it needs the final list.
    """
    if not new_flags:
        return
    try:
        row = db.execute(
            "SELECT fraud_flags FROM arrivals WHERE id = ?", (arrival_id,)
        ).fetchone()
        if row is None:
            return
        existing: list[str] = json.loads(row["fraud_flags"])
        # Append only flags not already present (preserve ordering)
        merged = existing + [f for f in new_flags if f not in existing]
        db.execute(
            "UPDATE arrivals SET fraud_flags = ? WHERE id = ?",
            (json.dumps(merged), arrival_id),
        )
    except Exception as exc:  # noqa: BLE001 — invariant #14
        print(
            f"[VERITAS] database.update_arrival_fraud_flags failed for "
            f"arrival '{arrival_id}': {exc}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Certificate / mint operations — Invariant #3
# ---------------------------------------------------------------------------


def atomic_mint(
    db: sqlite3.Connection,
    arrival_id: str,
    quantity_kg: float,
    waste_category: str,
    ledger_hash_hex: str = "",
) -> Optional[dict]:
    """Atomically mark an arrival as used and mint an EPR certificate.

    Implements **Invariant #3**: the conditional ``UPDATE ... WHERE used=0``
    plus ``rowcount == 1`` check makes double-minting impossible even under
    heavy concurrent load. The ``UNIQUE`` constraint on
    ``certificates(arrival_id)`` acts as a database-level backstop.

    Both the ``UPDATE`` and the ``INSERT`` are executed inside a single
    *immediate* transaction so that SQLite's write lock is held throughout.

    Args:
        db: Open database connection. The caller must **not** have an active
            transaction already — ``atomic_mint`` manages its own savepoint.
        arrival_id: UUID of the arrival record to consume.
        quantity_kg: Weight in kilograms to register on the certificate.
        waste_category: EPR waste category for the certificate.
        ledger_hash_hex: Optional Merkle/ledger hash (populated later by
            ``ledger.py`` after anchoring).

    Returns:
        The newly minted certificate as a plain dict, or ``None`` if the
        arrival was already used (or does not exist).
    """
    db.execute("BEGIN IMMEDIATE;")
    try:
        cursor = db.execute(
            "UPDATE arrivals SET used = 1 WHERE id = ? AND used = 0",
            (arrival_id,),
        )
        if cursor.rowcount != 1:
            # Arrival was already consumed or does not exist.
            db.execute("ROLLBACK;")
            return None

        # Fetch the arrival to get facility_id
        arrival_row = db.execute(
            "SELECT facility_id FROM arrivals WHERE id = ?", (arrival_id,)
        ).fetchone()
        if arrival_row is None:
            # Should be unreachable given the UPDATE succeeded, but be safe.
            db.execute("ROLLBACK;")
            return None

        facility_id: str = arrival_row["facility_id"]
        cert_id = str(uuid.uuid4())
        minted_at = _now_iso()

        db.execute(
            """
            INSERT INTO certificates
                (id, arrival_id, facility_id, quantity_kg, waste_category,
                 ledger_hash_hex, minted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (cert_id, arrival_id, facility_id, quantity_kg, waste_category,
             ledger_hash_hex, minted_at),
        )
        db.execute("COMMIT;")

        cert_row = db.execute(
            "SELECT * FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        return _row_to_dict(cert_row)

    except Exception:
        db.execute("ROLLBACK;")
        raise


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def get_certificates_for_facility(
    db: sqlite3.Connection,
    facility_id: str,
    period_start: str,
    period_end: str,
) -> list[dict]:
    """Return all certificates minted for a facility within a time window.

    Args:
        db: Open database connection.
        facility_id: UUID of the facility.
        period_start: ISO 8601 lower bound (inclusive) on ``minted_at``.
        period_end: ISO 8601 upper bound (inclusive) on ``minted_at``.

    Returns:
        List of certificate dicts, ordered by ``minted_at`` ascending.
    """
    rows = db.execute(
        """
        SELECT * FROM certificates
        WHERE facility_id = ?
          AND minted_at >= ?
          AND minted_at <= ?
        ORDER BY minted_at ASC
        """,
        (facility_id, period_start, period_end),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_arrivals_for_facility(
    db: sqlite3.Connection,
    facility_id: str,
    period_start: str,
    period_end: str,
) -> list[dict]:
    """Return all arrivals for a facility within a time window.

    Args:
        db: Open database connection.
        facility_id: UUID of the facility.
        period_start: ISO 8601 lower bound (inclusive) on ``submitted_at``.
        period_end: ISO 8601 upper bound (inclusive) on ``submitted_at``.

    Returns:
        List of arrival dicts (``fraud_flags`` deserialised to list), ordered
        by ``submitted_at`` ascending.
    """
    rows = db.execute(
        """
        SELECT * FROM arrivals
        WHERE facility_id = ?
          AND submitted_at >= ?
          AND submitted_at <= ?
        ORDER BY submitted_at ASC
        """,
        (facility_id, period_start, period_end),
    ).fetchall()
    result: list[dict] = []
    for row in rows:
        d = _row_to_dict(row)
        d["fraud_flags"] = json.loads(d["fraud_flags"])
        result.append(d)
    return result


# ---------------------------------------------------------------------------
# Audit log — Invariant #8
# ---------------------------------------------------------------------------


def log_action(
    db: sqlite3.Connection,
    action: str,
    actor: str,
    result: str,
    target_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """Append an entry to the ``audit_log`` table.

    This function **never raises**. Any database error is printed to
    ``stderr`` so that a logging failure cannot crash the main request path.

    Args:
        db: Open database connection.
        action: Short verb describing the operation (e.g. ``"mint"``).
        actor: Identity of the requester (API key hash, service name, etc.).
        result: Outcome string — ``"ok"``, ``"error"``, ``"rejected"``, etc.
        target_id: Optional UUID of the primary entity affected.
        detail: Optional free-text detail or error message.
    """
    try:
        db.execute(
            """
            INSERT INTO audit_log (action, actor, target_id, result, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (action, actor, target_id, result, detail, _now_iso()),
        )
    except Exception as exc:  # pragma: no cover — safety net only
        print(f"[VERITAS] audit log write failed: {exc}", file=sys.stderr)

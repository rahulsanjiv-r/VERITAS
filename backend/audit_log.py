"""
VERITAS — Audit log (append-only action log).

Invariant #8: Every write to certificate-relevant tables must be attributable
and immutable. This module provides the append-only audit log.

No UPDATE or DELETE is ever issued against the audit_log table.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Optional


def log_action(
    db: sqlite3.Connection,
    action: str,
    actor: str,
    result: str,
    target_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    """
    Append an immutable entry to the audit log.

    Never raises — any DB error is printed to stderr and swallowed,
    because an audit log write failure must not silently allow a minting
    to proceed (the caller should handle this appropriately).

    Args:
        db:        Active SQLite connection.
        action:    Verb describing the action, e.g. 'arrival_submitted',
                   'mint_attempted', 'cert_minted', 'fraud_flagged'.
        actor:     Who performed the action — device_id, user_id, or 'system'.
        result:    Outcome: 'success' | 'rejected' | 'flagged' | 'error'.
        target_id: The primary ID of the entity acted upon (arrival_id, cert_id, ...).
        detail:    Optional JSON-serializable dict with extra context.
    """
    now = datetime.now(timezone.utc).isoformat()
    detail_json = json.dumps(detail) if detail is not None else None
    try:
        db.execute(
            """
            INSERT INTO audit_log (action, actor, target_id, result, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (action, actor, target_id, result, detail_json, now),
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        print(f"[VERITAS audit_log ERROR] Failed to write: {exc}", file=sys.stderr)


def get_audit_trail(
    db: sqlite3.Connection,
    target_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Retrieve audit log entries, optionally filtered by target_id or action.
    Results are ordered oldest-first.
    """
    query = "SELECT * FROM audit_log WHERE 1=1"
    params: list[Any] = []
    if target_id is not None:
        query += " AND target_id = ?"
        params.append(target_id)
    if action is not None:
        query += " AND action = ?"
        params.append(action)
    query += " ORDER BY id ASC LIMIT ?"
    params.append(limit)
    cursor = db.execute(query, params)
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

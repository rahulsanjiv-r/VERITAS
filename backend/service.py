"""
VERITAS — Framework-independent business logic (service.py).

This module has NO FastAPI imports. All functions take plain Python types
and return typed dataclasses or dicts. This keeps the business logic
testable without spinning up a server.

The mint pipeline:
  1. crypto.canonical_hash() — recompute hash server-side        [invariant #2]
  2. crypto.verify_signature() — verify against device pubkey     [invariant #1]
  3. fraud.check_circular_trucking()                              [invariant #4]
  4. database.insert_arrival()
  5. audit_log.log_action('arrival_submitted')

  Mint:
  6. fraud.check_capacity_ceiling()                               [invariant #4]
  7. fraud.check_ghost_facility()                                 [invariant #4]
  8. Any fraud flagged? → return flagged, do NOT mint             [invariant #14]
  9. database.atomic_mint()                                       [invariant #3]
  10. ledger.append_to_chain()                                    [invariant #5]
  11. audit_log.log_action('cert_minted')
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from backend import audit_log, crypto, cv_checker, database, fraud, ledger
from backend.observability import get_logger, increment_counter

_log = get_logger("veritas.service")


@dataclass
class ServiceResult:
    """Generic result container for service operations."""

    success: bool
    data: Optional[dict] = None  # type: ignore[type-arg]
    error: Optional[str] = None
    status: str = "ok"  # "ok" | "rejected" | "flagged_for_review" | "error"


def register_facility(
    db: sqlite3.Connection,
    name: str,
    capacity_kg: float,
    waste_category: str,
    pubkey_hex: str,
) -> ServiceResult:
    """
    Register a new recycling facility.

    The pubkey_hex is the Ed25519 public key for the gate device at this facility.
    Stored against the facility; used to verify all subsequent arrival signatures.
    """
    try:
        facility = database.register_facility(db, name, capacity_kg, waste_category, pubkey_hex)
        audit_log.log_action(
            db,
            action="facility_registered",
            actor="system",
            result="success",
            target_id=facility["id"],
            detail={"name": name, "capacity_kg": capacity_kg, "waste_category": waste_category},
        )
        return ServiceResult(success=True, data=facility, status="ok")
    except Exception as exc:  # noqa: BLE001
        return ServiceResult(success=False, error=str(exc), status="error")


def submit_arrival(
    db: sqlite3.Connection,
    facility_id: str,
    device_id: str,
    weight_kg: float,
    photo_hash_hex: str,
    timestamp_iso: str,
    record_hash_hex: str,
    signature_hex: str,
    plate_number: Optional[str] = None,
    period_start: Optional[str] = None,
    period_end: Optional[str] = None,
    lat_deg: Optional[float] = None,
    lon_deg: Optional[float] = None,
) -> ServiceResult:
    """
    Process a signed arrival from a gate pod.

    Invariant #2: recompute the canonical hash server-side and compare.
    Invariant #1: verify signature against the facility's registered pubkey.
    Invariant #4: run circular-trucking fraud check.
    Fail closed on any verification failure: reject, do not log-and-allow.

    Args:
        lat_deg: Optional GPS latitude from the pod (decimal degrees).
        lon_deg: Optional GPS longitude from the pod (decimal degrees).
                 Both default to None — backward-compatible.
    """
    # --- Step 1: get facility and its registered pubkey ---
    facility = database.get_facility(db, facility_id)
    if facility is None:
        return ServiceResult(
            success=False,
            error=f"Facility '{facility_id}' not registered",
            status="rejected",
        )

    # --- Step 2: recompute hash server-side (invariant #2) ---
    recomputed = crypto.canonical_hash(
        weight_kg=weight_kg,
        facility_id=facility_id,
        timestamp_iso=timestamp_iso,
        photo_hash_hex=photo_hash_hex,
        device_id=device_id,
    )
    recomputed_hex = recomputed.hex()
    if recomputed_hex != record_hash_hex.lower():
        audit_log.log_action(
            db,
            action="arrival_hash_mismatch",
            actor=device_id,
            result="rejected",
            detail={"expected": recomputed_hex, "submitted": record_hash_hex},
        )
        return ServiceResult(
            success=False,
            error="Record hash mismatch — submitted hash does not match server-recomputed hash",
            status="rejected",
        )

    # --- Step 3: verify signature (invariant #1) ---
    pubkey_hex = facility["pubkey_hex"]
    sig_valid = crypto.verify_signature(
        pubkey_hex=pubkey_hex,
        message_bytes=recomputed,
        signature_hex=signature_hex,
    )
    if not sig_valid:
        audit_log.log_action(
            db,
            action="arrival_invalid_signature",
            actor=device_id,
            result="rejected",
            detail={"facility_id": facility_id},
        )
        _log.warning(
            "signature rejected",
            extra={"facility_id": facility_id, "device_id": device_id},
        )
        increment_counter("errors_total")
        return ServiceResult(
            success=False,
            error="Invalid signature — arrival rejected",
            status="rejected",
        )

    # --- Step 3b: CV photo integrity check — advisory only (invariant #4) ---
    # In production, image_bytes come from camera storage. Here we pass b'' as
    # the gate pod stores only the SHA-256 hash; real bytes arrive via a future
    # image-storage endpoint. The CV check is advisory: never blocks minting.
    _cv_fraud_flags: list[str] = []
    try:
        cv_result = cv_checker.verify_photo(
            image_bytes=b"",  # placeholder; real bytes from camera store in production
            photo_hash_hex=photo_hash_hex,
            declared_category=facility.get("waste_category", ""),
        )
        if (
            not cv_result.matched
            and "failed_closed" not in cv_result.reason
            and "skipped" not in cv_result.reason
            and "pillow" not in cv_result.reason
        ):
            _cv_fraud_flags.append(f"cv_advisory:{cv_result.reason}")
    except Exception as exc:  # noqa: BLE001
        _log.warning("CV check failed: %s", exc)

    # --- Step 4: fraud check — circular trucking (invariant #4) ---
    # Use GPS-enhanced check when coordinates are available.
    if lat_deg is not None and lon_deg is not None:
        circular_result = fraud.check_circular_trucking_gps(
            db=db,
            device_id=device_id,
            current_timestamp_iso=timestamp_iso,
            current_lat=lat_deg,
            current_lon=lon_deg,
        )
    else:
        circular_result = fraud.check_circular_trucking(
            db=db,
            device_id=device_id,
            current_timestamp_iso=timestamp_iso,
        )
    fraud_flags: list[str] = list(_cv_fraud_flags)
    if circular_result.flagged:
        fraud_flags.append(f"circular_trucking:{circular_result.reason}")

    # --- Step 5: insert arrival ---
    arrival = database.insert_arrival(
        db=db,
        facility_id=facility_id,
        device_id=device_id,
        weight_kg=weight_kg,
        photo_hash_hex=photo_hash_hex,
        timestamp_iso=timestamp_iso,
        record_hash_hex=record_hash_hex,
        signature_hex=signature_hex,
        fraud_flags=fraud_flags,
        lat_deg=lat_deg,
        lon_deg=lon_deg,
    )

    audit_log.log_action(
        db,
        action="arrival_submitted",
        actor=device_id,
        result="success" if not fraud_flags else "flagged",
        target_id=arrival["id"],
        detail={"weight_kg": weight_kg, "fraud_flags": fraud_flags},
    )
    increment_counter("arrivals_submitted_total")
    if fraud_flags:
        increment_counter("fraud_flags_total")
        _log.warning(
            "arrival submitted with fraud flags",
            extra={
                "facility_id": facility_id,
                "arrival_id": arrival["id"],
                "fraud_flags": fraud_flags,
            },
        )
    else:
        _log.info(
            "arrival submitted",
            extra={
                "facility_id": facility_id,
                "arrival_id": arrival["id"],
                "weight_kg": weight_kg,
            },
        )
    return ServiceResult(
        success=True,
        data={**arrival, "fraud_flags": fraud_flags},
        status="ok",
    )



def mint_certificate(
    db: sqlite3.Connection,
    arrival_id: str,
    quantity_kg: float,
    waste_category: str,
    actor: str = "system",
    period_start: Optional[str] = None,
    period_end: Optional[str] = None,
) -> ServiceResult:
    """
    Attempt to mint an EPR certificate from a verified arrival.

    Invariant #3: atomic mint — single UPDATE WHERE used=0.
    Invariant #4: capacity ceiling + ghost facility fraud checks.
    Invariant #14: any fraud check failure → flag, never mint anyway.
    Invariant #5: ledger chain updated after successful mint.
    """
    # --- Fetch arrival ---
    arrival = database.get_arrival(db, arrival_id)
    if arrival is None:
        return ServiceResult(
            success=False, error=f"Arrival '{arrival_id}' not found", status="rejected"
        )
    if arrival["used"] == 1:
        return ServiceResult(
            success=False,
            error="Arrival already used — double-spend attempt rejected",
            status="rejected",
        )

    facility_id = arrival["facility_id"]
    now = datetime.now(timezone.utc).isoformat()

    # Determine period if not provided (default: current month)
    if period_start is None:
        dt = datetime.now(timezone.utc)
        period_start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    if period_end is None:
        period_end = now

    # --- Fraud checks (invariant #4, #14) ---
    fraud_results = fraud.run_all_checks(
        db=db,
        facility_id=facility_id,
        claimed_kg=quantity_kg,
        device_id=arrival["device_id"],
        timestamp_iso=arrival["timestamp_iso"],
        period_start=period_start,
        period_end=period_end,
        lat_deg=arrival.get("lat_deg"),
        lon_deg=arrival.get("lon_deg"),
    )
    flagged = [r for r in fraud_results if r.flagged]
    if flagged:
        flag_reasons = [r.reason or "unknown" for r in flagged]
        audit_log.log_action(
            db,
            action="mint_fraud_flagged",
            actor=actor,
            result="flagged",
            target_id=arrival_id,
            detail={"reasons": flag_reasons},
        )
        increment_counter("fraud_flags_total")
        _log.warning(
            "fraud flagged — mint blocked",
            extra={"arrival_id": arrival_id, "facility_id": facility_id, "reasons": flag_reasons},
        )
        return ServiceResult(
            success=False,
            error=f"Minting blocked: fraud flags raised — {flag_reasons}",
            status="flagged_for_review",
        )

    # --- Atomic mint (invariant #3) ---
    certificate = database.atomic_mint(
        db=db,
        arrival_id=arrival_id,
        quantity_kg=quantity_kg,
        waste_category=waste_category,
    )
    if certificate is None:
        # Race condition: another request minted first
        audit_log.log_action(
            db,
            action="mint_double_spend_blocked",
            actor=actor,
            result="rejected",
            target_id=arrival_id,
        )
        return ServiceResult(
            success=False,
            error="Double-spend blocked — arrival already minted by concurrent request",
            status="rejected",
        )

    # --- Update ledger hash chain (invariant #5) ---
    try:
        chain_hash = ledger.append_to_chain(db=db, cert_id=certificate["id"])
        certificate["ledger_hash_hex"] = chain_hash
    except Exception as exc:  # noqa: BLE001
        # Ledger failure must NOT silently pass; certificate is valid but chain needs repair
        audit_log.log_action(
            db,
            action="ledger_append_failed",
            actor="system",
            result="error",
            target_id=certificate["id"],
            detail={"error": str(exc)},
        )
        return ServiceResult(
            success=False,
            error="Ledger append failed. Certificate generated but chain is invalid.",
            data=None,
        )

    audit_log.log_action(
        db,
        action="cert_minted",
        actor=actor,
        result="success",
        target_id=certificate["id"],
        detail={"arrival_id": arrival_id, "quantity_kg": quantity_kg},
    )
    increment_counter("certificates_minted_total")
    _log.info(
        "certificate minted",
        extra={
            "cert_id": certificate["id"],
            "arrival_id": arrival_id,
            "facility_id": facility_id,
            "quantity_kg": quantity_kg,
        },
    )
    return ServiceResult(success=True, data=certificate, status="ok")


def verify_certificate(
    db: sqlite3.Connection,
    cert_id: str,
) -> ServiceResult:
    """
    Verify a certificate's Merkle proof and chain position.
    Returns proof data including whether the certificate is valid.
    """
    try:
        proof_data = ledger.get_certificate_proof(db=db, cert_id=cert_id)
        return ServiceResult(success=True, data=proof_data, status="ok")
    except Exception as exc:  # noqa: BLE001
        return ServiceResult(success=False, error=str(exc), status="error")


def get_facility_status(
    db: sqlite3.Connection,
    facility_id: str,
    period_start: Optional[str] = None,
    period_end: Optional[str] = None,
) -> ServiceResult:
    """
    Return summary status for a facility: arrival count, cert count, capacity usage.
    """
    facility = database.get_facility(db, facility_id)
    if facility is None:
        return ServiceResult(
            success=False, error=f"Facility '{facility_id}' not found", status="rejected"
        )
    now = datetime.now(timezone.utc).isoformat()
    if period_start is None:
        dt = datetime.now(timezone.utc)
        period_start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    if period_end is None:
        period_end = now

    arrivals = database.get_arrivals_for_facility(db, facility_id, period_start, period_end)
    certs = database.get_certificates_for_facility(db, facility_id, period_start, period_end)
    total_certified_kg = sum(c["quantity_kg"] for c in certs)
    return ServiceResult(
        success=True,
        data={
            "facility": facility,
            "period_start": period_start,
            "period_end": period_end,
            "arrival_count": len(arrivals),
            "certificate_count": len(certs),
            "total_certified_kg": total_certified_kg,
            "capacity_kg": facility["capacity_kg"],
            "capacity_utilisation_pct": (
                round(100.0 * total_certified_kg / facility["capacity_kg"], 2)
                if facility["capacity_kg"] > 0
                else 0.0
            ),
        },
        status="ok",
    )

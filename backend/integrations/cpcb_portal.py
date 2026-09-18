"""
VERITAS — CPCB portal integration abstraction (Phase 12).

This module abstracts the CPCB centralized portal. There is currently
NO live API integration — CPCB has not published a stable API as of
this writing. This module produces a well-defined export format
(JSON/CSV) matching the portal's manual-upload schema.

Honest status: export-only. Live integration pending CPCB API publication.
Document this explicitly in ARCHITECTURE.md. Never overstate this as a
live integration in the pitch.

Phase 12 enhancements:
- CPCB_EXPORT_VERSION = "1.0"
- generate_qr_code() with pure-Python segno / qrcode fallback
- export_audit_report() for regulator / SPCB audits
- qr_code_base64 embedded in JSON exports
- Invariant #14: Fail-closed error handling throughout (never propagate crashes)
"""
from __future__ import annotations

import base64
import csv
from datetime import datetime, timezone
import io
import json
from typing import Any

CPCB_EXPORT_VERSION: str = "1.0"


def generate_qr_code(
    cert_id: str,
    verify_url: str,
    fail_closed: bool = True,
) -> bytes:
    """
    Generate QR code PNG bytes encoding verify_url for cert_id.

    Uses segno if available (lightweight pure-Python), falls back to qrcode,
    or returns empty bytes (fail-closed) if no QR library is installed.
    If fail_closed is False and no QR library is available, raises ImportError.
    """
    try:
        payload = verify_url or (
            f"https://veritas.cpcb.gov.in/certificates/{cert_id}/verify"
            if cert_id
            else ""
        )
        if not payload:
            return b""

        # Try segno first (pure Python, lightweight, no Pillow requirement)
        try:
            import segno  # type: ignore

            buf = io.BytesIO()
            qr = segno.make(payload)
            qr.save(buf, kind="png")
            return buf.getvalue()
        except ImportError:
            pass

        # Fallback to qrcode (qrcode[pil] or pure qrcode)
        try:
            import qrcode  # type: ignore

            buf = io.BytesIO()
            img = qrcode.make(payload)
            img.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            if not fail_closed:
                raise ImportError(
                    "Neither 'segno' nor 'qrcode' is installed. "
                    "Install with `pip install segno` or `pip install qrcode[pil]`."
                )
            return b""

    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("CPCB Export failed")
        import logging
        logging.getLogger(__name__).warning("Exception in cpcb_portal: %s", exc)
        if not fail_closed:
            raise
        return b""


def _format_cert_record(c: dict[str, Any]) -> dict[str, Any]:
    """Format a single certificate record with QR base64 encoding."""
    cert_id = c.get("id") or c.get("certificate_id")
    if not cert_id:
        raise ValueError("Missing certificate ID")

    verify_url = (
        c.get("verify_url")
        or f"https://veritas.cpcb.gov.in/certificates/{cert_id}/verify"
    )
    qr_bytes = generate_qr_code(str(cert_id), str(verify_url))
    qr_b64 = base64.b64encode(qr_bytes).decode("ascii") if qr_bytes else ""

    try:
        qty = float(c.get("quantity_kg", 0.0))
    except (ValueError, TypeError):
        qty = 0.0

    return {
        "certificate_id": str(cert_id),
        "facility_id": str(c.get("facility_id", "")),
        "quantity_kg": qty,
        "waste_category": str(c.get("waste_category", "")),
        "minted_at": str(c.get("minted_at", "")),
        "arrival_id": str(c.get("arrival_id", "")),
        "chain_hash": str(c.get("ledger_hash_hex") or c.get("chain_hash", "")),
        "qr_code_base64": qr_b64,
    }


def export_certificates_json(certificates: list[dict[str, Any]]) -> str:
    """
    Export certificates in CPCB-compatible JSON format.
    (Manual-upload schema — verify against live CPCB portal before use.)

    Includes base64-encoded QR PNG in qr_code_base64 field.
    Fail-closed: returns error JSON on malformed input or exception.
    """
    try:
        if not isinstance(certificates, list):
            return json.dumps(
                {
                    "error": "Invalid certificates input: expected list",
                    "veritas_export_version": CPCB_EXPORT_VERSION,
                    "certificates": [],
                },
                indent=2,
            )

        records = []
        for c in certificates:
            if not isinstance(c, dict):
                return json.dumps(
                    {
                        "error": "Malformed certificate record: expected dict",
                        "veritas_export_version": CPCB_EXPORT_VERSION,
                        "certificates": [],
                    },
                    indent=2,
                )
            records.append(_format_cert_record(c))

        return json.dumps(
            {
                "veritas_export_version": CPCB_EXPORT_VERSION,
                "certificates": records,
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps(
            {
                "error": f"Export failed: {str(e)}",
                "veritas_export_version": CPCB_EXPORT_VERSION,
                "certificates": [],
            },
            indent=2,
        )


def export_certificates_csv(certificates: list[dict[str, Any]]) -> str:
    """
    Export certificates as CSV for manual CPCB portal upload.

    Fail-closed: returns header-only CSV on empty input, and catches exceptions.
    """
    fieldnames = [
        "certificate_id",
        "facility_id",
        "quantity_kg",
        "waste_category",
        "minted_at",
        "arrival_id",
        "chain_hash",
    ]
    try:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        if not isinstance(certificates, list):
            return output.getvalue()

        for c in certificates:
            if not isinstance(c, dict):
                return ""  # fail-closed on malformed record
            cert_id = c.get("id") or c.get("certificate_id")
            if not cert_id:
                return ""  # fail-closed on missing id

            try:
                qty = float(c.get("quantity_kg", 0.0))
            except (ValueError, TypeError):
                qty = 0.0

            writer.writerow(
                {
                    "certificate_id": str(cert_id),
                    "facility_id": str(c.get("facility_id", "")),
                    "quantity_kg": qty,
                    "waste_category": str(c.get("waste_category", "")),
                    "minted_at": str(c.get("minted_at", "")),
                    "arrival_id": str(c.get("arrival_id", "")),
                    "chain_hash": str(
                        c.get("ledger_hash_hex") or c.get("chain_hash", "")
                    ),
                }
            )
        return output.getvalue()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("CPCB Export failed")
        import logging
        logging.getLogger(__name__).warning("Exception in cpcb_portal: %s", exc)
        return ""


def export_audit_report(
    certificates: list[dict[str, Any]],
    facility_name: str,
    period_start: str,
    period_end: str,
) -> dict[str, Any]:
    """
    Generate a structured audit report for SPCB/CPCB regulatory inspection.

    Returns structured dict with metadata + records for complete audit compliance.
    Fail-closed: returns error dict on malformed input or unexpected exceptions.
    """
    def _error_response(msg: str) -> dict[str, Any]:
        return {
            "error": msg,
            "metadata": {
                "facility_name": str(facility_name) if facility_name else "",
                "period_start": str(period_start) if period_start else "",
                "period_end": str(period_end) if period_end else "",
                "period": f"{period_start} to {period_end}" if period_start and period_end else "",
                "export_version": CPCB_EXPORT_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_certificates": 0,
                "total_quantity_kg": 0.0,
            },
            "facility_name": str(facility_name) if facility_name else "",
            "period": {
                "start": str(period_start) if period_start else "",
                "end": str(period_end) if period_end else "",
            },
            "records": [],
        }

    try:
        if not isinstance(certificates, list):
            return _error_response("Invalid certificates input: expected list")

        records = []
        for c in certificates:
            if not isinstance(c, dict):
                return _error_response("Malformed certificate record: expected dict")
            records.append(_format_cert_record(c))

        total_kg = sum(r["quantity_kg"] for r in records)

        metadata = {
            "facility_name": str(facility_name),
            "period_start": str(period_start),
            "period_end": str(period_end),
            "period": f"{period_start} to {period_end}",
            "export_version": CPCB_EXPORT_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_certificates": len(records),
            "total_quantity_kg": round(total_kg, 2),
        }

        return {
            "metadata": metadata,
            "facility_name": str(facility_name),
            "period": {
                "start": str(period_start),
                "end": str(period_end),
            },
            "records": records,
        }
    except Exception as e:
        return _error_response(f"Audit report generation failed: {str(e)}")

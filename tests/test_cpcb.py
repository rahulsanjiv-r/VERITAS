"""
Tests for VERITAS backend/integrations/cpcb_portal.py — Phase 12.

Verifies CPCB centralized portal export schemas (JSON and CSV),
QR code generation (segno / qrcode pure Python), structured audit reports,
and Invariant #14 (fail-closed: errors flagged, never raw crashes).
"""
from __future__ import annotations

import base64
import csv
import io
import json
from unittest.mock import patch
import pytest

from backend.integrations.cpcb_portal import (
    CPCB_EXPORT_VERSION,
    export_audit_report,
    export_certificates_csv,
    export_certificates_json,
    generate_qr_code,
)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_json_export_structure():
    """Verify keys present, version correct, and record fields conform to schema."""
    certs = [
        {
            "id": "cert-cpcb-001",
            "facility_id": "fac-delhi-01",
            "quantity_kg": 500.0,
            "waste_category": "CAT-1",
            "minted_at": "2026-09-18T10:00:00Z",
            "arrival_id": "arr-001",
            "ledger_hash_hex": "abcd1234abcd1234",
        }
    ]
    raw = export_certificates_json(certs)
    data = json.loads(raw)

    assert "veritas_export_version" in data
    assert data["veritas_export_version"] == CPCB_EXPORT_VERSION
    assert data["veritas_export_version"] == "1.0"
    assert "certificates" in data
    assert len(data["certificates"]) == 1

    rec = data["certificates"][0]
    assert rec["certificate_id"] == "cert-cpcb-001"
    assert rec["facility_id"] == "fac-delhi-01"
    assert rec["quantity_kg"] == 500.0
    assert rec["waste_category"] == "CAT-1"
    assert rec["minted_at"] == "2026-09-18T10:00:00Z"
    assert rec["arrival_id"] == "arr-001"
    assert rec["chain_hash"] == "abcd1234abcd1234"
    assert "qr_code_base64" in rec


def test_json_export_empty():
    """Empty list returns valid JSON with correct version and empty certificates."""
    raw = export_certificates_json([])
    data = json.loads(raw)
    assert data["veritas_export_version"] == "1.0"
    assert data["certificates"] == []


def test_csv_export_has_header():
    """CSV output has correct fieldnames in header row."""
    csv_str = export_certificates_csv([])
    reader = csv.reader(io.StringIO(csv_str))
    header = next(reader)
    expected_fieldnames = [
        "certificate_id",
        "facility_id",
        "quantity_kg",
        "waste_category",
        "minted_at",
        "arrival_id",
        "chain_hash",
    ]
    assert header == expected_fieldnames


def test_csv_export_row_count():
    """N certs produce N+1 rows (1 header + N data rows)."""
    n = 5
    certs = [
        {
            "id": f"cert-{i}",
            "facility_id": f"fac-{i}",
            "quantity_kg": 100.0 * i,
            "waste_category": "CAT-1",
            "minted_at": "2026-09-18T10:00:00Z",
            "arrival_id": f"arr-{i}",
            "ledger_hash_hex": f"hash-{i}",
        }
        for i in range(n)
    ]
    csv_str = export_certificates_csv(certs)
    rows = list(csv.reader(io.StringIO(csv_str)))
    assert len(rows) == n + 1


def test_csv_export_empty():
    """Empty cert list produces header-only CSV."""
    csv_str = export_certificates_csv([])
    rows = list(csv.reader(io.StringIO(csv_str)))
    assert len(rows) == 1
    assert rows[0][0] == "certificate_id"


def test_audit_report_structure():
    """Audit report contains metadata, facility_name, period, and records."""
    certs = [
        {
            "id": "cert-audit-01",
            "facility_id": "fac-01",
            "quantity_kg": 1200.0,
            "waste_category": "CAT-2",
            "minted_at": "2026-09-10T12:00:00Z",
            "arrival_id": "arr-01",
            "ledger_hash_hex": "hash01",
        },
        {
            "id": "cert-audit-02",
            "facility_id": "fac-01",
            "quantity_kg": 800.0,
            "waste_category": "CAT-2",
            "minted_at": "2026-09-12T14:00:00Z",
            "arrival_id": "arr-02",
            "ledger_hash_hex": "hash02",
        },
    ]
    report = export_audit_report(
        certificates=certs,
        facility_name="Alpha Recycling Plant",
        period_start="2026-09-01",
        period_end="2026-09-30",
    )
    assert isinstance(report, dict)
    assert "metadata" in report
    assert "facility_name" in report
    assert "period" in report
    assert "records" in report

    assert report["facility_name"] == "Alpha Recycling Plant"
    assert report["period"]["start"] == "2026-09-01"
    assert report["period"]["end"] == "2026-09-30"

    meta = report["metadata"]
    assert meta["facility_name"] == "Alpha Recycling Plant"
    assert meta["period_start"] == "2026-09-01"
    assert meta["period_end"] == "2026-09-30"
    assert meta["export_version"] == "1.0"
    assert meta["total_certificates"] == 2
    assert meta["total_quantity_kg"] == 2000.0
    assert "generated_at" in meta

    assert len(report["records"]) == 2
    assert report["records"][0]["certificate_id"] == "cert-audit-01"
    assert report["records"][0]["quantity_kg"] == 1200.0
    assert "qr_code_base64" in report["records"][0]


def test_qr_code_returns_bytes():
    """generate_qr_code returns bytes, and non-empty if QR library is available."""
    qr = generate_qr_code(
        cert_id="cert-qr-001",
        verify_url="https://veritas.cpcb.gov.in/certificates/cert-qr-001/verify",
    )
    assert isinstance(qr, bytes)
    assert len(qr) > 0
    # Must be valid PNG magic bytes
    assert qr.startswith(b"\x89PNG\r\n\x1a\n")


def test_export_fail_closed():
    """
    Invariant #14: Fail-closed. Passing malformed cert dict doesn't crash,
    returns error dict or empty dict/string rather than raising raw exceptions.
    """
    malformed_certs = [{"invalid_key": "no_id_present"}]

    # 1. Audit report returns error dict, never crashes
    report = export_audit_report(
        certificates=malformed_certs,
        facility_name="Bad Facility",
        period_start="2026-01-01",
        period_end="2026-01-31",
    )
    assert isinstance(report, dict)
    assert "error" in report or report == {} or report.get("records") == []

    # 2. JSON export returns valid JSON with error, never crashes
    json_res = export_certificates_json(malformed_certs)
    assert isinstance(json_res, str)
    data = json.loads(json_res)
    assert isinstance(data, dict)
    assert "error" in data or data == {} or data.get("certificates") == []

    # 3. CSV export doesn't crash on malformed cert
    csv_res = export_certificates_csv(malformed_certs)
    assert isinstance(csv_res, str)

    # 4. Non-list / bad input types fail-closed without crashing
    bad_type_report = export_audit_report(
        certificates=None,  # type: ignore
        facility_name="Test",
        period_start="2026-01-01",
        period_end="2026-01-31",
    )
    assert isinstance(bad_type_report, dict)
    assert "error" in bad_type_report or bad_type_report == {}

    bad_json = export_certificates_json("not-a-list")  # type: ignore
    bad_data = json.loads(bad_json)
    assert "error" in bad_data or bad_data == {}


def test_json_includes_qr_base64_key():
    """JSON export dict has 'qr_code_base64' field in each certificate record."""
    certs = [
        {
            "id": "cert-qr-verify-1",
            "facility_id": "fac-01",
            "quantity_kg": 450.0,
            "waste_category": "CAT-1",
            "minted_at": "2026-09-18T10:00:00Z",
            "arrival_id": "arr-1",
            "ledger_hash_hex": "feedface01",
        }
    ]
    json_out = export_certificates_json(certs)
    data = json.loads(json_out)
    assert "certificates" in data
    assert len(data["certificates"]) == 1
    record = data["certificates"][0]
    assert "qr_code_base64" in record
    assert isinstance(record["qr_code_base64"], str)
    assert len(record["qr_code_base64"]) > 0

    # Verify that the base64 string decodes to valid PNG bytes
    decoded = base64.b64decode(record["qr_code_base64"])
    assert decoded.startswith(b"\x89PNG\r\n\x1a\n")


def test_cpcb_export_version_constant():
    """Module-level CPCB_EXPORT_VERSION constant is defined and set to '1.0'."""
    assert CPCB_EXPORT_VERSION == "1.0"


def test_generate_qr_code_empty_payload():
    """Empty cert_id and verify_url returns empty bytes without crashing."""
    result = generate_qr_code(cert_id="", verify_url="")
    assert result == b""


def test_audit_report_empty_certs():
    """Audit report with empty certificates list returns structured report with 0 totals."""
    report = export_audit_report(
        certificates=[],
        facility_name="Clean Recycling Plant",
        period_start="2026-09-01",
        period_end="2026-09-30",
    )
    assert isinstance(report, dict)
    assert report["records"] == []
    assert report["metadata"]["total_certificates"] == 0
    assert report["metadata"]["total_quantity_kg"] == 0.0
    assert report["facility_name"] == "Clean Recycling Plant"


def test_qr_code_fallback_and_import_error():
    """
    Test missing QR library behavior:
    - Default fail_closed=True returns b""
    - fail_closed=False raises helpful ImportError
    """
    import builtins

    orig_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name in ("segno", "qrcode"):
            raise ImportError(f"No module named {name}")
        return orig_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        # Fail-closed returns b""
        res = generate_qr_code("cert-1", "https://example.com/verify")
        assert res == b""

        # Explicit fail_closed=False raises ImportError
        with pytest.raises(ImportError) as exc_info:
            generate_qr_code(
                "cert-1", "https://example.com/verify", fail_closed=False
            )
        assert "segno" in str(exc_info.value) or "qrcode" in str(exc_info.value)

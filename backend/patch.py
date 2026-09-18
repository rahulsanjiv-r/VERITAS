import sys
with open("integrations/cpcb_portal.py", "r") as f:
    text = f.read()

import re

new_func = """def export_audit_report(
    certificates: list[dict[str, Any]],
    facility_name: str,
    period_start: str,
    period_end: str,
) -> dict[str, Any]:
    \"\"\"
    Generate a structured audit report for SPCB/CPCB regulatory inspection.

    Returns structured dict with metadata + records for complete audit compliance.
    Fail-closed: returns error dict on malformed input or unexpected exceptions.
    \"\"\"
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
"""

import ast

class Rewrite(ast.NodeTransformer):
    pass

# We will just regex replace the function
pattern = re.compile(r'def export_audit_report\(.*?\)\s*->\s*dict\[str,\s*Any\]:.*?return \{.*?\}\n', re.DOTALL)
text = re.sub(r'def export_audit_report\(.*?return \{.*?\}', new_func, text, flags=re.DOTALL)

with open("integrations/cpcb_portal.py", "w") as f:
    f.write(text)

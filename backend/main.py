"""
VERITAS — FastAPI route handlers (main.py).

This file is routing ONLY. Every handler is a thin wrapper around service.py.
No business logic lives here. If you're writing more than 10 lines in a handler,
the logic belongs in service.py instead.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request

from backend import cv_checker, database, image_store, service
from backend.auth import get_current_facility_id, require_role
from backend.integrations import cpcb_portal
from backend.observability import get_metrics, increment_counter
from backend.models import (
    ArrivalResponse,
    ArrivalSubmit,
    CertificateResponse,
    FacilityCreate,
    FacilityResponse,
    HealthResponse,
    LedgerVerifyResponse,
    MintRequest,
    MintResponse,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VERITAS",
    description=(
        "Verified EPR Recycling with Integrity Tamper-proof Arrival Signatures — "
        "cryptographic anti-fraud backend for EPR certificate minting."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _metrics_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Track requests_total per method+route for the /metrics endpoint."""
    response = await call_next(request)
    route = request.scope.get("path", request.url.path)
    label = f"{request.method} {route}"
    increment_counter("requests_total", labels=label)
    return response

DB_PATH = Path(os.getenv("VERITAS_DB_PATH", "veritas.db"))

# Dashboard static files — served at /dashboard/*
_DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
if _DASHBOARD_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_DASHBOARD_DIR)), name="dashboard")

# Mobile PWA — served at /mobile/*
app.mount("/mobile", StaticFiles(directory="mobile", html=True), name="mobile")


def _get_db_path() -> Path:
    return Path(os.getenv("VERITAS_DB_PATH", str(DB_PATH)))


def get_db() -> Any:
    """Get a DB connection. Used directly in handlers for simplicity in Phase 0."""
    return database.get_connection(_get_db_path())


@app.on_event("startup")
def startup() -> None:
    """Initialize DB on startup."""
    database.init_db(_get_db_path())


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    """Redirect / to the dashboard."""
    index_path = _DASHBOARD_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return FileResponse(str(index_path))


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health_check() -> HealthResponse:
    """Health check — confirms the service is up."""
    return HealthResponse()


@app.get("/metrics", tags=["system"])
def metrics_endpoint() -> Any:
    """Return in-memory metrics counters as JSON.  No auth required."""
    return JSONResponse(content=get_metrics())


# ---------------------------------------------------------------------------
# Facilities
# ---------------------------------------------------------------------------


@app.post(
    "/facilities",
    response_model=FacilityResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["facilities"],
)
def register_facility(
    body: FacilityCreate,
    token_data: dict = Depends(require_role("veritas_admin")),
) -> Any:
    """Register a new recycling facility with its gate device public key."""
    db = get_db()
    result = service.register_facility(
        db=db,
        name=body.name,
        capacity_kg=body.capacity_kg,
        waste_category=body.waste_category.value,
        pubkey_hex=body.pubkey_hex,
    )
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return result.data


@app.get("/facilities/{facility_id}", response_model=FacilityResponse, tags=["facilities"])
def get_facility(
    facility_id: str,
    token_data: dict = Depends(
        require_role("facility_operator", "veritas_admin", "regulator_auditor")
    ),
) -> Any:
    """Get facility details."""
    db = get_db()
    facility = database.get_facility(db, facility_id)
    if facility is None:
        raise HTTPException(status_code=404, detail="Facility not found")
    return facility


@app.get("/facilities/{facility_id}/status", tags=["facilities"])
def facility_status(
    facility_id: str,
    token_data: dict = Depends(
        require_role("facility_operator", "veritas_admin", "regulator_auditor")
    ),
) -> Any:
    """Get facility status: arrival count, certificate count, capacity utilisation."""
    db = get_db()
    result = service.get_facility_status(db=db, facility_id=facility_id)
    if not result.success:
        raise HTTPException(status_code=404 if "not found" in (result.error or "") else 500,
                            detail=result.error)
    return result.data


# ---------------------------------------------------------------------------
# Arrivals
# ---------------------------------------------------------------------------


@app.post(
    "/arrivals",
    response_model=ArrivalResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["arrivals"],
)
def submit_arrival(
    body: ArrivalSubmit,
    token_data: dict = Depends(require_role("facility_operator", "veritas_admin")),
) -> Any:
    """
    Submit a signed arrival record from a gate pod.

    The backend recomputes the canonical hash and verifies the signature.
    Returns 201 on success, 400 on signature/hash failure, 422 on invalid input.
    """
    db = get_db()
    result = service.submit_arrival(
        db=db,
        facility_id=body.facility_id,
        device_id=body.device_id,
        weight_kg=body.weight_kg,
        photo_hash_hex=body.photo_hash_hex,
        timestamp_iso=body.timestamp_iso,
        record_hash_hex=body.record_hash_hex,
        signature_hex=body.signature_hex,
    )
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return result.data


@app.get("/arrivals", tags=["arrivals"])
def list_arrivals(
    facility_id: str = "",
    period_start: str = "",
    period_end: str = "",
    token_data: dict = Depends(
        require_role("facility_operator", "veritas_admin", "regulator_auditor")
    ),
) -> Any:
    """List arrivals for a facility."""
    if token_data.get("role") == "facility_operator":
        facility_id = get_current_facility_id(token_data) or ""
    db = get_db()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    arrivals = database.get_arrivals_for_facility(
        db, facility_id, period_start or "2000-01-01T00:00:00+00:00", period_end or now
    )
    return {"arrivals": arrivals, "count": len(arrivals)}


# ---------------------------------------------------------------------------
# Certificates / Mint
# ---------------------------------------------------------------------------


@app.post("/certificates/mint", response_model=MintResponse, tags=["certificates"])
def mint_certificate(
    body: MintRequest,
    token_data: dict = Depends(require_role("facility_operator", "veritas_admin")),
) -> Any:
    """
    Mint an EPR certificate from a verified arrival record.

    Returns 'minted', 'flagged_for_review', or 'rejected' depending on
    fraud checks and the atomic-mint result. Never raises 5xx for a rejected mint.
    """
    db = get_db()
    result = service.mint_certificate(
        db=db,
        arrival_id=body.arrival_id,
        quantity_kg=body.quantity_kg,
        waste_category=body.waste_category.value,
    )
    if result.status == "error":
        raise HTTPException(status_code=500, detail=result.error)

    return {
        "status": result.status if result.status != "ok" else "minted",
        "certificate": result.data if result.success else None,
        "reason": result.error,
    }


@app.get(
    "/certificates/{cert_id}/verify",
    response_model=LedgerVerifyResponse,
    tags=["certificates"],
)
def verify_certificate(
    cert_id: str,
    token_data: dict = Depends(
        require_role("facility_operator", "veritas_admin", "regulator_auditor")
    ),
) -> Any:
    """Verify a certificate's Merkle proof and hash chain position."""
    db = get_db()
    result = service.verify_certificate(db=db, cert_id=cert_id)
    if not result.success:
        raise HTTPException(status_code=404, detail=result.error)
    return result.data


@app.get("/certificates", tags=["certificates"])
def list_certificates(
    facility_id: str = "",
    period_start: str = "",
    period_end: str = "",
    token_data: dict = Depends(
        require_role("facility_operator", "veritas_admin", "regulator_auditor")
    ),
) -> Any:
    """List certificates minted for a facility in the given period."""
    if token_data.get("role") == "facility_operator":
        facility_id = get_current_facility_id(token_data) or ""
    from datetime import datetime, timezone
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    certs = database.get_certificates_for_facility(
        db, facility_id, period_start or "2000-01-01T00:00:00+00:00", period_end or now
    )
    return {"certificates": certs, "count": len(certs)}


# ---------------------------------------------------------------------------
# CPCB Audit Export (Task A)
# ---------------------------------------------------------------------------


@app.get("/export/audit", tags=["export"])
def export_audit(
    facility_id: str = "",
    period_start: str = "",
    period_end: str = "",
    format: str = "json",
    token_data: dict = Depends(require_role("regulator_auditor", "veritas_admin")),
) -> Any:
    """Export an audit report for a facility and period.

    Requires role: ``regulator_auditor`` or ``veritas_admin``.

    Query parameters:
        facility_id: UUID of the facility to audit.
        period_start: ISO 8601 lower bound on minted_at (default: epoch).
        period_end: ISO 8601 upper bound on minted_at (default: now).
        format: ``json`` (default) or ``csv``.

    Returns:
        JSON audit report or CSV attachment.
    """
    from datetime import datetime, timezone

    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    certs = database.get_certificates_for_facility(
        db,
        facility_id,
        period_start or "2000-01-01T00:00:00+00:00",
        period_end or now,
    )

    if format == "csv":
        csv_content = cpcb_portal.export_certificates_csv(certs)
        return PlainTextResponse(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=veritas_audit.csv"},
        )

    # Default: JSON
    report = cpcb_portal.export_audit_report(
        certificates=certs,
        facility_name=facility_id,
        period_start=period_start or "2000-01-01T00:00:00+00:00",
        period_end=period_end or now,
    )
    return JSONResponse(content=report)


# ---------------------------------------------------------------------------
# Arrival Photo Upload (Task B)
# ---------------------------------------------------------------------------


@app.post("/arrivals/{arrival_id}/photo", tags=["arrivals"])
async def upload_arrival_photo(
    arrival_id: str,
    request: Request,
    token_data: dict = Depends(require_role("facility_operator", "veritas_admin")),
) -> Any:
    """Upload a raw JPEG photo for an arrival record.

    Requires role: ``facility_operator`` or ``veritas_admin``.

    Invariant #9 — tenant isolation: if the caller is a ``facility_operator``,
    the arrival's ``facility_id`` must match the token's ``facility_id``.

    Invariant #4 — advisory CV check: the computer-vision result is recorded
    as a fraud flag when it signals a mismatch, but it never blocks the save.

    Body:
        Raw JPEG bytes (``Content-Type: application/octet-stream``).

    Returns:
        ``{"arrival_id": ..., "photo_sha256": ..., "path": ...,
           "cv_matched": ..., "cv_confidence": ..., "cv_reason": ...,
           "cv_detected_category": ...}``
    """
    db = get_db()
    arrival = database.get_arrival(db, arrival_id)
    if arrival is None:
        raise HTTPException(status_code=404, detail=f"Arrival '{arrival_id}' not found")

    # Invariant #9 — tenant isolation
    if token_data.get("role") == "facility_operator":
        caller_facility_id = get_current_facility_id(token_data) or ""
        if arrival["facility_id"] != caller_facility_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: arrival belongs to a different facility",
            )

    image_bytes = await request.body()
    sha256_hex = image_store.compute_sha256(image_bytes)
    path = image_store.save_photo(arrival_id, image_bytes)

    # -----------------------------------------------------------------------
    # CV check (Invariant #4 — advisory only; never blocks the save)
    # declared_category lives on the facility record, not the arrival row.
    # -----------------------------------------------------------------------
    facility = database.get_facility(db, arrival["facility_id"])
    declared_category: str = (facility or {}).get("waste_category", "") or ""

    cv_result = cv_checker.verify_photo(
        image_bytes=image_bytes,
        photo_hash_hex=sha256_hex,
        declared_category=declared_category,
    )

    # Determine which fraud flags (if any) the CV result warrants
    cv_flags: list[str] = []
    if not cv_result.matched:
        cv_flags.append("cv_hash_mismatch")
    elif cv_result.reason.startswith("category_mismatch"):
        cv_flags.append("cv_category_mismatch")

    if cv_flags:
        database.update_arrival_fraud_flags(db, arrival_id, cv_flags)
        db.commit()

    return {
        "arrival_id": arrival_id,
        "photo_sha256": sha256_hex,
        "path": path,
        "cv_matched": cv_result.matched,
        "cv_confidence": cv_result.confidence,
        "cv_detected_category": cv_result.detected_category,
        "cv_reason": cv_result.reason,
    }


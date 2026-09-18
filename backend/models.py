"""
VERITAS — Pydantic request/response models.

No business logic here. No database access here.
All field validation lives here so service.py and route handlers stay clean.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class WasteCategory(str, Enum):
    """Supported waste categories — configurable for EPR scope expansion."""

    PLASTIC = "plastic"
    E_WASTE = "e_waste"
    NON_FERROUS_METAL = "non_ferrous_metal"
    CONSTRUCTION_DEMOLITION = "construction_demolition"


# ---------------------------------------------------------------------------
# Facility
# ---------------------------------------------------------------------------


class FacilityCreate(BaseModel):
    """Request body to register a new recycling facility."""

    name: str = Field(..., min_length=2, max_length=200)
    capacity_kg: float = Field(..., gt=0, description="Registered max kg per period")
    waste_category: WasteCategory
    pubkey_hex: str = Field(
        ..., min_length=64, max_length=64, description="Device Ed25519 public key (32 bytes hex)"
    )

    @field_validator("pubkey_hex")
    @classmethod
    def pubkey_must_be_hex(cls, v: str) -> str:
        try:
            bytes.fromhex(v)
        except ValueError as e:
            raise ValueError("pubkey_hex must be valid hexadecimal") from e
        return v.lower()


class FacilityResponse(BaseModel):
    """Response after registering a facility."""

    id: str
    name: str
    capacity_kg: float
    waste_category: WasteCategory
    created_at: datetime


# ---------------------------------------------------------------------------
# Arrival
# ---------------------------------------------------------------------------


class ArrivalSubmit(BaseModel):
    """
    Signed arrival record posted by a gate pod.

    The backend will independently recompute record_hash_hex from the other
    fields (invariant #2) before verifying the signature (invariant #1).
    Never trust the submitted hash directly.
    """

    facility_id: str
    device_id: str = Field(..., description="Unique identifier for the gate pod")
    weight_kg: float = Field(..., gt=0, lt=1_000_000)
    photo_hash_hex: str = Field(..., min_length=64, max_length=64)
    timestamp_iso: str = Field(..., description="ISO 8601 UTC timestamp from pod clock")
    record_hash_hex: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="Canonical hash of (weight_kg, facility_id, timestamp_iso, photo_hash_hex, device_id) — server will recompute and verify",
    )
    signature_hex: str = Field(..., min_length=128, max_length=128)
    plate_number: Optional[str] = Field(None, max_length=20)
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    lat_deg: Optional[float] = None
    lon_deg: Optional[float] = None

    @field_validator("photo_hash_hex", "record_hash_hex")
    @classmethod
    def must_be_hex_32(cls, v: str) -> str:
        try:
            b = bytes.fromhex(v)
        except ValueError as e:
            raise ValueError("must be valid hexadecimal") from e
        if len(b) != 32:
            raise ValueError("must be exactly 32 bytes (64 hex chars)")
        return v.lower()

    @field_validator("signature_hex")
    @classmethod
    def must_be_hex_64(cls, v: str) -> str:
        try:
            b = bytes.fromhex(v)
        except ValueError as e:
            raise ValueError("must be valid hexadecimal") from e
        if len(b) != 64:
            raise ValueError("Ed25519 signature must be 64 bytes (128 hex chars)")
        return v.lower()


class ArrivalResponse(BaseModel):
    """Response after a successful arrival submission."""

    id: str
    facility_id: str
    weight_kg: float
    submitted_at: datetime
    fraud_flags: list[str]
    lat_deg: Optional[float] = None
    lon_deg: Optional[float] = None


# ---------------------------------------------------------------------------
# Certificate / Mint
# ---------------------------------------------------------------------------


class MintRequest(BaseModel):
    """Request to mint an EPR certificate from a verified arrival."""

    arrival_id: str
    quantity_kg: float = Field(..., gt=0)
    waste_category: WasteCategory


class CertificateResponse(BaseModel):
    """Minted EPR certificate."""

    id: str
    arrival_id: str
    facility_id: str
    quantity_kg: float
    waste_category: WasteCategory
    ledger_hash_hex: str
    minted_at: datetime


class MintResponse(BaseModel):
    """Response from a mint attempt — may be success, flagged, or rejected."""

    status: str  # "minted" | "flagged_for_review" | "rejected"
    certificate: Optional[CertificateResponse] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Ledger / Verification
# ---------------------------------------------------------------------------


class LedgerVerifyResponse(BaseModel):
    """Result of verifying a certificate's Merkle proof."""

    certificate_id: str
    valid: bool
    merkle_root: Optional[str] = None
    detail: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    service: str = "veritas"
    version: str = "0.1.0"

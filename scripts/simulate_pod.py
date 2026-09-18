"""
VERITAS — Gate pod simulator (no hardware required).

Signs and posts three types of arrivals to a running VERITAS backend:
  1. A legitimate arrival → should mint successfully
  2. A forged-signature arrival → should be rejected
  3. An over-capacity arrival → should be flagged for review

Usage:
    python scripts/simulate_pod.py [--url http://localhost:8000]

Requires the backend to be running. Requires PyNaCl.

CRYPTO: Option B (software Ed25519). This simulator uses the same
canonical_hash() and sign_payload() functions as the backend test suite,
proving the cross-language round-trip in the Python domain. For real
firmware signing round-trip, see ARCHITECTURE.md Phase 6 notes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

# Add project root to path so we can import from backend
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.crypto import canonical_hash, generate_keypair, sign_payload  # noqa: E402


def _get_auth_headers(args: argparse.Namespace) -> dict:  # type: ignore[type-arg]
    """Return Authorization header if a token or secret is available.

    Priority:
      1. --token <jwt>  : use as-is
      2. --secret <s>   : auto-generate a veritas_admin token
      3. VERITAS_JWT_SECRET env var : same as --secret
      4. Nothing provided : return {} (works with unauthenticated server)
    """
    token = getattr(args, "token", None)
    if token:
        return {"Authorization": f"Bearer {token}"}

    secret = getattr(args, "secret", None) or os.environ.get("VERITAS_JWT_SECRET", "")
    if secret:
        try:
            from backend.auth import create_token  # noqa: E402
            token = create_token(role="veritas_admin", facility_id=None, secret=secret)
            return {"Authorization": f"Bearer {token}"}
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] Could not auto-generate token: {exc}. Running without auth.")
    return {}


def make_photo_hash(seed: str) -> str:
    """Fake a photo hash for simulation purposes."""
    return hashlib.sha256(seed.encode()).hexdigest()


def submit_arrival(
    client: httpx.Client,
    base_url: str,
    facility_id: str,
    privkey_hex: str,
    weight_kg: float,
    device_id: str,
    timestamp_iso: str | None = None,
    description: str = "",
) -> dict:
    """Build, sign, and POST an arrival record."""
    ts = timestamp_iso or datetime.now(timezone.utc).isoformat()
    photo_hash_hex = make_photo_hash(f"{device_id}:{ts}:{weight_kg}")

    record_hash = canonical_hash(
        weight_kg=weight_kg,
        facility_id=facility_id,
        timestamp_iso=ts,
        photo_hash_hex=photo_hash_hex,
        device_id=device_id,
    )
    sig_hex = sign_payload(privkey_hex=privkey_hex, message_bytes=record_hash)

    payload = {
        "facility_id": facility_id,
        "device_id": device_id,
        "weight_kg": weight_kg,
        "photo_hash_hex": photo_hash_hex,
        "timestamp_iso": ts,
        "record_hash_hex": record_hash.hex(),
        "signature_hex": sig_hex,
    }

    print(f"\n{'='*60}")
    print(f"[SIM] {description}")
    print(f"  weight_kg={weight_kg}, device_id={device_id}")
    resp = client.post(f"{base_url}/arrivals", json=payload)
    print(f"  → HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json() if resp.status_code < 500 else {}


def mint_certificate(
    client: httpx.Client,
    base_url: str,
    arrival_id: str,
    quantity_kg: float,
    waste_category: str = "plastic",
) -> dict:
    """Attempt to mint a certificate from an arrival."""
    payload = {
        "arrival_id": arrival_id,
        "quantity_kg": quantity_kg,
        "waste_category": waste_category,
    }
    resp = client.post(f"{base_url}/certificates/mint", json=payload)
    print(f"  MINT → HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json() if resp.status_code < 500 else {}


def main() -> None:
    parser = argparse.ArgumentParser(description="VERITAS gate pod simulator")
    parser.add_argument("--url", default="http://localhost:8000", help="Backend base URL")
    parser.add_argument(
        "--token", default=None,
        help="Bearer JWT token for authenticated endpoints (veritas_admin role recommended)"
    )
    parser.add_argument(
        "--secret", default=None,
        help="JWT secret to auto-generate a veritas_admin token. "
             "Falls back to VERITAS_JWT_SECRET env var. Omit for unauthenticated servers."
    )
    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    auth_headers = _get_auth_headers(args)
    if auth_headers:
        print("[AUTH] Using Bearer token for all requests.")
    else:
        print("[AUTH] No token provided — requests sent without Authorization header.")

    client = httpx.Client(timeout=10.0, headers=auth_headers)

    # --- Generate device keypair (in real use, key lives on device) ---
    pubkey_hex, privkey_hex = generate_keypair()
    _, attacker_privkey = generate_keypair()

    print(f"\n{'='*60}")
    print("VERITAS Pod Simulator")
    print(f"Backend: {base_url}")
    print(f"Device pubkey: {pubkey_hex[:16]}...")

    # --- Register facility ---
    print(f"\n{'='*60}")
    print("[SIM] Registering facility...")
    resp = client.post(
        f"{base_url}/facilities",
        json={
            "name": "Sim Recycler Facility",
            "capacity_kg": 1000.0,
            "waste_category": "plastic",
            "pubkey_hex": pubkey_hex,
        },
    )
    print(f"  → HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code != 201:
        print("[SIM ERROR] Could not register facility. Is the backend running?")
        sys.exit(1)
    facility = resp.json()
    facility_id = facility["id"]
    print(f"  Facility ID: {facility_id}")

    # -----------------------------------------------------------------------
    # Demo 1: Legitimate arrival → should mint
    # -----------------------------------------------------------------------
    arrival1 = submit_arrival(
        client, base_url, facility_id, privkey_hex,
        weight_kg=300.0, device_id="SIM-POD-001",
        description="Demo 1: Legitimate arrival (300 kg)",
    )
    if "id" in arrival1:
        mint_certificate(client, base_url, arrival1["id"], 300.0)

    # -----------------------------------------------------------------------
    # Demo 2: Forged signature → should be rejected
    # -----------------------------------------------------------------------
    ts = datetime.now(timezone.utc).isoformat()
    photo_hash_hex = make_photo_hash("forged:attempt")
    record_hash = canonical_hash(500.0, facility_id, ts, photo_hash_hex, "SIM-POD-001")
    bad_sig = sign_payload(attacker_privkey, record_hash)  # wrong key!

    print(f"\n{'='*60}")
    print("[SIM] Demo 2: Forged signature (wrong key)")
    forged_payload = {
        "facility_id": facility_id,
        "device_id": "SIM-POD-001",
        "weight_kg": 500.0,
        "photo_hash_hex": photo_hash_hex,
        "timestamp_iso": ts,
        "record_hash_hex": record_hash.hex(),
        "signature_hex": bad_sig,
    }
    resp = client.post(f"{base_url}/arrivals", json=forged_payload)
    print(f"  → HTTP {resp.status_code}: {resp.text[:200]}")
    assert resp.status_code == 400, "Expected 400 for forged signature"
    print("  ✓ Forged signature correctly rejected")

    # -----------------------------------------------------------------------
    # Demo 3: Over-capacity → should be flagged for review
    # -----------------------------------------------------------------------
    # Facility has 1000 kg capacity. We already minted 300 kg. Now claim 800 kg more.
    arrival3 = submit_arrival(
        client, base_url, facility_id, privkey_hex,
        weight_kg=800.0, device_id="SIM-POD-002",
        description="Demo 3: Over-capacity arrival (800 kg — would exceed 1000 kg cap)",
    )
    if "id" in arrival3:
        mint_result = mint_certificate(client, base_url, arrival3["id"], 800.0)
        status = mint_result.get("status", "unknown")
        if status == "flagged_for_review":
            print("  ✓ Over-capacity correctly flagged for review")
        elif status == "minted":
            print("  ✗ OVER-CAPACITY WAS MINTED — fraud check did not fire!")
        else:
            print(f"  Status: {status}")

    print(f"\n{'='*60}")
    print("[SIM] Simulation complete. Check the dashboard at http://localhost:8000/docs")
    client.close()


if __name__ == "__main__":
    main()

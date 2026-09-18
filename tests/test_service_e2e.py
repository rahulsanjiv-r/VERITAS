"""
VERITAS — Phase 5 end-to-end test (test_service_e2e.py).

Tests the full pipeline: register → arrive → mint → double-spend rejected →
forged signature rejected → capacity flag trips → Merkle proof verifies.

Uses a real (temp-file) SQLite DB — no mocking of the core path.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend import crypto, database, service


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Temporary SQLite database path, initialized fresh for each test."""
    p = tmp_path / "veritas_e2e.db"
    database.init_db(p)
    return p


@pytest.fixture
def db(db_path: Path):  # type: ignore[no-untyped-def]
    """Open DB connection for the test."""
    conn = database.get_connection(db_path)
    yield conn
    conn.close()


@pytest.fixture
def keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair for each test."""
    return crypto.generate_keypair()


@pytest.fixture
def facility(db, keypair: tuple[str, str]):  # type: ignore[no-untyped-def]
    """Register a test facility with capacity 1000 kg."""
    pubkey_hex, _ = keypair
    result = service.register_facility(
        db=db,
        name="Test Recycler Alpha",
        capacity_kg=1000.0,
        waste_category="plastic",
        pubkey_hex=pubkey_hex,
    )
    assert result.success
    return result.data


def _make_arrival(
    db,
    facility: dict,
    keypair: tuple[str, str],
    weight_kg: float = 100.0,
    timestamp_iso: str | None = None,
) -> dict:
    """Helper: submit a valid signed arrival and return the result data."""
    pubkey_hex, privkey_hex = keypair
    ts = timestamp_iso or datetime.now(timezone.utc).isoformat()
    photo_hash = b"\xab" * 32
    photo_hash_hex = photo_hash.hex()
    device_id = "device-test-001"

    record_hash = crypto.canonical_hash(
        weight_kg=weight_kg,
        facility_id=facility["id"],
        timestamp_iso=ts,
        photo_hash_hex=photo_hash_hex,
        device_id=device_id,
    )
    sig_hex = crypto.sign_payload(privkey_hex=privkey_hex, message_bytes=record_hash)

    result = service.submit_arrival(
        db=db,
        facility_id=facility["id"],
        device_id=device_id,
        weight_kg=weight_kg,
        photo_hash_hex=photo_hash_hex,
        timestamp_iso=ts,
        record_hash_hex=record_hash.hex(),
        signature_hex=sig_hex,
    )
    return result


# ---------------------------------------------------------------------------
# E2E tests
# ---------------------------------------------------------------------------


class TestRegisterToMint:
    """Core pipeline: register → arrive → mint."""

    def test_register_facility_success(self, db, keypair: tuple[str, str]) -> None:
        """Registering a facility returns a facility with an ID."""
        pubkey_hex, _ = keypair
        result = service.register_facility(db, "Facility A", 500.0, "plastic", pubkey_hex)
        assert result.success
        assert result.data is not None
        assert "id" in result.data
        assert result.data["name"] == "Facility A"

    def test_submit_valid_arrival(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """A properly signed arrival is accepted."""
        result = _make_arrival(db, facility, keypair)
        assert result.success, f"Expected success, got: {result.error}"
        assert result.data is not None
        assert result.data["weight_kg"] == 100.0

    def test_mint_certificate(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """After a valid arrival, minting succeeds and returns a certificate."""
        arrival_result = _make_arrival(db, facility, keypair)
        assert arrival_result.success
        arrival_id = arrival_result.data["id"]

        mint_result = service.mint_certificate(
            db=db, arrival_id=arrival_id, quantity_kg=100.0, waste_category="plastic"
        )
        assert mint_result.success, f"Mint failed: {mint_result.error}"
        assert mint_result.data is not None
        assert mint_result.data["arrival_id"] == arrival_id


class TestDoublespendRejection:
    """Invariant #3: double-spend must always be rejected."""

    def test_double_spend_rejected(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """Second mint on the same arrival must be rejected."""
        arrival = _make_arrival(db, facility, keypair)
        assert arrival.success
        arrival_id = arrival.data["id"]

        first = service.mint_certificate(db, arrival_id, 100.0, "plastic")
        assert first.success

        second = service.mint_certificate(db, arrival_id, 100.0, "plastic")
        assert not second.success
        assert second.status == "rejected"

    def test_concurrent_double_spend(self, db_path: Path, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """Concurrency: 10 threads racing to mint the same arrival → exactly 1 succeeds."""
        # Create arrival using a fresh connection
        conn = database.get_connection(db_path)
        arrival = _make_arrival(conn, facility, keypair)
        assert arrival.success
        arrival_id = arrival.data["id"]
        conn.close()

        results: list[service.ServiceResult] = []
        lock = threading.Lock()

        def try_mint() -> None:
            c = database.get_connection(db_path)
            try:
                r = service.mint_certificate(c, arrival_id, 100.0, "plastic")
                with lock:
                    results.append(r)
            finally:
                c.close()

        threads = [threading.Thread(target=try_mint) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if r.success]
        assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"


class TestSignatureRejection:
    """Invariant #1: forged signatures must be rejected."""

    def test_forged_signature_rejected(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """An arrival signed with a different key is rejected before storage."""
        _, attacker_privkey = crypto.generate_keypair()
        pubkey_hex, _ = keypair
        ts = datetime.now(timezone.utc).isoformat()
        photo_hash_hex = "ab" * 32
        device_id = "device-test-001"

        record_hash = crypto.canonical_hash(100.0, facility["id"], ts, photo_hash_hex, device_id)
        # Sign with attacker's key — not the registered key
        bad_sig = crypto.sign_payload(attacker_privkey, record_hash)

        result = service.submit_arrival(
            db=db,
            facility_id=facility["id"],
            device_id=device_id,
            weight_kg=100.0,
            photo_hash_hex=photo_hash_hex,
            timestamp_iso=ts,
            record_hash_hex=record_hash.hex(),
            signature_hex=bad_sig,
        )
        assert not result.success
        assert result.status == "rejected"
        assert "signature" in (result.error or "").lower()

    def test_tampered_payload_rejected(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """Payload tampered after signing fails hash check before signature check."""
        pubkey_hex, privkey_hex = keypair
        ts = datetime.now(timezone.utc).isoformat()
        photo_hash_hex = "ab" * 32
        device_id = "device-test-001"

        # Sign with correct weight
        record_hash = crypto.canonical_hash(100.0, facility["id"], ts, photo_hash_hex, device_id)
        sig_hex = crypto.sign_payload(privkey_hex, record_hash)

        # Submit with tampered weight (200.0 instead of 100.0)
        result = service.submit_arrival(
            db=db,
            facility_id=facility["id"],
            device_id=device_id,
            weight_kg=200.0,  # tampered!
            photo_hash_hex=photo_hash_hex,
            timestamp_iso=ts,
            record_hash_hex=record_hash.hex(),  # hash of original weight
            signature_hex=sig_hex,
        )
        assert not result.success
        assert result.status == "rejected"
        assert "hash" in (result.error or "").lower()


class TestCapacityFraud:
    """Invariant #4: capacity ceiling fraud check must trip."""

    def test_capacity_ceiling_blocks_mint(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """Minting more than facility capacity in a period flags for review."""
        # Facility has 1000 kg capacity. Mint 900 kg.
        arrival1 = _make_arrival(db, facility, keypair, weight_kg=900.0)
        assert arrival1.success
        mint1 = service.mint_certificate(db, arrival1.data["id"], 900.0, "plastic")
        assert mint1.success

        # Now try to mint another 200 kg — should exceed 1000 kg capacity
        arrival2 = _make_arrival(
            db,
            facility,
            keypair,
            weight_kg=200.0,
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
        )
        assert arrival2.success
        mint2 = service.mint_certificate(db, arrival2.data["id"], 200.0, "plastic")
        # Should be flagged, not minted
        assert not mint2.success
        assert mint2.status == "flagged_for_review"


class TestLedgerVerification:
    """Invariant #5: ledger proof must verify correctly."""

    def test_certificate_proof_verifies(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """After minting, the certificate's Merkle proof verifies as valid."""
        arrival = _make_arrival(db, facility, keypair)
        assert arrival.success
        mint = service.mint_certificate(db, arrival.data["id"], 100.0, "plastic")
        assert mint.success

        verify = service.verify_certificate(db, mint.data["id"])
        assert verify.success
        assert verify.data is not None
        assert verify.data["valid"] is True

    def test_tampered_cert_fails_verification(self, db, facility, keypair) -> None:  # type: ignore[no-untyped-def]
        """Manually corrupting ledger_hash_hex causes verification to fail."""
        arrival = _make_arrival(db, facility, keypair)
        assert arrival.success
        mint = service.mint_certificate(db, arrival.data["id"], 100.0, "plastic")
        assert mint.success
        cert_id = mint.data["id"]

        # Corrupt the ledger hash directly in the DB
        db.execute(
            "UPDATE certificates SET ledger_hash_hex = 'deadbeef' WHERE id = ?", (cert_id,)
        )
        db.commit()

        verify = service.verify_certificate(db, cert_id)
        # Either fails, or returns valid=False
        if verify.success:
            assert verify.data["valid"] is False

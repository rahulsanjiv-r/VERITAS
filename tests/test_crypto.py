"""
VERITAS — Phase 1 Crypto Test Suite
=====================================

Tests for :mod:`backend.crypto` covering all nine required cases:

1. Valid signature verifies → ``True``
2. Forged signature (different key) → ``False`` (no exception)
3. Tampered payload with valid signature on different data → ``False``
4. Invalid ``pubkey_hex`` → ``False`` (no exception)
5. Invalid ``signature_hex`` (wrong length) → ``False``
6. ``canonical_hash`` is deterministic for identical inputs
7. ``canonical_hash`` is sensitive to field changes (weight change → different hash)
8. Cross-language round-trip: sign with ``sign_payload`` → verify → ``True``
9. ``canonical_hash`` field-order sensitivity: swapping facility_id and device_id
   produces a different hash

No crypto functions are mocked — all calls are real PyNaCl operations.
"""

from __future__ import annotations

import hashlib

import nacl.exceptions
import nacl.signing
import pytest

from backend.crypto import (
    canonical_hash,
    generate_keypair,
    sign_payload,
    verify_signature,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# Standard valid record used across multiple tests.
_WEIGHT_KG: float = 42.123456
_FACILITY_ID: str = "FAC-BLR-001"
_TIMESTAMP_ISO: str = "2026-09-18T12:00:00Z"
_PHOTO_HASH_HEX: str = hashlib.sha256(b"sample photo bytes").hexdigest()
_DEVICE_ID: str = "POD-007"


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    """Return a freshly generated ``(pubkey_hex, privkey_hex)`` pair."""
    return generate_keypair()


@pytest.fixture(scope="module")
def canonical_message() -> bytes:
    """Return the canonical hash for the shared test record."""
    return canonical_hash(
        weight_kg=_WEIGHT_KG,
        facility_id=_FACILITY_ID,
        timestamp_iso=_TIMESTAMP_ISO,
        photo_hash_hex=_PHOTO_HASH_HEX,
        device_id=_DEVICE_ID,
    )


@pytest.fixture(scope="module")
def valid_signature(keypair: tuple[str, str], canonical_message: bytes) -> str:
    """Return a valid signature over ``canonical_message`` using the test keypair."""
    _, privkey_hex = keypair
    return sign_payload(privkey_hex, canonical_message)


# ---------------------------------------------------------------------------
# Test 1 — valid signature verifies → True
# ---------------------------------------------------------------------------


def test_valid_signature_returns_true(
    keypair: tuple[str, str],
    canonical_message: bytes,
    valid_signature: str,
) -> None:
    """A correctly generated signature must verify as True."""
    pubkey_hex, _ = keypair
    result = verify_signature(pubkey_hex, canonical_message, valid_signature)
    assert result is True, "verify_signature must return True for a valid signature"


# ---------------------------------------------------------------------------
# Test 2 — forged signature (different key) → False, no exception
# ---------------------------------------------------------------------------


def test_forged_signature_returns_false(
    canonical_message: bytes,
    valid_signature: str,
) -> None:
    """A signature from a different key must return False, never raise."""
    # Generate a completely unrelated keypair — its public key should reject the
    # signature that was created with the *original* keypair.
    attacker_pubkey_hex, _ = generate_keypair()
    result = verify_signature(attacker_pubkey_hex, canonical_message, valid_signature)
    assert result is False, (
        "verify_signature must return False when the pubkey does not match the signer"
    )


# ---------------------------------------------------------------------------
# Test 3 — tampered payload → False
# ---------------------------------------------------------------------------


def test_tampered_payload_returns_false(
    keypair: tuple[str, str],
    valid_signature: str,
) -> None:
    """A valid signature over record A must not verify against a different record B."""
    pubkey_hex, _ = keypair
    # Tamper: change the weight by a tiny amount — the canonical hash changes.
    tampered_message = canonical_hash(
        weight_kg=_WEIGHT_KG + 0.000001,  # one microgram off
        facility_id=_FACILITY_ID,
        timestamp_iso=_TIMESTAMP_ISO,
        photo_hash_hex=_PHOTO_HASH_HEX,
        device_id=_DEVICE_ID,
    )
    result = verify_signature(pubkey_hex, tampered_message, valid_signature)
    assert result is False, (
        "verify_signature must return False when the message does not match the signature"
    )


# ---------------------------------------------------------------------------
# Test 4 — invalid pubkey_hex → False, no exception
# ---------------------------------------------------------------------------


def test_invalid_pubkey_hex_returns_false(
    canonical_message: bytes,
    valid_signature: str,
) -> None:
    """Malformed pubkey_hex must return False without raising any exception."""
    for bad_key in [
        "not-a-hex-string",          # non-hex characters
        "deadbeef",                   # valid hex but wrong length (4 bytes, need 32)
        "",                           # empty string
        "zz" * 32,                    # non-hex, correct length slot
    ]:
        result = verify_signature(bad_key, canonical_message, valid_signature)
        assert result is False, (
            f"verify_signature must return False for invalid pubkey_hex={bad_key!r}"
        )


# ---------------------------------------------------------------------------
# Test 5 — invalid signature_hex (wrong length) → False
# ---------------------------------------------------------------------------


def test_invalid_signature_hex_returns_false(
    keypair: tuple[str, str],
    canonical_message: bytes,
) -> None:
    """Malformed or wrong-length signature_hex must return False without raising."""
    pubkey_hex, _ = keypair
    for bad_sig in [
        "deadbeef",           # too short (4 bytes)
        "ab" * 65,            # too long  (65 bytes — Ed25519 needs exactly 64)
        "",                   # empty
        "zz" * 64,            # non-hex characters, correct byte-length slot
    ]:
        result = verify_signature(pubkey_hex, canonical_message, bad_sig)
        assert result is False, (
            f"verify_signature must return False for bad signature_hex={bad_sig!r}"
        )


# ---------------------------------------------------------------------------
# Test 6 — canonical_hash is deterministic
# ---------------------------------------------------------------------------


def test_canonical_hash_is_deterministic() -> None:
    """Calling canonical_hash twice with identical inputs must return the same bytes."""
    kwargs: dict[str, object] = {
        "weight_kg": _WEIGHT_KG,
        "facility_id": _FACILITY_ID,
        "timestamp_iso": _TIMESTAMP_ISO,
        "photo_hash_hex": _PHOTO_HASH_HEX,
        "device_id": _DEVICE_ID,
    }
    first = canonical_hash(**kwargs)  # type: ignore[arg-type]
    second = canonical_hash(**kwargs)  # type: ignore[arg-type]
    assert first == second, "canonical_hash must be deterministic for identical inputs"
    assert len(first) == 32, "canonical_hash must return a 32-byte SHA-256 digest"


# ---------------------------------------------------------------------------
# Test 7 — canonical_hash is sensitive to field changes
# ---------------------------------------------------------------------------


def test_canonical_hash_sensitive_to_weight_change() -> None:
    """A different weight_kg must produce a different canonical hash."""
    hash_a = canonical_hash(
        weight_kg=10.0,
        facility_id=_FACILITY_ID,
        timestamp_iso=_TIMESTAMP_ISO,
        photo_hash_hex=_PHOTO_HASH_HEX,
        device_id=_DEVICE_ID,
    )
    hash_b = canonical_hash(
        weight_kg=10.000001,  # differ by 1 µkg
        facility_id=_FACILITY_ID,
        timestamp_iso=_TIMESTAMP_ISO,
        photo_hash_hex=_PHOTO_HASH_HEX,
        device_id=_DEVICE_ID,
    )
    assert hash_a != hash_b, (
        "canonical_hash must produce different digests for different weight_kg values"
    )


# ---------------------------------------------------------------------------
# Test 8 — cross-language round-trip simulation
# ---------------------------------------------------------------------------


def test_cross_language_roundtrip() -> None:
    """sign_payload → verify_signature round-trip must succeed."""
    pubkey_hex, privkey_hex = generate_keypair()
    message = canonical_hash(
        weight_kg=99.0,
        facility_id="FAC-ROUNDTRIP",
        timestamp_iso="2026-01-01T00:00:00Z",
        photo_hash_hex="cc" * 32,
        device_id="POD-ROUNDTRIP",
    )
    signature_hex = sign_payload(privkey_hex, message)

    # Signature must be 64 bytes → 128 hex chars.
    assert len(signature_hex) == 128, (
        f"sign_payload must return a 128-char hex string; got {len(signature_hex)}"
    )
    result = verify_signature(pubkey_hex, message, signature_hex)
    assert result is True, (
        "verify_signature must return True for a signature produced by sign_payload "
        "with the matching private key"
    )


# ---------------------------------------------------------------------------
# Test 9 — canonical_hash field-order sensitivity
# ---------------------------------------------------------------------------


def test_canonical_hash_field_order_sensitivity() -> None:
    """Swapping facility_id and device_id must produce a different hash.

    This test validates that the canonical string is *not* commutative with
    respect to the pipe-separated fields — i.e., that field order is
    semantically meaningful and enforced.
    """
    facility = "FAC-ALPHA"
    device = "POD-BETA"

    # Correct order: ...| facility_id | ... | device_id
    hash_correct = canonical_hash(
        weight_kg=1.0,
        facility_id=facility,
        timestamp_iso=_TIMESTAMP_ISO,
        photo_hash_hex=_PHOTO_HASH_HEX,
        device_id=device,
    )
    # Swapped: facility_id slot gets device value and vice versa
    hash_swapped = canonical_hash(
        weight_kg=1.0,
        facility_id=device,   # swapped
        timestamp_iso=_TIMESTAMP_ISO,
        photo_hash_hex=_PHOTO_HASH_HEX,
        device_id=facility,   # swapped
    )
    assert hash_correct != hash_swapped, (
        "canonical_hash must produce different hashes when facility_id and device_id "
        "are swapped, proving field order is enforced"
    )

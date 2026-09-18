"""
VERITAS — Cryptographic EPR Recycling Verification System
==========================================================

Phase 1 Crypto Module — Option B: Software Ed25519 via PyNaCl
--------------------------------------------------------------

**Cryptographic implementation choice: Option B**
This module uses ``nacl.signing`` (PyNaCl ≥ 1.5) for Ed25519 signature
generation and verification.  The Ed25519 private key lives in **ESP32
flash storage protected by flash encryption** (AES-XTS-256 enabled via
eFuse burn in the factory provisioning step).

**Important security caveat**
This arrangement is *NOT* hardware-backed in the strict sense.
A hardware-backed configuration would require a dedicated secure element
such as the **NXP SE050** (Option C) that performs key operations entirely
inside tamper-resistant silicon and never exposes the private key bytes.
Option B is the MVP path; the private key is recoverable from the ESP32
if an attacker has physical access and can defeat flash encryption.

**Recommended commercial upgrade path: Option C — NXP SE050**
Replace ``sign_payload`` calls in firmware with SE050 I²C commands so the
private key is generated and used inside the secure element and cannot be
extracted even with physical board access.  The backend ``verify_signature``
function and all canonical-hash logic remain unchanged.

Canonical-hash invariant
------------------------
``canonical_hash`` MUST produce byte-for-byte identical output to the
firmware implementation.  The wire format is::

    f"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"

encoded as UTF-8 and hashed with SHA-256.  Any deviation — field order,
separator, float precision — means every arrival record from the affected
firmware version will fail server-side verification.
"""

from __future__ import annotations

import hashlib

import nacl.exceptions
import nacl.signing

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

CANONICAL_FIELD_ORDER: list[str] = [
    "weight_kg",
    "facility_id",
    "timestamp_iso",
    "photo_hash_hex",
    "device_id",
]
"""Ordered field names used when assembling the pipe-separated canonical string.

The ordering is fixed and must never change once firmware is deployed.  Adding
a new field requires a firmware version bump *and* a migration in the backend
to handle both the old and new canonical formats during the transition window.
"""


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def canonical_hash(
    weight_kg: float,
    facility_id: str,
    timestamp_iso: str,
    photo_hash_hex: str,
    device_id: str,
) -> bytes:
    """Compute the canonical SHA-256 hash of an EPR arrival record.

    The canonical string is constructed as::

        f"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"

    It is encoded as UTF-8 before hashing.  The field order and separator
    character are intentionally fixed and MUST match the firmware
    implementation exactly — any deviation causes verification failure for
    every arrival record produced by that firmware build.

    Args:
        weight_kg:       Gross weight of the EPR batch in kilograms.
        facility_id:     Unique string identifier of the recycling facility.
        timestamp_iso:   ISO-8601 timestamp string (e.g. ``"2026-09-18T12:00:00Z"``).
        photo_hash_hex:  Lowercase hex-encoded SHA-256 digest of the arrival photo.
        device_id:       Unique identifier of the VERITAS IoT pod (ESP32 unit).

    Returns:
        32-byte SHA-256 digest of the canonical UTF-8 string.

    Example::

        >>> digest = canonical_hash(12.5, "FAC-001", "2026-09-18T12:00:00Z",
        ...                         "ab" * 32, "POD-007")
        >>> len(digest)
        32
    """
    canonical_str = (
        f"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).digest()


def verify_signature(
    pubkey_hex: str,
    message_bytes: bytes,
    signature_hex: str,
) -> bool:
    """Verify an Ed25519 signature against a message and public key.

    This is the **authoritative verification path** used by the backend.  It
    must satisfy the following invariants:

    * **Never returns** ``True`` if the signature is invalid or the public key
      does not match the signing key.
    * **Never raises** — all ``ValueError``, ``nacl.exceptions.BadSignatureError``,
      and any other exception are caught and converted to ``False``.
    * Constant-time comparison is performed internally by PyNaCl.

    Args:
        pubkey_hex:     Hex-encoded 32-byte Ed25519 public key (64 hex chars).
        message_bytes:  Raw bytes of the message that was signed (i.e. the
                        output of :func:`canonical_hash`).
        signature_hex:  Hex-encoded 64-byte Ed25519 signature (128 hex chars).

    Returns:
        ``True`` if and only if the signature is cryptographically valid for
        the given public key and message; ``False`` in every other case.
    """
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        verify_key = nacl.signing.VerifyKey(pubkey_bytes)
        # VerifyKey.verify raises BadSignatureError on failure; no return value used.
        verify_key.verify(message_bytes, sig_bytes)
        return True
    except (
        nacl.exceptions.BadSignatureError,
        ValueError,
        TypeError,
        Exception,  # noqa: BLE001 — intentional blanket catch; must never raise
    ):
        return False


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair for testing or device provisioning.

    Returns a ``(pubkey_hex, privkey_hex)`` tuple where both components are
    lowercase hex strings.  The public key is 32 bytes (64 hex chars); the
    private key (signing seed) is 32 bytes (64 hex chars).

    .. warning::
        **For production use** the private key MUST be generated inside the
        secure element (ESP32 flash encryption zone in Option B; NXP SE050 in
        Option C) and must never transit this function.  This function is
        provided solely for use in tests and the ``simulate_pod.py`` script.

    Returns:
        Tuple of ``(pubkey_hex, privkey_hex)``.

    Example::

        >>> pub, priv = generate_keypair()
        >>> len(pub)
        64
        >>> len(priv)
        64
    """
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    # SigningKey.encode() returns the 32-byte seed; VerifyKey.encode() is the 32-byte public key.
    privkey_hex: str = signing_key.encode().hex()
    pubkey_hex: str = verify_key.encode().hex()
    return pubkey_hex, privkey_hex


def sign_payload(privkey_hex: str, message_bytes: bytes) -> str:
    """Sign a message with an Ed25519 private key and return the hex signature.

    Produces a lowercase hex-encoded 64-byte Ed25519 signature (128 hex chars).

    .. note::
        This function is used only by ``simulate_pod.py`` and the test suite.
        It is **NOT** part of the backend verification path — the backend only
        calls :func:`verify_signature`.  In a real deployment the signing
        happens on the ESP32 (Option B) or inside the NXP SE050 (Option C).

    Args:
        privkey_hex:    Hex-encoded 32-byte Ed25519 signing seed (64 hex chars).
        message_bytes:  Raw bytes to sign (typically the output of
                        :func:`canonical_hash`).

    Returns:
        Lowercase hex-encoded 64-byte signature string (128 hex chars).

    Raises:
        ValueError: If ``privkey_hex`` is not a valid 32-byte hex string.
    """
    seed_bytes = bytes.fromhex(privkey_hex)
    signing_key = nacl.signing.SigningKey(seed_bytes)
    signed: nacl.signing.SignedMessage = signing_key.sign(message_bytes)
    # signed.signature is the raw 64-byte signature without the message prepended.
    return signed.signature.hex()

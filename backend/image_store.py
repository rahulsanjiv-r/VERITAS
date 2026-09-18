"""
VERITAS — Image storage module (image_store.py).

Handles saving and retrieving gate-pod photos for EPR arrival records.

Design principles:
- Invariant #14 (fail-closed): every function catches all exceptions and
  returns a safe default (empty string / None) rather than propagating to
  callers. Errors are printed to stderr so they are visible in logs.
- Invariant #13 (data minimisation): files are stored by arrival_id only;
  no personally-identifiable metadata is embedded in the path.
- Object storage (S3-compatible) is the recommended production backend
  per SKILL.md. This local-disk module is for the pilot/demo phase.

Environment variables:
    VERITAS_PHOTOS_DIR  Directory to store arrival photos (default: ./photos)
"""
from __future__ import annotations

import hashlib
import os
import sys
import logging

_log = logging.getLogger(__name__)
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_PHOTOS_DIR = "./photos"


def _photos_dir() -> str:
    """Return the configured photos directory from env (or default)."""
    return os.environ.get("VERITAS_PHOTOS_DIR", _DEFAULT_PHOTOS_DIR)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def save_photo(arrival_id: str, image_bytes: bytes) -> str:
    """Save raw image bytes to disk as ``{VERITAS_PHOTOS_DIR}/{arrival_id}.jpg``.

    The directory is created if it does not exist.

    Invariant #14 — fail-closed: any exception is caught, printed to stderr,
    and an empty string is returned so the caller is never surprised by an
    uncaught exception from the storage layer.

    Args:
        arrival_id: UUID of the arrival this photo belongs to.  Used as the
            filename stem so retrieval is O(1) (no directory scan needed).
        image_bytes: Raw JPEG bytes from the gate pod camera.

    Returns:
        Absolute path of the saved file on success, or ``""`` on any error.
    """
    if ".." in arrival_id or "/" in arrival_id or "\\" in arrival_id:
        _log.error(f"[VERITAS] image_store.save_photo failed: invalid arrival_id '{arrival_id}'")
        return ""

    try:
        photos_dir = Path(_photos_dir())
        os.makedirs(photos_dir, exist_ok=True)
        file_path = photos_dir / f"{arrival_id}.jpg"
        file_path.write_bytes(image_bytes)
        return str(file_path.resolve())
    except Exception as exc:  # noqa: BLE001 — intentional broad catch (invariant #14)
        _log.error(
            f"[VERITAS] image_store.save_photo failed for arrival '{arrival_id}': {exc}",
        )
        return ""


def get_photo_path(arrival_id: str) -> str | None:
    """Return the path of the stored photo for ``arrival_id``, or ``None`` if absent.

    Invariant #14 — fail-closed: any unexpected exception returns ``None``
    rather than propagating.

    Args:
        arrival_id: UUID of the arrival to look up.

    Returns:
        Absolute path string if the file exists, otherwise ``None``.
    """
    if ".." in arrival_id or "/" in arrival_id or "\\" in arrival_id:
        return None

    try:
        file_path = Path(_photos_dir()) / f"{arrival_id}.jpg"
        if file_path.exists():
            return str(file_path.resolve())
        return None
    except Exception as exc:  # noqa: BLE001 — invariant #14
        _log.error(
            f"[VERITAS] image_store.get_photo_path failed for arrival '{arrival_id}': {exc}",
        )
        return None


def compute_sha256(image_bytes: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``image_bytes``.

    This is used to bind the stored photo to the ``photo_hash_hex`` recorded
    in the arrival — a cross-check that the bytes stored on disk match the
    hash the gate pod committed to in its signed arrival record.

    Invariant #14 — fail-closed: returns empty string on any error rather
    than propagating.

    Args:
        image_bytes: Raw bytes to hash.

    Returns:
        64-character lowercase hex string, or ``""`` on error.
    """
    try:
        return hashlib.sha256(image_bytes).hexdigest()
    except Exception as exc:  # noqa: BLE001 — invariant #14
        _log.error(
            f"[VERITAS] image_store.compute_sha256 failed: {exc}",
        )
        return ""

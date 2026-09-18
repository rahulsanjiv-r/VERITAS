"""
VERITAS — Image storage module tests (test_image_store.py).

Tests for backend/image_store.py:
- save_and_retrieve_photo: save bytes, verify file exists, sha256 matches
- compute_sha256_known_value: sha256 of b'hello' == known value
- save_photo_fail_closed: OSError during makedirs → returns "" without raising
- get_photo_path_nonexistent: returns None for unknown arrival_id
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from backend import image_store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 256  # minimal JPEG-like header


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_save_and_retrieve_photo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """save_photo saves bytes to disk; get_photo_path returns the same path;
    and compute_sha256 of the saved bytes matches the on-disk file."""
    monkeypatch.setenv("VERITAS_PHOTOS_DIR", str(tmp_path / "photos"))

    arrival_id = "arrival-test-001"
    image_bytes = _SAMPLE_BYTES

    # Save
    path = image_store.save_photo(arrival_id, image_bytes)
    assert path != "", "save_photo should return a non-empty path on success"
    assert Path(path).exists(), "Saved file must exist on disk"
    assert Path(path).read_bytes() == image_bytes, "File content must match input bytes"

    # Retrieve
    retrieved = image_store.get_photo_path(arrival_id)
    assert retrieved is not None
    assert Path(retrieved).exists()

    # SHA-256 cross-check
    expected_sha = hashlib.sha256(image_bytes).hexdigest()
    actual_sha = image_store.compute_sha256(image_bytes)
    assert actual_sha == expected_sha


def test_compute_sha256_known_value() -> None:
    """SHA-256 of b'hello' must equal the well-known constant."""
    known = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    result = image_store.compute_sha256(b"hello")
    assert result == known


def test_save_photo_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If os.makedirs raises OSError, save_photo returns '' without raising."""
    monkeypatch.setenv("VERITAS_PHOTOS_DIR", str(tmp_path / "photos"))

    with patch("os.makedirs", side_effect=OSError("disk full")):
        result = image_store.save_photo("arrival-fail-001", b"data")

    assert result == "", "save_photo must return '' on OSError (fail-closed invariant #14)"


def test_get_photo_path_nonexistent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """get_photo_path returns None when no photo has been saved for the arrival_id."""
    monkeypatch.setenv("VERITAS_PHOTOS_DIR", str(tmp_path / "photos"))

    result = image_store.get_photo_path("arrival-that-does-not-exist")
    assert result is None, "get_photo_path must return None for unknown arrival_id"

"""
VERITAS — tests/test_cv_checker.py

Unit tests for backend/cv_checker.py (Phase 13: Computer-Vision waste verification).
Verifies:
  - Hash integrity checks (match and mismatch)
  - Color histogram extraction and statistics
  - Waste category classification heuristics (plastic, metal, paper, glass, e_waste)
  - Fail-closed error handling (Invariant #14)
  - Pillow-unavailable graceful skip
  - Return types and confidence bounds
"""

import hashlib
import io
from dataclasses import is_dataclass
from typing import Tuple

import pytest

from backend import cv_checker
from backend.cv_checker import (
    CVResult,
    analyze_color_histogram,
    classify_waste_category,
    verify_photo,
)
from backend.models import WasteCategory

try:
    from PIL import Image

    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def _create_test_image(color: Tuple[int, int, int] = (200, 100, 50)) -> bytes:
    """Helper to generate a valid minimal 10x10 PNG in memory."""
    if not HAS_PIL:
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 50  # fallback stub
    img = Image.new("RGB", (10, 10), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Test 1: Hash mismatch detected
# ---------------------------------------------------------------------------
def test_hash_mismatch_detected() -> None:
    """Passing a wrong hash must return matched=False."""
    image_bytes = _create_test_image((50, 120, 220))
    wrong_hash = "0" * 64
    result = verify_photo(image_bytes, wrong_hash, "plastic")

    assert isinstance(result, CVResult)
    assert result.matched is False
    assert result.detected_category is None
    assert "mismatch" in result.reason or "photo_hash_mismatch" in result.reason


# ---------------------------------------------------------------------------
# Test 2: Correct hash matches
# ---------------------------------------------------------------------------
def test_hash_match_correct() -> None:
    """Correct SHA-256 of image bytes must return matched=True."""
    image_bytes = _create_test_image((50, 120, 220))
    correct_hash = hashlib.sha256(image_bytes).hexdigest()
    result = verify_photo(image_bytes, correct_hash, "plastic")

    assert isinstance(result, CVResult)
    assert result.matched is True


# ---------------------------------------------------------------------------
# Test 3: Fail-closed on bad input
# ---------------------------------------------------------------------------
def test_fail_closed_on_bad_input() -> None:
    """Empty bytes must fail-closed: matched=False, reason contains 'failed_closed'."""
    result = verify_photo(b"", "any_hash", "plastic")

    assert isinstance(result, CVResult)
    if result.reason == "pillow_not_installed_skipped":
        assert result.matched is True
    else:
        assert result.matched is False
        assert "failed_closed" in result.reason


# ---------------------------------------------------------------------------
# Test 4: Pillow not available skips gracefully
# ---------------------------------------------------------------------------
def test_pillow_not_available_skips_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """When Pillow is not available, verify_photo must skip gracefully with matched=True."""
    monkeypatch.setattr(cv_checker, "PILLOW_AVAILABLE", False)
    raw_bytes = b"\xff" * 64
    h = hashlib.sha256(raw_bytes).hexdigest()

    result = verify_photo(raw_bytes, h, "plastic")
    assert isinstance(result, CVResult)
    assert result.matched is True
    assert result.confidence == 0.0
    assert result.reason == "pillow_not_installed_skipped"
    assert result.detected_category is None


# ---------------------------------------------------------------------------
# Test 5: Result is dataclass
# ---------------------------------------------------------------------------
def test_result_is_dataclass() -> None:
    """Returned result must be an instance of the CVResult dataclass."""
    image_bytes = _create_test_image((160, 160, 160))
    h = hashlib.sha256(image_bytes).hexdigest()
    result = verify_photo(image_bytes, h, "metal")

    assert isinstance(result, CVResult)
    assert is_dataclass(result)
    assert hasattr(result, "matched")
    assert hasattr(result, "detected_category")
    assert hasattr(result, "confidence")
    assert hasattr(result, "reason")


# ---------------------------------------------------------------------------
# Test 6: Confidence range
# ---------------------------------------------------------------------------
def test_confidence_range() -> None:
    """Confidence must always be bounded in [0.0, 1.0]."""
    test_cases = [
        (_create_test_image((50, 120, 220)), "plastic"),
        (_create_test_image((150, 150, 150)), "metal"),
        (_create_test_image((220, 190, 140)), "paper"),
        (_create_test_image((245, 248, 250)), "glass"),
        (_create_test_image((30, 35, 40)), "e_waste"),
        (b"", "plastic"),
        (b"\xff" * 50, "plastic"),
    ]

    for img_bytes, cat in test_cases:
        h = hashlib.sha256(img_bytes).hexdigest() if img_bytes else "fake_hash"
        result = verify_photo(img_bytes, h, cat)
        assert 0.0 <= result.confidence <= 1.0, f"Failed for category {cat}: {result.confidence}"


# ---------------------------------------------------------------------------
# Test 7: Declared category comparison
# ---------------------------------------------------------------------------
def test_declared_category_comparison() -> None:
    """When detected category matches declared, confidence > 0.5 OR reason explains skip."""
    blue_plastic_bytes = _create_test_image((50, 120, 220))
    h = hashlib.sha256(blue_plastic_bytes).hexdigest()

    # Match case
    result_match = verify_photo(blue_plastic_bytes, h, "plastic")
    if result_match.reason == "pillow_not_installed_skipped":
        assert result_match.confidence == 0.0
    else:
        assert result_match.matched is True
        assert result_match.confidence > 0.5
        assert "category_match" in result_match.reason

    # Mismatch case
    result_mismatch = verify_photo(blue_plastic_bytes, h, "metal")
    if result_mismatch.reason != "pillow_not_installed_skipped":
        assert result_mismatch.matched is True
        assert "category_mismatch" in result_mismatch.reason


# ---------------------------------------------------------------------------
# Test 8: Analyze histogram returns dict with expected keys
# ---------------------------------------------------------------------------
def test_analyze_histogram_returns_dict() -> None:
    """analyze_color_histogram must return a dict containing all expected statistics keys."""
    if not HAS_PIL:
        pytest.skip("Pillow not installed in test environment")

    image_bytes = _create_test_image((100, 150, 200))
    stats = analyze_color_histogram(image_bytes)

    assert isinstance(stats, dict)
    expected_keys = [
        "mean_r",
        "mean_g",
        "mean_b",
        "avg_r",
        "avg_g",
        "avg_b",
        "brightness",
        "saturation",
        "variance",
        "red_ratio",
        "green_ratio",
        "blue_ratio",
        "perceptual_hash",
        "pixel_count",
    ]
    for k in expected_keys:
        assert k in stats, f"Missing expected key: {k}"

    assert isinstance(stats["perceptual_hash"], str)
    assert len(stats["perceptual_hash"]) == 16
    assert stats["pixel_count"] > 0


# ---------------------------------------------------------------------------
# Test 9: Classification heuristics for all 5 categories
# ---------------------------------------------------------------------------
def test_classify_waste_category_all_categories() -> None:
    """Synthetic stats for all 5 categories must classify correctly with high confidence."""
    category_stats = {
        "plastic": {
            "mean_r": 50.0,
            "mean_g": 120.0,
            "mean_b": 220.0,
            "brightness": 130.0,
            "saturation": 0.77,
            "variance": 10.0,
            "blue_ratio": 0.56,
        },
        "metal": {
            "mean_r": 150.0,
            "mean_g": 150.0,
            "mean_b": 150.0,
            "brightness": 150.0,
            "saturation": 0.0,
            "variance": 0.0,
            "blue_ratio": 0.33,
        },
        "paper": {
            "mean_r": 220.0,
            "mean_g": 190.0,
            "mean_b": 140.0,
            "brightness": 183.0,
            "saturation": 0.36,
            "variance": 20.0,
            "blue_ratio": 0.25,
        },
        "glass": {
            "mean_r": 245.0,
            "mean_g": 248.0,
            "mean_b": 250.0,
            "brightness": 247.0,
            "saturation": 0.02,
            "variance": 5.0,
            "blue_ratio": 0.33,
        },
        "e_waste": {
            "mean_r": 30.0,
            "mean_g": 35.0,
            "mean_b": 40.0,
            "brightness": 35.0,
            "saturation": 0.25,
            "variance": 10.0,
            "blue_ratio": 0.38,
        },
    }

    for expected_cat, stats in category_stats.items():
        detected_cat, conf = classify_waste_category(stats)
        assert detected_cat == expected_cat, f"Expected {expected_cat}, got {detected_cat}"
        assert conf > 0.5, f"Confidence for {expected_cat} was {conf} <= 0.5"


# ---------------------------------------------------------------------------
# Test 10: Empty stats dictionary returns unknown
# ---------------------------------------------------------------------------
def test_classify_waste_category_empty_dict() -> None:
    """Empty or missing stats must return ('unknown', 0.0) without raising."""
    cat, conf = classify_waste_category({})
    assert cat == "unknown"
    assert conf == 0.0


# ---------------------------------------------------------------------------
# Test 11: Support WasteCategory Enum
# ---------------------------------------------------------------------------
def test_verify_photo_with_enum_category() -> None:
    """Passing WasteCategory Enum instance must work seamlessly."""
    blue_plastic_bytes = _create_test_image((50, 120, 220))
    h = hashlib.sha256(blue_plastic_bytes).hexdigest()

    result = verify_photo(blue_plastic_bytes, h, WasteCategory.PLASTIC)
    assert result.matched is True
    if result.reason != "pillow_not_installed_skipped":
        assert "category_match" in result.reason

    # Metal enum comparison
    grey_bytes = _create_test_image((150, 150, 150))
    h_grey = hashlib.sha256(grey_bytes).hexdigest()
    result_metal = verify_photo(grey_bytes, h_grey, WasteCategory.NON_FERROUS_METAL)
    assert result_metal.matched is True
    if result_metal.reason != "pillow_not_installed_skipped":
        assert "category_match" in result_metal.reason


# ---------------------------------------------------------------------------
# Test 12: Raw non-image bytes with correct hash
# ---------------------------------------------------------------------------
def test_raw_bytes_hash_match_unidentified_image() -> None:
    """Raw non-image bytes (e.g. b'\xff'*100) with correct hash match integrity."""
    raw_bytes = b"\xff" * 100
    h = hashlib.sha256(raw_bytes).hexdigest()

    result = verify_photo(raw_bytes, h, "plastic")
    assert result.matched is True
    assert result.detected_category is None
    assert result.confidence == 0.0
    assert (
        result.reason == "image_decode_failed_hash_matched"
        or result.reason == "pillow_not_installed_skipped"
    )


# ---------------------------------------------------------------------------
# Test 13: Fail-closed on None inputs
# ---------------------------------------------------------------------------
def test_fail_closed_on_none_inputs() -> None:
    """Passing None as image_bytes or photo_hash_hex must fail-closed."""
    res1 = verify_photo(None, "hash", "plastic")  # type: ignore[arg-type]
    assert res1.matched is False
    assert "failed_closed" in res1.reason

    res2 = verify_photo(b"data", None, "plastic")  # type: ignore[arg-type]
    assert res2.matched is False
    assert "failed_closed" in res2.reason


# ---------------------------------------------------------------------------
# Test 14: analyze_color_histogram on empty bytes raises ValueError
# ---------------------------------------------------------------------------
def test_analyze_color_histogram_empty_bytes_raises() -> None:
    """analyze_color_histogram must raise ValueError if image_bytes is empty."""
    with pytest.raises(ValueError, match="Cannot analyze empty image bytes"):
        analyze_color_histogram(b"")


# ---------------------------------------------------------------------------
# Test 15: Unexpected runtime exception fails-closed
# ---------------------------------------------------------------------------
def test_unexpected_runtime_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any unexpected internal exception in verify_photo must return cv_check_failed_closed."""
    def _exploding_sha(*args: object, **kwargs: object) -> object:
        raise RuntimeError("Catastrophic hash failure")

    monkeypatch.setattr(hashlib, "sha256", _exploding_sha)
    result = verify_photo(b"test_image_bytes", "hash", "plastic")

    assert isinstance(result, CVResult)
    assert result.matched is False
    assert result.confidence == 0.0
    assert result.reason == "cv_check_failed_closed"


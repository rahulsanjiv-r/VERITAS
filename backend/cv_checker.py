"""
VERITAS — backend/cv_checker.py

Lightweight computer vision waste category verification.

Fail-closed contract (Invariant #14):
-------------------------------------
Any unexpected exception during image processing returns:
``CVResult(matched=False, detected_category=None, confidence=0.0, reason='cv_check_failed_closed')``

Advisory role (Invariant #4):
-----------------------------
This check is purely ADVISORY. It raises a fraud signal/flag when the photo
signature or category does not match, but does NOT block certificate minting
by itself. The service layer (service.py) makes the final policy decision.

Architecture & Constraints:
---------------------------
- Lightweight: No GPU, no PyTorch, no TensorFlow, no heavy models.
- Perceptual difference hash (dHash) + color histogram analysis.
- Supports 5 waste categories heuristically:
  * plastic: high blue/clear tones, low variance (homogeneous)
  * metal: silver/grey dominant (high avg, low saturation)
  * paper: beige/brown/white dominant
  * glass: high transparency proxy (light image, low saturation)
  * e_waste: mixed colors, darker tones
- Graceful skip if Pillow is not installed: returns ``matched=True`` with
  ``reason='pillow_not_installed_skipped'``.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    import PIL
    from PIL import Image, UnidentifiedImageError

    PILLOW_AVAILABLE = True
except ImportError:  # pragma: no cover
    PILLOW_AVAILABLE = False
    Image = None  # type: ignore[assignment]
    UnidentifiedImageError = Exception  # type: ignore[assignment,misc]


@dataclass
class CVResult:
    """Result of computer vision waste photo verification.

    Attributes:
        matched:            True if photo_hash_hex matches image bytes (integrity check).
        detected_category:  Best guess at waste category (plastic, metal, paper, glass, e_waste),
                            or None if image could not be classified.
        confidence:         Float in range [0.0, 1.0].
        reason:             Human-readable explanation of the check outcome.
    """

    matched: bool
    detected_category: Optional[str]
    confidence: float
    reason: str


def _is_pillow_available() -> bool:
    """Check if Pillow is currently installed and functional."""
    if not PILLOW_AVAILABLE:
        return False
    try:
        import PIL
        from PIL import Image  # noqa: F401

        return True
    except (ImportError, ModuleNotFoundError, AttributeError):
        return False


def _normalize_category(cat: Optional[str]) -> str:
    """Normalize category name for robust comparison."""
    if not cat:
        return ""
    c = cat.lower().strip().replace("-", "_").replace(" ", "_")
    if "plastic" in c:
        return "plastic"
    if "metal" in c:
        return "metal"
    if "e_waste" in c or "ewaste" in c or "electronic" in c:
        return "e_waste"
    if "paper" in c:
        return "paper"
    if "glass" in c:
        return "glass"
    if "construction" in c or "demolition" in c:
        return "construction_demolition"
    return c


def compute_perceptual_hash(image: Any) -> str:
    """Compute a 64-bit difference hash (dHash) as a 16-char hex string.

    Internal helper used alongside color histogram analysis.
    """
    try:
        gray = image.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
        if hasattr(gray, "get_flattened_data"):
            pixels = list(gray.get_flattened_data())
        else:
            pixels = list(gray.getdata())

        bits = []
        for row in range(8):
            for col in range(8):
                left = pixels[row * 9 + col]
                right = pixels[row * 9 + col + 1]
                bits.append("1" if left > right else "0")
        bit_str = "".join(bits)
        return f"{int(bit_str, 2):016x}"
    except Exception:
        return "0" * 16


def analyze_color_histogram(image_bytes: bytes) -> Dict[str, Any]:
    """Return color channel statistics and perceptual hash for classification.

    Internal use. Extracts RGB channel averages, variance, brightness,
    saturation, and channel ratios.

    Args:
        image_bytes: Raw bytes of the image file (PNG/JPEG/etc.)

    Returns:
        Dictionary containing color metrics and perceptual hash.

    Raises:
        ValueError: If image_bytes is empty or invalid.
    """
    if not image_bytes:
        raise ValueError("Cannot analyze empty image bytes")

    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    # Resize to max 64x64 for fast and deterministic analysis on CPU
    image.thumbnail((64, 64))

    if hasattr(image, "get_flattened_data"):
        pixels = list(image.get_flattened_data())
    else:
        pixels = list(image.getdata())

    if not pixels:
        raise ValueError("Image has no pixel data")

    n = len(pixels)
    sum_r = sum(p[0] for p in pixels)
    sum_g = sum(p[1] for p in pixels)
    sum_b = sum(p[2] for p in pixels)

    mean_r = sum_r / n
    mean_g = sum_g / n
    mean_b = sum_b / n

    var_r = sum((p[0] - mean_r) ** 2 for p in pixels) / n
    var_g = sum((p[1] - mean_g) ** 2 for p in pixels) / n
    var_b = sum((p[2] - mean_b) ** 2 for p in pixels) / n
    total_variance = (var_r + var_g + var_b) / 3.0

    # Brightness (mean RGB intensity, 0-255)
    brightness = (mean_r + mean_g + mean_b) / 3.0

    # Saturation (average of (max - min) / max)
    sat_sum = 0.0
    for r, g, b in pixels:
        mx = max(r, g, b)
        mn = min(r, g, b)
        if mx > 0:
            sat_sum += (mx - mn) / mx
    avg_saturation = sat_sum / n

    # Color channel ratios
    total_rgb = mean_r + mean_g + mean_b + 1e-6
    red_ratio = mean_r / total_rgb
    green_ratio = mean_g / total_rgb
    blue_ratio = mean_b / total_rgb

    # Perceptual difference hash
    p_hash = compute_perceptual_hash(image)

    return {
        "pixel_count": n,
        "mean_r": mean_r,
        "mean_g": mean_g,
        "mean_b": mean_b,
        "avg_r": mean_r,
        "avg_g": mean_g,
        "avg_b": mean_b,
        "brightness": brightness,
        "saturation": avg_saturation,
        "variance": total_variance,
        "var_r": var_r,
        "var_g": var_g,
        "var_b": var_b,
        "red_ratio": red_ratio,
        "green_ratio": green_ratio,
        "blue_ratio": blue_ratio,
        "perceptual_hash": p_hash,
    }


def classify_waste_category(histogram_stats: Dict[str, Any]) -> Tuple[str, float]:
    """Heuristic classifier. Returns (category, confidence). Internal use.

    Categories:
      - plastic: high blue/clear tones, low variance (homogeneous)
      - metal: silver/grey dominant (high avg, low saturation)
      - paper: beige/brown/white dominant
      - glass: high transparency proxy (light image, low saturation)
      - e_waste: mixed colors, darker tones

    Args:
        histogram_stats: Channel statistics dict from analyze_color_histogram.

    Returns:
        Tuple of (detected_category, confidence) where confidence is in [0.0, 1.0].
    """
    if not histogram_stats:
        return ("unknown", 0.0)

    mean_r = float(histogram_stats.get("mean_r", 0.0))
    mean_g = float(histogram_stats.get("mean_g", 0.0))
    mean_b = float(histogram_stats.get("mean_b", 0.0))
    brightness = float(histogram_stats.get("brightness", 0.0))
    saturation = float(histogram_stats.get("saturation", 0.0))
    variance = float(histogram_stats.get("variance", 0.0))
    blue_ratio = float(histogram_stats.get("blue_ratio", 0.0))

    scores: Dict[str, float] = {}

    # 1. Plastic: high blue/clear tones, low variance (homogeneous)
    plastic_score = 0.0
    if blue_ratio > 0.36:
        plastic_score = 0.55 + min(0.35, (blue_ratio - 0.36) * 2.0)
        if variance < 800:
            plastic_score += 0.1 * (1.0 - variance / 800.0)
    scores["plastic"] = plastic_score

    # 2. Glass: high transparency proxy (light image, low saturation)
    # Checked before metal because glass is typically lighter/higher brightness
    glass_score = 0.0
    if brightness >= 225 and saturation < 0.10:
        glass_score = (
            0.75
            + min(0.15, (brightness - 225) / 30.0 * 0.15)
            + (1.0 - saturation / 0.10) * 0.10
        )
    scores["glass"] = glass_score

    # 3. Metal: silver/grey dominant (high avg, low saturation)
    metal_score = 0.0
    if saturation < 0.15 and 80 <= brightness < 225:
        metal_score = 0.70 + (1.0 - saturation / 0.15) * 0.25
    scores["metal"] = metal_score

    # 4. Paper: beige/brown/white dominant
    paper_score = 0.0
    if (mean_r > mean_g >= mean_b) and (mean_r - mean_b >= 15):
        paper_score = 0.70 + min(0.25, (mean_r - mean_b) / 100.0)
    elif 180 <= brightness < 225 and saturation < 0.20 and (mean_r >= mean_g >= mean_b):
        paper_score = 0.65
    scores["paper"] = paper_score

    # 5. E-waste: mixed colors, darker tones
    e_waste_score = 0.0
    if brightness < 90:
        e_waste_score = 0.70 + (1.0 - brightness / 90.0) * 0.25
        if variance > 300 or saturation > 0.2:
            e_waste_score += 0.05
    elif brightness < 120 and (variance > 400 or saturation > 0.3):
        e_waste_score = 0.65
    scores["e_waste"] = e_waste_score

    best_category, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score < 0.3:
        return ("unknown", 0.0)

    confidence = round(min(1.0, max(0.0, best_score)), 2)
    return (best_category, confidence)


def verify_photo(
    image_bytes: bytes,
    photo_hash_hex: str,
    declared_category: str,
) -> CVResult:
    """Verify image hash integrity and optionally classify waste category.

    Fail-closed: Any unexpected exception returns:
    ``CVResult(matched=False, detected_category=None, confidence=0.0, reason='cv_check_failed_closed')``

    If Pillow is not installed, returns:
    ``CVResult(matched=True, detected_category=None, confidence=0.0, reason='pillow_not_installed_skipped')``

    Args:
        image_bytes:       Raw binary bytes of the arrival photo.
        photo_hash_hex:    Declared SHA-256 hex digest of the arrival photo.
        declared_category: Declared waste category string (e.g. 'plastic', 'metal').

    Returns:
        CVResult with matched status, detected category, confidence, and explanation.
    """
    # Check if Pillow is available; if not, skip gracefully
    if not _is_pillow_available():
        return CVResult(
            matched=True,
            detected_category=None,
            confidence=0.0,
            reason="pillow_not_installed_skipped",
        )

    try:
        # Validate inputs
        if not image_bytes:
            return CVResult(
                matched=False,
                detected_category=None,
                confidence=0.0,
                reason="cv_check_failed_closed",
            )

        if not photo_hash_hex or not isinstance(photo_hash_hex, str):
            return CVResult(
                matched=False,
                detected_category=None,
                confidence=0.0,
                reason="cv_check_failed_closed",
            )

        # 1. Integrity check: SHA-256 of image bytes vs photo_hash_hex
        computed_hash = hashlib.sha256(image_bytes).hexdigest().lower()
        if computed_hash != photo_hash_hex.strip().lower():
            return CVResult(
                matched=False,
                detected_category=None,
                confidence=0.0,
                reason="photo_hash_mismatch",
            )

        # Normalize declared category
        declared_str = ""
        if declared_category is not None:
            declared_str = str(getattr(declared_category, "value", declared_category))

        # 2. Category classification using color histogram
        try:
            stats = analyze_color_histogram(image_bytes)
            detected_category, confidence = classify_waste_category(stats)
        except (UnidentifiedImageError, OSError):
            # Hash matched, but bytes are not a valid image format (e.g. raw test bytes)
            return CVResult(
                matched=True,
                detected_category=None,
                confidence=0.0,
                reason="image_decode_failed_hash_matched",
            )

        norm_detected = _normalize_category(detected_category)
        norm_declared = _normalize_category(declared_str)

        if norm_detected and norm_declared and norm_detected == norm_declared:
            confidence = max(confidence, 0.6)
            reason = (
                f"category_match: detected '{detected_category}' "
                f"matches declared '{declared_str}'"
            )
        else:
            reason = (
                f"category_mismatch: detected '{detected_category}' "
                f"does not match declared '{declared_str}'"
            )

        return CVResult(
            matched=True,
            detected_category=detected_category,
            confidence=min(1.0, max(0.0, float(confidence))),
            reason=reason,
        )

    except Exception:
        return CVResult(
            matched=False,
            detected_category=None,
            confidence=0.0,
            reason="cv_check_failed_closed",
        )

import sys
with open("image_store.py", "r") as f:
    text = f.read()

replacement = """def save_photo(arrival_id: str, image_bytes: bytes) -> str:
    \"\"\"Save raw image bytes to disk as ``{VERITAS_PHOTOS_DIR}/{arrival_id}.jpg``.

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
    \"\"\"
    if ".." in arrival_id or "/" in arrival_id or "\\\\" in arrival_id:
        print(f"[VERITAS] image_store.save_photo failed: invalid arrival_id '{arrival_id}'", file=sys.stderr)
        return ""

    try:"""

text = text.replace('def save_photo(arrival_id: str, image_bytes: bytes) -> str:\n    """Save raw image bytes to disk as ``{VERITAS_PHOTOS_DIR}/{arrival_id}.jpg``.\n\n    The directory is created if it does not exist.\n\n    Invariant #14 — fail-closed: any exception is caught, printed to stderr,\n    and an empty string is returned so the caller is never surprised by an\n    uncaught exception from the storage layer.\n\n    Args:\n        arrival_id: UUID of the arrival this photo belongs to.  Used as the\n            filename stem so retrieval is O(1) (no directory scan needed).\n        image_bytes: Raw JPEG bytes from the gate pod camera.\n\n    Returns:\n        Absolute path of the saved file on success, or ``""`` on any error.\n    """\n    try:', replacement)

with open("image_store.py", "w") as f:
    f.write(text)

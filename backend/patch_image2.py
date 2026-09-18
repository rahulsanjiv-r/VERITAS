import sys
with open("image_store.py", "r") as f:
    text = f.read()

replacement2 = """def get_photo_path(arrival_id: str) -> str | None:
    \"\"\"Return the path of the stored photo for ``arrival_id``, or ``None`` if absent.

    Invariant #14 — fail-closed: any unexpected exception returns ``None``
    rather than propagating.

    Args:
        arrival_id: UUID of the arrival to look up.

    Returns:
        Absolute path string if the file exists, otherwise ``None``.
    \"\"\"
    if ".." in arrival_id or "/" in arrival_id or "\\\\" in arrival_id:
        return None

    try:"""

text = text.replace('def get_photo_path(arrival_id: str) -> str | None:\n    """Return the path of the stored photo for ``arrival_id``, or ``None`` if absent.\n\n    Invariant #14 — fail-closed: any unexpected exception returns ``None``\n    rather than propagating.\n\n    Args:\n        arrival_id: UUID of the arrival to look up.\n\n    Returns:\n        Absolute path string if the file exists, otherwise ``None``.\n    """\n    try:', replacement2)

with open("image_store.py", "w") as f:
    f.write(text)

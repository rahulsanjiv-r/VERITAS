"""
Root conftest.py — adds the project root to sys.path so that
`import backend.*` works in tests without a pip-editable install.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on the path regardless of how pytest is invoked.
sys.path.insert(0, str(Path(__file__).parent))

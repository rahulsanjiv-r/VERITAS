"""
VERITAS — Observability (observability.py).

Provides:
  * JSONFormatter: a logging.Formatter subclass that writes each record as a
    single-line JSON object.  No third-party deps — stdlib only.
  * get_logger(name): returns a configured logger that writes JSON lines to
    stderr.
  * In-memory metrics counters (thread-safe) for:
    - requests_total (keyed by "METHOD /route")
    - arrivals_submitted_total
    - certificates_minted_total
    - fraud_flags_total
    - errors_total
  * increment_counter(metric_name, labels=None): increment a named counter.
  * get_metrics(): snapshot of all counters as a plain dict.

Phase 16 — Observability & Ops.
"""
from __future__ import annotations

import json
import logging
import sys
import threading
import time
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object.

    Standard fields always present:
        timestamp  – ISO-8601 UTC (seconds precision)
        level      – record level name (e.g. "INFO")
        logger     – record name
        message    – formatted message

    Any keyword arguments passed via the ``extra`` dict on the logging call
    are merged into the top-level JSON object so callers can add context:

        logger.info("arrival submitted", extra={"facility_id": "abc", "weight_kg": 42.0})
    """

    # Keys that exist on every LogRecord; we must not re-emit them as extras.
    _STANDARD_KEYS: frozenset[str] = frozenset(
        {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "thread", "threadName", "exc_info", "exc_text",
            "message", "taskName",
        }
    )

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        record.message = record.getMessage()
        obj: Dict[str, Any] = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }
        # Merge extra kwargs that the caller attached
        for key, value in record.__dict__.items():
            if key not in self._STANDARD_KEYS:
                obj[key] = value
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj, default=str)


def get_logger(name: str) -> logging.Logger:
    """Return a logger configured to write JSON lines to stderr.

    Calling ``get_logger`` multiple times with the same name is safe — the
    handler is only added once (idempotent).
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
    return logger


# ---------------------------------------------------------------------------
# In-memory metrics counters
# ---------------------------------------------------------------------------

_lock = threading.Lock()

_counters: Dict[str, Any] = {
    "requests_total": {},          # keyed by "METHOD /route"
    "arrivals_submitted_total": 0,
    "certificates_minted_total": 0,
    "fraud_flags_total": 0,
    "errors_total": 0,
}


def increment_counter(metric_name: str, labels: Optional[str] = None) -> None:
    """Increment a named metric counter.

    Args:
        metric_name: One of the keys in ``_counters``.
        labels:      Optional label string used as a sub-key for dict-valued
                     counters (e.g. ``requests_total`` keyed by route).
    """
    with _lock:
        if metric_name not in _counters:
            # Gracefully handle unknown metric names rather than crashing.
            _counters[metric_name] = 0
        current = _counters[metric_name]
        if isinstance(current, dict):
            key = labels or "__unlabeled__"
            current[key] = current.get(key, 0) + 1
        else:
            _counters[metric_name] = current + 1


def get_metrics() -> Dict[str, Any]:
    """Return a snapshot of all metrics counters."""
    with _lock:
        # Deep-copy the requests_total sub-dict so callers can't mutate state
        snapshot = dict(_counters)
        snapshot["requests_total"] = dict(_counters["requests_total"])
    return snapshot


def reset_metrics() -> None:
    """Reset all counters to zero (useful for testing)."""
    with _lock:
        _counters["requests_total"] = {}
        _counters["arrivals_submitted_total"] = 0
        _counters["certificates_minted_total"] = 0
        _counters["fraud_flags_total"] = 0
        _counters["errors_total"] = 0

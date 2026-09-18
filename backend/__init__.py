"""
VERITAS backend package.

All business logic lives in service.py. This package contains:
  crypto.py      — Ed25519 signature verification + canonical hash (Option B)
  database.py    — SQLite WAL, schema, atomic mint
  fraud.py       — capacity-ceiling, ghost-facility, circular-trucking checks
  ledger.py      — hash chain + Merkle tree verification
  service.py     — framework-independent business logic
  models.py      — Pydantic request/response models
  main.py        — FastAPI routes (thin — delegates to service.py)
  auth.py        — JWT roles + tenant isolation (Phase 11)
  audit_log.py   — append-only action log (Phase 0 stub, real in Phase 2)
  integrations/  — CPCB portal abstraction (Phase 12)
"""

# VERITAS — Architecture

> **VERITAS** — **V**erified **E**PR **R**ecycling with **I**ntegrity **T**amper-proof **A**rrival **S**ignatures
> Open-source community project.

**Status:** Phase 9 complete, Phase 10-12 in progress (2026-09-18). This document reflects the *actual built system*, not the aspirational pitch. If code and this doc conflict, fix the doc (or the code).

---

## Phase Completion Status

| Phase | Description | Key Modules / Artifacts | Status | Test Coverage / Verification |
|---|---|---|---|---|
| **Phase 0** | Scaffold & Repository Architecture | Repo layout, CI, configs, initial specs | **COMPLETE** | CI workflows, pre-commit, linters configured |
| **Phase 1** | Cryptographic Verification | `backend/crypto.py` (PyNaCl Ed25519 Option B) | **COMPLETE** | 9/9 tests pass (sig verify, tamper detect, round-trip) |
| **Phase 2** | Database & Atomic Minting | `backend/database.py` (SQLite WAL, atomic UPDATE) | **COMPLETE** | 12/12 tests pass (concurrency 20 threads, idempotent) |
| **Phase 3** | Fraud Detection Engine | `backend/fraud.py` (3 fail-closed checks) | **COMPLETE** | 8/8 tests pass (fire, no false-positive, fail-closed) |
| **Phase 4** | Transparency Ledger | `backend/ledger.py` (hash chain + Merkle tree) | **COMPLETE** | 10/10 tests pass (proof roundtrip, chain tampering) |
| **Phase 5** | Service & API Layer | `backend/service.py`, `backend/main.py`, `models.py` | **COMPLETE** | 10/10 tests pass (full E2E register-to-mint flow) |
| **Phase 6** | Gate Pod Firmware | `firmware/veritas_pod/veritas_pod.ino` | **COMPLETE** | ESP32 + HX711 + CAM + WolfSSL Ed25519 + signed OTA |
| **Phase 7** | Gate Pod Simulator | `scripts/simulate_pod.py` | **COMPLETE** | Live verified: legitimate mint, forged reject, over-cap flag |
| **Phase 8** | Operator & Auditor Dashboard | `dashboard/index.html` (zero-build static UI) | **COMPLETE** | Live verified: static mount at `/`, dynamic cert table |
| **Phase 9** | Test Suite Consolidation | `tests/` consolidated suite | **COMPLETE** | **49/49 tests pass in 0.33s** across all modules |
| **Phase 10** | System Documentation & Threat Model | `ARCHITECTURE.md`, `THREAT-MODEL.md` | **IN PROGRESS** | Reflects built implementation, attacks, hardware notes |
| **Phase 11** | AuthN/AuthZ & Multi-Tenancy | `backend/auth.py` (JWT roles, query isolation) | **IN PROGRESS** | Parallel subagent building; not yet in main branch |
| **Phase 12** | Regulator / CPCB Integration | `backend/integrations/cpcb_portal.py` | **IN PROGRESS** | Manual-export stub (JSON/CSV) ready; live API pending |

---

## System Overview

VERITAS refuses to mint an EPR recycling certificate unless a cryptographically signed, tamper-evident physical arrival record exists to back it. Every design decision flows from that one sentence.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        VERITAS System                               │
│                                                                     │
│  ┌──────────────┐   signed POST    ┌──────────────────────────────┐ │
│  │  Gate Pod    │ ──────────────→  │     Backend (FastAPI)         │ │
│  │  (ESP32 /    │                  │                               │ │
│  │  ESP32-CAM)  │                  │  main.py (routes only)        │ │
│  │              │                  │  service.py (business logic)  │ │
│  │  load cell   │                  │  crypto.py   ← verify sig     │ │
│  │  camera      │                  │  database.py ← atomic mint    │ │
│  │  HX711       │                  │  fraud.py    ← fraud checks   │ │
│  │  Ed25519 key │                  │  ledger.py   ← hash chain     │ │
│  └──────────────┘                  │  audit_log.py← append-only    │ │
│                                    │  auth.py     ← (Phase 11)     │ │
│  ┌──────────────┐                  └───────────────┬──────────────┘ │
│  │  simulate_   │ (no hardware demo)               │                │
│  │  pod.py      │ ─────────────────────────────────┘                │
│  └──────────────┘                  ┌──────────────────────────────┐ │
│                                    │   SQLite (WAL mode)          │ │
│  ┌──────────────┐                  │   → Postgres at scale        │ │
│  │  Dashboard   │ ← HTTP GET ────  │   Local/S3 storage for photos│ │
│  │  (static     │                  └──────────────────────────────┘ │
│  │   HTML/JS)   │                                                   │
│  └──────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Responsibilities

### `backend/crypto.py` (Phase 1)
**Crypto option chosen:** Option B — Software Ed25519 via PyNaCl.
- `verify_signature(public_key_hex, payload_bytes, signature_hex) → bool` — strictly returns `False` on any error or signature mismatch, never `True`.
- `canonical_hash(weight_kg, facility_id, timestamp_iso, photo_hash_hex, device_id) → bytes` — recomputes canonical SHA-256 hash using invariant field ordering:
  `f"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"`
- `generate_keypair() → tuple[str, str]` — helper to generate private/public keypair in hex.
- `sign_payload(private_key_hex, payload_bytes) → str` — signs arbitrary payload bytes with Ed25519 private key.
- All fields ordered and encoded identically to the firmware; field order is documented in both here and firmware code (`CANONICAL_FIELD_ORDER`).

> [!IMPORTANT]
> Option B means the Ed25519 key lives in firmware flash (with ESP32 flash encryption enabled via eFuse). Do NOT claim "hardware-backed" anywhere — that claim requires Option C (NXP SE050). For commercial deployment, upgrade to Option C.

### `backend/database.py` (Phase 2)
- SQLite in WAL mode (`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`).
- Schema: `facilities`, `arrivals`, `certificates` (with unique constraint on `arrival_id`), `audit_log`.
- `atomic_mint(db, arrival_id, facility_id, quantity_kg, waste_category) → dict | None`
  - Executes a single conditional update: `UPDATE arrivals SET used=1 WHERE id=? AND used=0`.
  - Checks `cursor.rowcount == 1`. If not 1 (already minted or concurrent race), aborts immediately with `None`.
  - Unique constraint on `(arrival_id)` in `certificates` is the backstop, not the primary defense.
  - Concurrency verified with 20 parallel threads racing against the same arrival record.
- `update_certificate_ledger_hash(db, cert_id, ledger_hash_hex)` — binds the certificate to the cryptographic hash chain.
- Query helpers: `get_facility()`, `get_arrival()`, `get_certificate()`, `get_arrivals_for_facility()`, `get_certificates_for_facility()`.

### `backend/fraud.py` (Phase 3)
- Fail-closed invariant (#14): Every check catches all exceptions at its outermost level and returns `FraudResult(flagged=True, reason="check_failed_closed")`. A check that cannot run is treated as flagged, never as a pass.
- `check_capacity_ceiling(db, facility_id, claimed_kg, period_start, period_end) → FraudResult`
  - Compares `existing_sum + claimed_kg > capacity_kg` across certificates in the period.
  - Flags `reason="capacity_exceeded"` to prevent overclaiming (e.g. 38× capacity fraud).
- `check_ghost_facility(db, facility_id, period_start, period_end, min_arrival_ratio=0.1) → FraudResult`
  - Flags `reason="ghost_facility"` if certificates exist with 0 arrivals.
  - Flags `reason="low_arrival_ratio"` if `arrivals / certificates < min_arrival_ratio`.
- `check_circular_trucking(db, device_id, current_timestamp_iso, window_hours=4.0) → FraudResult`
  - Flags `reason="circular_trucking"` if the same device has an already consumed (`used=1`) arrival within the look-back window.
- `run_all_checks(db, facility_id, claimed_kg, device_id, timestamp_iso, period_start, period_end) → list[FraudResult]` — runs all three checks safely.

### `backend/ledger.py` (Phase 4)
- **Hash chain:**
  - `certificate_bytes(cert) → bytes` — canonical UTF-8 representation: `f"{id}|{arrival_id}|{facility_id}|{quantity_kg:.6f}|{waste_category}|{minted_at}"`.
  - `hash_chain_entry(previous_hash, cert) → bytes` — computes `SHA-256(previous_hash || certificate_bytes)`.
  - `append_to_chain(db, cert) → str` — appends certificate to chain and updates database ledger hash.
  - `verify_chain(db, from_id, to_id) → bool` — traverses sequential entries and detects retroactive alterations.
- **Merkle tree:**
  - `build_merkle_tree(leaf_hashes)` — binary SHA-256 tree supporting odd, even, and single-leaf counts.
  - `get_merkle_proof(leaves, index)` / `verify_merkle_proof(leaf_hash, proof, root_hash) → bool` — compact inclusion verification.
  - `get_certificate_proof(db, cert_id) → dict` — returns Merkle proof, leaf hash, Merkle root, and validates both Merkle root inclusion AND hash-chain predecessor continuity (`valid = proof_valid and chain_hash_valid`).

### `backend/service.py` (Phase 5)
- Framework-independent business logic; no FastAPI or HTTP imports.
- Functions take plain Python types and return typed `ServiceResult` dataclasses (`success`, `data`, `error`, `status`).
- Orchestrates the full lifecycle:
  - `register_facility(...)`
  - `submit_arrival(...)` — validates hash, verifies Ed25519 signature, runs circular trucking check, records arrival, logs audit trail.
  - `mint_certificate(...)` — validates arrival existence and unused state, executes capacity ceiling and ghost facility checks. If flagged, sets status to `"flagged_for_review"` and aborts minting without consuming the arrival. If clear, executes `atomic_mint()`, commits to `ledger.append_to_chain()`, and records audit log.
  - `verify_certificate(...)` — delegates to `ledger.get_certificate_proof()`.
  - `get_facility_status(...)` — aggregates total arrivals, certificates, and capacity utilization.

### `backend/main.py` (Phase 5, updated Phase 8)
- Thin route handlers (≤ 10 lines per handler) wrapping `service.py`.
- Endpoints:
  - `GET /` — serves `dashboard/index.html` directly.
  - `GET /health` — health probe confirming server availability.
  - `POST /facilities` — register facility with device public key.
  - `GET /facilities/{facility_id}` & `GET /facilities/{facility_id}/status` — facility details and operational status.
  - `POST /arrivals` — ingest signed gate-pod arrival record.
  - `GET /arrivals?facility_id=&period_start=&period_end=` — query arrivals for a facility.
  - `POST /certificates/mint` — trigger certificate minting pipeline.
  - `GET /certificates/{cert_id}/verify` — cryptographic Merkle + chain verification.
  - `GET /certificates?facility_id=&period_start=&period_end=` — query minted certificates.
- Static file serving mounted at `/dashboard` for dashboard assets.

### `backend/models.py` (Phase 5)
- Pydantic v2 schemas: `FacilityCreate`, `FacilityResponse`, `ArrivalSubmit`, `ArrivalResponse`, `MintRequest`, `MintResponse`, `LedgerVerifyResponse`, `HealthResponse`, `WasteCategoryEnum`.
- Strict input validation; no business logic or database dependencies.

### `backend/audit_log.py` (Phase 2 / Phase 5)
- Append-only audit trail table; no `UPDATE` or `DELETE` ever issued.
- `log_action(db, action, actor, result, target_id=None, detail=None)` — appends immutable record. Never raises (logs failures to stderr) to protect core transaction flow while preserving attribution.
- `get_audit_trail(db, target_id=None, action=None, limit=100)` — queryable audit history.

### `firmware/veritas_pod/veritas_pod.ino` (Phase 6)
- Embedded firmware for ESP32 + HX711 load cell + ESP32-CAM.
- Constructs canonical hash matching `backend/crypto.py` field order and encoding exactly.
- Signs arrival records via WolfSSL Ed25519 (Option B) and transmits via HTTPClient POST.
- Features signed OTA update handler (`ArduinoOTA` with verification) enforcing Invariant #11.

### `scripts/simulate_pod.py` (Phase 7)
- Hardware-free simulation and demonstration CLI script.
- Submits three arrival scenarios to a live server:
  1. Legitimate arrival → minted successfully (`status: "minted"`).
  2. Forged-signature arrival → rejected at ingestion (HTTP 400).
  3. Over-capacity arrival → flagged by fraud engine (`status: "flagged_for_review"`).

### `dashboard/index.html` (Phase 8)
- Zero-build static HTML/JavaScript single-page application.
- Real-time facility metrics, arrivals log, minted certificates table, fraud flags visualization, and interactive certificate verification against `/certificates/{cert_id}/verify`.

### `backend/auth.py` *(Phase 11 — IN PROGRESS)*
- **Status: NOT YET BUILT** (currently being developed in Phase 11).
- JWT-based authentication with role-based permissions: `facility_operator`, `veritas_admin`, `regulator_auditor`.
- Tenant isolation enforced at the database query layer, preventing cross-facility data leaks even if route decorators are bypassed.

### `backend/integrations/cpcb_portal.py` *(Phase 12 — STUBBED)*
- **Status: STUBBED (EXPORT-ONLY)**.
- Provides `export_certificates_json()` and `export_certificates_csv()` formatted for manual upload to CPCB's centralized portal.
- **Honest status:** No live CPCB API integration exists today because CPCB has not published a public API. Live API synchronization is deferred until the regulatory portal supports automated endpoints.

---

## Data Flow — Arrival → Certificate

```
Gate Pod (or simulate_pod.py)
  │ weight_kg, photo_hash_hex, timestamp_iso, facility_id, device_id
  │ → canonical_hash() in firmware → Ed25519 sign
  │
  ▼ POST /arrivals {weight_kg, photo_hash_hex, timestamp_iso,
                    facility_id, device_id, record_hash_hex, signature_hex}
Backend (service.submit_arrival)
  1. crypto.canonical_hash(fields) → recompute hash server-side
  2. assert recomputed == submitted record_hash_hex                 [INVARIANT #2]
  3. crypto.verify_signature(device_pubkey, hash_bytes, sig)        [INVARIANT #1]
  4. fraud.check_circular_trucking(device_id, timestamp)            [INVARIANT #4]
  5. db.insert_arrival(..., fraud_flags)
  6. audit_log.log_action("arrival_submitted", ...)
  → 201 Created {arrival_id, record_hash_hex, ...}

  POST /certificates/mint {arrival_id, quantity_kg, waste_category}
Backend (service.mint_certificate)
  1. db.get_arrival(arrival_id) → assert exists and used == 0
  2. fraud.check_capacity_ceiling(facility_id, claimed_kg, period)  [INVARIANT #4]
  3. fraud.check_ghost_facility(facility_id, period)                [INVARIANT #4]
  4. If any fraud check flagged or failed closed:
       audit_log.log_action("cert_mint_flagged", ...)
       return {status: "flagged_for_review", reason: ...}          [INVARIANT #14]
       (DOES NOT MINT, arrival remains used=0 for review)
  5. db.atomic_mint(arrival_id, ...)                                [INVARIANT #3 — conditional UPDATE WHERE used=0]
  6. ledger.append_to_chain(certificate)                            [INVARIANT #5]
  7. db.update_certificate_ledger_hash(cert_id, chain_hash)
  8. audit_log.log_action("cert_minted", ...)
  → 200 OK {status: "minted", certificate: {certificate_id, ledger_hash_hex, ...}}
```

---

## Database Schema (SQLite, WAL mode)

```sql
CREATE TABLE facilities (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    capacity_kg REAL NOT NULL,   -- registered max per period
    waste_category TEXT NOT NULL,
    pubkey_hex  TEXT NOT NULL,   -- device Ed25519 public key
    created_at  TEXT NOT NULL
);

CREATE TABLE arrivals (
    id              TEXT PRIMARY KEY,
    facility_id     TEXT NOT NULL REFERENCES facilities(id),
    device_id       TEXT NOT NULL,
    weight_kg       REAL NOT NULL,
    photo_hash_hex  TEXT NOT NULL,
    timestamp_iso   TEXT NOT NULL,
    record_hash_hex TEXT NOT NULL,
    signature_hex   TEXT NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,  -- 0=unused, 1=minted
    fraud_flags     TEXT,                         -- JSON array of flag names
    submitted_at    TEXT NOT NULL
);

CREATE TABLE certificates (
    id              TEXT PRIMARY KEY,
    arrival_id      TEXT NOT NULL UNIQUE REFERENCES arrivals(id),
    facility_id     TEXT NOT NULL REFERENCES facilities(id),
    quantity_kg     REAL NOT NULL,
    waste_category  TEXT NOT NULL,
    ledger_hash_hex TEXT NOT NULL,
    minted_at       TEXT NOT NULL
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    actor       TEXT NOT NULL,
    target_id   TEXT,
    result      TEXT NOT NULL,  -- 'success' | 'rejected' | 'flagged' | 'error'
    detail      TEXT,           -- JSON
    created_at  TEXT NOT NULL
);
```

---

## Tech Stack

| Layer | Choice | Notes |
|---|---|---|
| Backend | Python 3.11+ + FastAPI + Pydantic v2 | Thin route handlers over framework-independent `service.py` |
| Crypto | PyNaCl (Ed25519) — Option B | Software signing with ESP32 flash encryption; Option C (NXP SE050) for production |
| Database | SQLite in WAL mode | Tested with 20 concurrent worker threads; migrates to PostgreSQL in Phase 18 |
| Ledger | In-house SHA-256 Hash Chain & Merkle Tree | Provides inclusion proofs and tampering verification |
| Firmware | ESP32, Arduino framework, HX711, ESP32-CAM | WolfSSL Ed25519 signing, canonical hash matching, signed OTA |
| Simulator | Python CLI (`simulate_pod.py`) | E2E testing of legitimate, forged, and fraud scenarios |
| Dashboard | Zero-build static HTML/JS | Real-time operations and verification interface served directly at `/` |
| Ops | Docker (`ops/Dockerfile`), Compose | Containerized service and automated health checks |
| CI | GitHub Actions | Linters, type checks, and 49/49 unit/integration/concurrency tests |

---

*Last updated: Phase 9 complete, Phase 10-12 in progress — 2026-09-18*

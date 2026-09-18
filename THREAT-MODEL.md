# VERITAS — Threat Model

> **VERITAS** — **V**erified **E**PR **R**ecycling with **I**ntegrity **T**amper-proof **A**rrival **S**ignatures
> Open-source community project.

**Status:** Phase 9 complete, Phase 10 updated (2026-09-18). Updated to reflect the fully built Phase 0–9 implementation: Option B Ed25519 cryptography, ESP32 flash-encryption threat analysis, fail-closed fraud detection engine (circular trucking, ghost facility, 38× capacity overclaiming), hash-chain / Merkle ledger proofs, and append-only audit logging.

---

## Assets Being Protected

1. **Certificate integrity** — a minted EPR recycling certificate must represent a real, verified physical arrival backed by cryptographic proof.
2. **Double-spend prevention** — each physical arrival record can back exactly one certificate; duplicate or replay minting is strictly prevented.
3. **Fraud detection coverage** — the system must actively detect, flag, and halt known industrial attack patterns (capacity overclaiming, ghost facilities, circular trucking).
4. **Audit trail immutability** — every certificate-relevant action (arrival submission, mint attempt, fraud flag, verification) must be attributable and irrefutable.
5. **Device key confidentiality** — an attacker possessing the gate-pod private signing key can forge arbitrary arrivals; key extraction vectors must be defended against.

---

## Trust Boundaries

```
[Untrusted] Gate pod device / network
    │
    ▼ (Boundary: canonical SHA-256 hash recompute + Ed25519 signature verification)
[Trusted] Backend service.py
    │
    ▼ (Boundary: fail-closed fraud engine: circular trucking, capacity ceiling, ghost facility)
[Trusted] Fraud engine & database.py
    │
    ▼ (Boundary: atomic conditional UPDATE arrivals SET used=1 WHERE id=? AND used=0)
[Trusted] certificates table
    │
    ▼ (Boundary: sequential SHA-256 hash chain + binary Merkle tree commitment)
[Trusted] ledger.py & append-only audit_log table
```

All data arriving from a gate pod or external client is **untrusted until Invariants #1 and #2 are satisfied** — the canonical hash is independently recomputed server-side and matched against `record_hash_hex`, and the Ed25519 signature is verified against the facility's registered public key.

---

## Attack Surface & Mitigations

### A1 — Forged Arrival & Device Key Extraction (Firmware Flash-Encryption Note)
**Threat:** A fraudulent recycler attempts to mint certificates by submitting fabricated arrival records (inflated weights, fictional truck arrivals, or non-existent recycling batches).

**Mitigation (Invariants #1 & #2):**
- The gate device captures physical weight (HX711 load cell), camera photo hash, and timestamp, and computes a canonical SHA-256 hash formatted as:
  `"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"`
- The device signs this hash with its Ed25519 private key.
- The backend independently reassembles the canonical string, recomputes the SHA-256 hash, checks exact match against `record_hash_hex`, and verifies the signature using `crypto.verify_signature(pubkey_hex, hash_bytes, sig_hex)`.
- Forged payloads without the private key fail at ingestion with HTTP 400.

**Physical Key Extraction & ESP32 Flash Encryption:**
- **Option B Architecture:** In the current implementation (Option B — Software Ed25519 via PyNaCl on backend and WolfSSL on ESP32), the private key resides in ESP32 non-volatile SPI flash memory.
- **Physical Attack Vector:** Without protection, an adversary with physical access to the gate pod can connect to the UART bootloader, attach a JTAG probe, or desolder the SPI flash chip to dump the firmware binary and extract the raw Ed25519 private key. Once extracted, the attacker could synthesize valid arrival signatures from anywhere.
- **Required Production Hardening:** In production deployments using Option B, **ESP32 Flash Encryption (AES-XTS-256)** must be enabled during factory provisioning by burning cryptographic keys into hardware eFuses (`BLOCK4` through `BLOCK7`), combined with **Secure Boot v2**. Furthermore, hardware eFuses must be burned to permanently disable the UART bootloader download mode and JTAG pins. This renders the flash unreadable via external bus monitoring or extraction probes.
- **Commercial Upgrade Path (Option C — NXP SE050):** While Option B with flash encryption is secure for prototype and controlled pilot deployments, the recommended commercial upgrade is **Option C (NXP SE050 Secure Element via I²C)**. With Option C, the private key is generated inside a tamper-resistant EAL6+ certified secure element and never leaves silicon under any circumstances, eliminating physical flash-dump risk entirely.

---

### A2 — Double-Spend / Concurrency Race Condition
**Threat:** A recycler attempts to submit simultaneous or rapid-fire mint requests against the same arrival record, attempting to generate multiple certificates from a single truckload.

**Mitigation (Invariants #3 & #6):**
- Handled at the database level using a single atomic conditional statement:
  ```sql
  UPDATE arrivals SET used = 1 WHERE id = ? AND used = 0;
  ```
- The database engine checks `cursor.rowcount == 1`. If two concurrent requests race to mint against the same arrival, exactly one succeeds and obtains `rowcount == 1`; the competing request receives `rowcount == 0` and is immediately aborted with `None`.
- The `certificates` table enforces a database-level `UNIQUE (arrival_id)` constraint as an independent backstop.
- Concurrency safety is continuously verified in CI by `test_atomic_mint_concurrency`, which launches 20 concurrent threads racing to mint the same arrival.

---

### A3 — Capacity Inflation (Ghost Tonnage) & The 38× CPCB Overclaiming Case
**Threat:** A recycling facility claims processing volumes far beyond its physical capabilities, generating fictitious EPR credits for sale to Brand Owners / PIBOs.

**Real-World Precedent:**
In major regulatory enforcement cases documented by the Central Pollution Control Board (CPCB) and State Pollution Control Boards (e.g. widespread plastic EPR fraud investigations), fraudulent recycling facilities were caught issuing EPR certificates up to **38× their registered annual processing capacity**. These facilities operated minimal machinery but generated vast quantities of fictitious certificates to meet compliance demands from commercial producers.

**Mitigation (Invariants #4 & #14):**
- Mitigated by `fraud.check_capacity_ceiling(db, facility_id, claimed_kg, period_start, period_end)`:
  - When a certificate mint is requested, the system computes:
    ```
    existing_sum + claimed_kg > capacity_kg
    ```
    where `existing_sum` is the aggregate `quantity_kg` of all certificates previously minted for `facility_id` in the accounting period `[period_start, period_end]`.
  - If the new claim would push cumulative tonnage above `capacity_kg`, the check flags `reason="capacity_exceeded"` and populates diagnostic details (`capacity_kg`, `claimed_kg`, `existing_sum_kg`, `utilization_pct`).
  - In `backend/service.py`, any flagged result halts the minting pipeline immediately, records `cert_mint_flagged` in the audit log, and returns `status="flagged_for_review"`. Automated minting is blocked, and the arrival remains unminted (`used = 0`) until cleared by a human regulatory auditor.
  - The check adheres to Invariant #14 (fail-closed) and defaults to `flagged=True` on any database error.

---

### A4 — Ghost Facility Attack (Paper-Only Recyclers)
**Threat:** A shell corporation registers on regulatory portals as a recycling entity, generating and selling EPR credits without maintaining any physical recycling facility or handling actual waste.

**Real-World Precedent:**
Audits by environmental regulators have repeatedly uncovered "ghost facilities" — entities possessing an official registration certificate, tax identification, and portal account, but when inspected physically, consist of empty warehouses, vacant lots, or closed storefronts with zero physical machinery and zero truck deliveries.

**Mitigation (Invariants #4 & #14):**
- Mitigated by `fraud.check_ghost_facility(db, facility_id, period_start, period_end, min_arrival_ratio=0.1)`:
  - Analyzes the correlation between certificates generated and verified gate-pod arrival records in `arrivals`:
    1. **Condition 1 (Zero Arrivals):** If `certificates > 0` and `arrivals == 0`, the facility is immediately flagged with `reason="ghost_facility"`.
    2. **Condition 2 (Disproportionate Issuance):** If `certificates > 0` and `arrivals / certificates < min_arrival_ratio` (default threshold 10%), the check flags `reason="low_arrival_ratio"`.
  - A facility with zero certificates is not flagged (no claim = no fraud).
  - In `service.py`, flagged facilities are prevented from minting, and the event is written to `audit_log`.
  - Fails closed (`check_failed_closed`) on any database or computation exception.

---

### A5 — Circular Trucking Attack Pattern
**Threat:** A single truck or hauler colludes with a facility operator to make repeated full-load recycling claims within an impossibly short time window.

**Attack Pattern Mechanics:**
In this loop-and-reweigh scheme:
1. A truck loaded with recyclable plastic enters the facility gate.
2. The gate pod weighs the truck (e.g. 15,000 kg gross weight), captures a photo, and the record is signed and minted into an EPR certificate.
3. Rather than unloading and processing the material, the truck exits the gate, drives around the perimeter or loops the block, and re-enters the gate scale 15–45 minutes later with the exact same physical material.
4. The operator attempts to log a second full arrival and mint a second certificate.
5. In advanced variants, a small portion of the load is shuffled between vehicles, or water ballast is pumped between compartments to alter gross weights slightly while recycling the same core volume.

**Mitigation (Invariants #4 & #14):**
- Mitigated during arrival ingestion by `fraud.check_circular_trucking(db, device_id, current_timestamp_iso, window_hours=4.0)`:
  - When an arrival record is submitted via `service.submit_arrival()`, the engine queries the database for any arrival associated with that `device_id` (or vehicle identifier) where:
    - `used = 1` (the arrival was already consumed for a minted certificate), AND
    - `timestamp_iso` falls within the look-back window `[current_timestamp - window_hours, current_timestamp]` (default 4.0 hours).
  - If a used arrival exists within the look-back window, it flags `reason="circular_trucking"` with details containing the conflicting arrival's timestamp and the calculated `hours_since`.
  - The arrival is saved to the database with `fraud_flags = '["circular_trucking"]'`, logged in `audit_log`, and `service.mint_certificate()` prevents certificate issuance against any arrival bearing fraud flags.
  - Fails closed on any error (`reason="check_failed_closed"`).
  - **Phase 14 Hardening:** Future Phase 14 will enhance this check by incorporating GPS geofencing from driver companion apps and Automatic Number Plate Recognition (ANPR) from the gate camera photos, calculating minimum transit times between origin and disposal points.

---

### A6 — Data Tampering in Transit & Retroactive Ledger Modification
**Threat:**
- *In-transit:* An attacker intercepts an arrival POST, modifies the weight or timestamp to increase credit value, and forwards the packet.
- *Post-storage:* An insider or attacker with direct database access modifies historical rows in the `certificates` table (e.g., altering `quantity_kg` from 500 to 5,000).

**Mitigation (Invariants #2 & #5):**
- **In-transit:** Invariant #2 recomputes the canonical SHA-256 hash server-side from raw fields (`weight_kg`, `facility_id`, `timestamp_iso`, `photo_hash_hex`, `device_id`). If any field is altered in transit, the recomputed hash fails to match `record_hash_hex`. Furthermore, any signature generated over the altered payload will fail Ed25519 verification.
- **Post-storage (Transparency Ledger):**
  - Every minted certificate is appended to an append-only SHA-256 hash chain (`ledger_hash = SHA-256(prev_hash || cert_canonical_bytes)`).
  - Certificates are committed to a binary Merkle tree.
  - `GET /certificates/{cert_id}/verify` runs `ledger.get_certificate_proof()`, which validates both the Merkle inclusion proof against the tree root AND verifies that the certificate's `ledger_hash_hex` correctly chains from its predecessor.
  - Modifying any historical certificate in SQLite breaks the hash chain for all subsequent certificates and invalidates the Merkle root.

---

### A7 — Replay Attack
**Threat:** An attacker captures a valid, signed arrival transmission from the gate pod and replays it over HTTP to obtain duplicate certificates.

**Mitigation:**
- Every arrival has a unique UUID `arrival_id`.
- Replaying the identical packet with the same `arrival_id` causes `database.insert_arrival` to fail (or if already recorded, `atomic_mint` encounters `used = 1` and aborts).
- If an attacker strips or alters the `arrival_id` while keeping payload fields identical, `service.submit_arrival` tracks existing timestamps and hashes.
- Combined with `check_circular_trucking()`, rapid replays trigger immediate fraud flags.

---

### A8 — Compromised OTA Firmware Update
**Threat:** An attacker pushes malicious firmware to the ESP32 gate pod to bypass weight checks, spoof sensor values, or sign fraudulent data directly at the source.

**Mitigation (Invariant #11):**
- Firmware (`firmware/veritas_pod/veritas_pod.ino`) implements `ArduinoOTA` with signed update verification and cryptographic hash checks (`Update.setMD5()`).
- In production, firmware updates must be cryptographically signed by the VERITAS release private key. Unsigned or corrupted binaries are rejected by the bootloader before flash memory is overwritten.

---

### A9 — Insider Threat / Cross-Tenant Data Access
**Threat:** An authenticated facility operator attempts to view, manipulate, or mint certificates belonging to a competing recycling facility.

**Mitigation (Invariant #9 — Phase 11):**
- Multi-tenancy isolation is enforced at the database query layer, not merely at route-level decorators.
- Every database read and write query is explicitly scoped to the authenticated tenant's `facility_id` extracted from their validated JWT token.
- Route handlers cannot accidentally leak data across facilities because service and database methods require explicit tenant bounding.

---

### A10 — Fraud Engine Silent Failure (Fail-Closed Contract)
**Threat:** An internal component of the fraud detection engine crashes (e.g. database lock, disk full, missing column, arithmetic overflow), and the system defaults to "allow", issuing a certificate without verification.

**Mitigation (Invariant #14):**
- **Fail-Closed Contract:** Every public fraud check function in `backend/fraud.py` (`check_capacity_ceiling`, `check_ghost_facility`, `check_circular_trucking`) wraps its entire execution block in an outer `except Exception:` handler.
- Under any error condition, the function returns:
  ```python
  FraudResult(flagged=True, reason="check_failed_closed")
  ```
- A check that cannot run is treated identically to a check that detected fraud.
- `service.mint_certificate()` checks `result.flagged` on all checks and aborts minting if any check is flagged, ensuring no certificate is ever minted during a system failure.

---

### A11 — Secrets in Source Control or Log Dumps
**Threat:** Private keys, database credentials, or API keys are committed to git repositories or printed to server application logs.

**Mitigation (Invariant #10):**
- Private keys are generated on-device or provided via environment variables (`.env`), which are excluded by `.gitignore`.
- Pre-commit hooks (`detect-private-key`, `bandit`) scan commits for key patterns and credentials.
- Application loggers and `audit_log.py` explicitly exclude private key strings and sensitive token bodies.

---

### A12 — Audit Trail Repudiation & Deletion
**Threat:** A corrupt facility operator or administrator attempts to erase evidence of rejected arrivals or fraud flags.

**Mitigation (Invariant #8):**
- All lifecycle events (`facility_registered`, `arrival_submitted`, `arrival_rejected`, `cert_mint_flagged`, `cert_minted`, `cert_verified`) are recorded in an append-only `audit_log` table.
- No `UPDATE` or `DELETE` statements are ever issued against the `audit_log` table.
- `audit_log.log_action()` never raises an exception to ensure logging failures cannot be exploited to induce unhandled application states.

---

## What This Threat Model Does Not (Yet) Cover

The following attack vectors are recognized and scheduled for hardening in subsequent phases:

- **Cross-Facility Collusion:** Multiple independent facility registrations owned by the same cartel rotating trucks between facilities to evade single-facility capacity ceilings (Phase 3 extension / Phase 14).
- **GPS-Backed Circular Trucking:** Hardware GPS verification on gate pods and transit trucks to detect out-of-route travel or impossibly fast journeys (Phase 14).
- **Computer-Vision Material Classification:** Verifying whether the truck load visually matches the declared waste category (e.g., verifying PET vs. HDPE, or detecting concrete ballast hidden under plastic flakes) — scheduled for Phase 13.
- **Automated Number Plate Recognition (ANPR):** Machine-vision extraction of vehicle license plates from gate camera photos to replace manual vehicle ID reporting — scheduled for Phase 14.
- **DDoS & Ingestion Rate-Limiting:** High-frequency HTTP request flooding on the ingestion endpoint — scheduled for Phase 12 (Invariant #12).
- **Data Protection Regulations (DPDP Act):** Handling of driver facial imagery and vehicle plate numbers under India's Digital Personal Data Protection Act — scheduled for Phase 17.

---

*Last updated: Phase 9 complete, Phase 10 updated — 2026-09-18*

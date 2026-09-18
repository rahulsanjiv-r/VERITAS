# VERITAS — Build Instructions

> **VERITAS** — **V**erified **E**PR **R**ecycling with **I**ntegrity **T**amper-proof **A**rrival **S**ignatures
> Open-source community project.

This is the phase-by-phase execution plan for VERITAS. `SKILL.md` is the standing set of invariants — read it first, and treat every phase's "definition of done" as a subset of that file's checklist, never a substitute for it. `COMMERCIAL_ROADMAP.md` is the "why" and "what else is possible" companion to this "how, in order" document.

Phases 0–10 are the working-prototype core. Phases 11–20 are the commercial-hardening layer — do these once the core is solid and tested, not in parallel with it. Don't skip ahead to phase 15 with phase 3 still stubbed; a commercial auth layer around a fake fraud check is worse than no auth layer, because it looks finished.

> **Note on this rewrite:** the previous BUILD_INSTRUCTIONS.md upload didn't come through as build instructions — what arrived in this conversation was pasted transcript text describing prior work, not the actual phase plan. This version is written fresh from `SKILL.md`'s invariants and repo layout (which did come through intact) plus the research below. If you have the original file, diff it against this one and fold back anything phase-specific it had that this version is missing.

---

## Phase 0 — Scaffold

- Create the repo layout exactly as `SKILL.md` specifies, including `AGENTS.md`, `CONTRIBUTING.md`, and `.github/PULL_REQUEST_TEMPLATE.md` — don't defer contributor onboarding to "later," since every subsequent phase is a PR that should already be using the template.
- Set up `pre-commit` with `black`/`ruff`/`mypy` referenced in `CONTRIBUTING.md`, and a CI workflow (GitHub Actions or equivalent) that runs lint, type-check, and the full test suite — including the concurrency test — on every PR, once Phase 2 exists to give it something to test.
- `ARCHITECTURE.md` and `THREAT-MODEL.md` get real first drafts here, even if thin — they get filled in as later phases add fraud checks and integrations.
- Definition of done: repo builds, `pytest` runs (even with zero tests), FastAPI app boots and serves a health check, and a trivial PR against the new template actually renders the checklist.

## Phase 1 — Crypto (`crypto.py`)

- Make the Option A/B/C decision from `SKILL.md` explicit in the docstring before writing a single line.
- Implement `verify_signature` for real — no stub, no default-true path.
- Implement canonical hash reconstruction that exactly matches what the firmware will produce (agree on field order, encoding, and separators *before* writing firmware).
- Cross-language round-trip test: sign a payload in the target firmware language/library, verify in Python; sign in Python, verify in the firmware library. Both directions, not just one.
- Definition of done: `test_crypto.py` covers a valid signature, a forged signature (must reject), a tampered-payload-with-valid-signature-on-different-data case (must reject via hash mismatch before even checking the signature), and the cross-language round trip.

## Phase 2 — Database & atomic mint (`database.py`)

- SQLite, WAL mode, real schema (facilities, arrivals, certificates, used-flag).
- The mint operation is a single conditional `UPDATE arrivals SET used = 1 WHERE id = ? AND used = 0`, checked for rows-affected == 1, wrapped so a unique constraint on (arrival_id) in the certificates table is a backstop, not the primary defense.
- Definition of done: `test_database.py` includes a real concurrency test — spawn multiple threads/processes racing to mint against the same arrival record, assert exactly one succeeds, run it more than once to catch flaky races.

## Phase 3 — Fraud checks (`fraud.py`)

- Capacity-ceiling: reject/flag when a facility's cumulative claimed tonnage for the period exceeds its registered capacity.
- Silence-vs-claim / ghost-facility: flag facilities generating certificates with no or disproportionately low matching arrival activity.
- Circular-trucking: flag a plate/device reappearing full-load within an implausibly short window.
- Definition of done: each check has one test proving it fires on bad data and one proving it doesn't false-positive on legitimate data, using real inserted rows — not mocked function returns.

## Phase 4 — Transparency ledger (`ledger.py`)

- Hash chain and/or Merkle tree over certificates; a verify endpoint that does real cryptographic verification, not an echo.
- Definition of done: `test_ledger.py` covers odd, even, and single-leaf tree sizes, a valid-proof case, and a tampered-record case that must fail verification.

## Phase 5 — Service & API layer (`service.py`, `main.py`, `models.py`)

- `main.py` stays thin — routes call into `service.py`; every route handler is a few lines.
- Endpoints: register facility, submit arrival, mint certificate, list arrivals, verify ledger entry, facility status.
- Definition of done: `test_service_e2e.py` runs register → arrive → mint → double-spend rejected → forged signature rejected → capacity flag trips → Merkle proof verifies, end to end, against a real (temp-file) SQLite DB — not entirely mocked.

## Phase 6 — Firmware

- Load cell read (HX711), photo capture, canonical hash construction matching `crypto.py` exactly, signing per the Option A/B/C decision, POST to the backend.
- OTA update path is signed and verified before flashing (commercial invariant #11 — worth building in from the start even in the prototype, since retrofitting signed OTA onto deployed devices later is painful).
- Definition of done: firmware compiles for the target board; if no hardware is available in the sandbox, say so explicitly and note it as syntax-checked only.

## Phase 7 — Device simulator (`scripts/simulate_pod.py`)

- Signs and posts a legitimate arrival, a forged-signature arrival, and an over-capacity arrival, so the whole flow demos without hardware.
- Definition of done: running the script against a local server produces one successful mint, one rejected forgery, and one fraud-flagged (or rejected, per the chosen policy) over-capacity submission — verified live, not just asserted in a test.

## Phase 8 — Dashboard

- Zero-build static HTML/JS hitting the FastAPI endpoints directly: live arrivals, certificates, fraud flags, ledger status.
- Definition of done: loads and updates against a running backend with no build step.

## Phase 9 — Test suite consolidation

- Run the full suite together, including the concurrency test, and confirm nothing in a later phase silently broke an earlier invariant.
- Definition of done: green suite, and the "definition of done" checklist in `SKILL.md` walked through explicitly, not assumed.

## Phase 10 — Docs

- `ARCHITECTURE.md` reflects the actual built system, not the original pitch.
- `THREAT-MODEL.md` includes circular-trucking and any attack pattern discovered during Phase 3/7 testing.
- Definition of done: a new reader (or a judge) can understand the system and its guarantees from the docs alone, without reading the code.

---

## Phase 11 — AuthN/AuthZ & multi-tenancy (`auth.py`)

- Roles: facility operator, TrustPod admin, read-only regulator/auditor.
- Tenant isolation: a facility operator token must not be able to read or affect another facility's rows — enforce this at the query layer, not just the route layer, so a missed `@requires_role` decorator can't leak data.
- Definition of done: `test_auth.py` proves cross-tenant access is rejected (not just "not shown in the UI"), and that each role can do only what it should.

## Phase 12 — Regulator/government integration layer (`integrations/cpcb_portal.py`)

- Abstract the CPCB centralized portal behind an interface — there may be no public API to integrate against yet, in which case this phase produces a well-defined export format (CSV/JSON matching whatever the portal's manual-upload schema is) rather than a live integration.
- QR/barcode generation compliant with the January 2025 packaging-marking rule, if the product is issuing packaging-level identifiers rather than only facility-level certificates.
- Audit-export endpoints for SPCB/CPCB auditors: a role-scoped, read-only export of arrivals/certs/fraud-flags for a date range.
- Definition of done: the export format is documented in `ARCHITECTURE.md` with an explicit note on what's live-integrated vs. manual-export-only, so the pitch never overstates this.

## Phase 13 — Computer-vision waste verification

- Classify the photographed load against the claimed waste category (plastic type, or contamination in an e-waste/metal load) as a secondary check layered on top of the weight-based fraud checks.
- Start with a narrow, well-defined classification task (e.g., "does this look like the declared material category") rather than open-ended waste identification — scope creep here burns a lot of time for uncertain fraud-detection value.
- Definition of done: the check runs against a labeled test set of photos (even a small one) with a measured false-positive/false-negative rate documented, not just "it works on the demo photos."

## Phase 14 — Circular-trucking / vehicle tracking hardening

- If the device or a companion mobile app can capture GPS at weigh-in, cross-reference plate + timestamp + location to strengthen the circular-trucking check from Phase 3.
- Automatic number-plate recognition (ANPR) on the arrival photo is a reasonable stretch goal here, not a Phase 3 requirement.
- Definition of done: an explicit test simulating the loop-and-reweigh pattern (same plate, short window, full load both times) trips the check with location data available, and degrades gracefully (falls back to Phase 3's plate+timestamp-only check) when it isn't.

## Phase 15 — Mobile companion app

- For facility staff without desktop access and for field auditors who need to scan a device/QR and pull a verification proof on-site.
- Don't introduce a new mobile framework mid-project without checking what the user's already comfortable with.
- Definition of done: an auditor can, from the app, look up a certificate and see its Merkle proof and the underlying arrival record's signature status — the same evidence the dashboard shows, just field-portable.

## Phase 16 — Observability & ops

- Structured logging across backend and firmware-facing ingestion; metrics on arrival rate, mint rate, fraud-flag rate, and device silence per facility; alerting when a facility goes quiet or fraud flags spike.
- Definition of done: a simulated fraud-flag spike (script-driven) actually triggers a visible alert, not just a log line nobody reads.

## Phase 17 — Security hardening & compliance posture

- Secrets management (vault/KMS, never in source or env dumps committed anywhere).
- TLS everywhere; rate limiting on ingestion endpoints, independent of request-signing.
- Data minimization and a stated retention period for photos/plate numbers, framed against India's Digital Personal Data Protection Act, 2023.
- A documented (not necessarily certified yet) path toward ISO/IEC 27001 and SOC 2 Type II — enterprise PIBOs and government counterparties will ask.
- Definition of done: a written security posture doc exists (`SECURITY.md` or a section of `THREAT-MODEL.md`) that a procurement reviewer could actually read, plus the rate-limit and secrets-handling behavior are tested, not just described.

## Phase 18 — Cloud infrastructure & scaling

- Containerize; move photo storage to S3-compatible object storage; Postgres with read replicas once multi-tenant; a queue (SQS/Kafka/etc.) between arrival ingestion and the mint/fraud pipeline so a slow fraud check never blocks device intake.
- Definition of done: a load test shows ingestion throughput isn't gated by fraud-check latency, and the system degrades to "queued for review" rather than dropping arrivals under load.

## Phase 19 — Business/commercial layer

- Pricing model decision (per-device SaaS fee vs. per-tonne-verified fee vs. hybrid) — this is a product decision the user needs to make, not something to default silently.
- Facility onboarding workflow, billing integration, SLA definition.
- Hindi and relevant regional-language support for operator-facing UI, given the primary users are facility floor staff, not head-office PIBO staff.
- Definition of done: this phase produces decisions and docs more than code — capture them in `COMMERCIAL_ROADMAP.md` and revisit before building billing logic prematurely.

## Phase 20 — Pilot & go-to-market packaging

- A concrete pilot plan: one or two partner recyclers, a defined success metric (e.g., "X% of arrivals verified with zero disputed certificates over N weeks"), and what's needed from them (network access at the gate, a truck schedule to test circular-trucking detection against).
- Definition of done: a one-page pilot brief exists that a real facility owner could read and agree to.

---

## Cross-cutting rule for every phase

Before marking any phase "done," re-run the `SKILL.md` definition-of-done checklist in full — not just the bullets under that phase here. A commercial feature that quietly reopens an earlier invariant (e.g., a new integration endpoint that bypasses the atomic-mint path, or a dashboard view that leaks cross-tenant data before Phase 11 lands) is the failure mode this whole project exists to prevent in *other people's* systems; it would be a bad look to reproduce it in this one.

**Session logging rule (applies to every phase):** Before ending any session — especially when context/credit limits approach — append an entry to `SESSION_LOG.md`. Include: what was done, what was verified live vs. syntax-checked only, what invariants were touched, what is pending. An incomplete session log is the only failure that can't be recovered from code history alone.

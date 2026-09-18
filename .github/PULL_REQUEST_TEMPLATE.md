<!-- Read SKILL.md invariants 1–14 before filling this in. -->

## What this changes and why

<!-- One or two sentences. Link the BUILD_INSTRUCTIONS.md phase if this completes one. -->

## Invariant check (SKILL.md)

Check every box that applies to files you touched. Leave unrelated boxes unchecked — don't check something you didn't actually verify.

- [ ] Signature verification is still real and mandatory (no new default-accept path) — #1
- [ ] Server-side hash is recomputed and checked before signature verification, not trusted from the request — #2
- [ ] Minting (if touched) is still a single atomic conditional update, no read-then-write window — #3
- [ ] Fraud checks (if touched) are tested against real inserted data, both the fire case and the no-false-positive case — #4
- [ ] Ledger verification (if touched) still does real hash-chain/Merkle verification, not an echo — #5
- [ ] Concurrency/double-spend test still passes, and was actually run (not just present) — #6
- [ ] Nothing that matters to certificate logic lives only in memory — #7
- [ ] New writes to certificate-relevant tables are attributable via the audit log — #8
- [ ] No new cross-tenant data access path — #9
- [ ] No secret, key, or credential added to source, config, or logs — #10
- [ ] Firmware changes (if any) preserve signed-OTA verification before flashing — #11
- [ ] New/changed ingestion endpoints are rate-limited and request-signed — #12
- [ ] No new collection of personal data beyond what's already justified and retained per policy — #13
- [ ] Any new dependency on an external check fails closed (flag for review), not open (mint anyway) — #14

## Tests

- [ ] New/changed behavior has a test that fails without this change
- [ ] Full suite passes locally, including the concurrency test
- [ ] Anything not run live (no hardware / no network in this environment) is named explicitly below

## Docs

- [ ] `ARCHITECTURE.md` and/or `THREAT-MODEL.md` updated in this PR if this adds a fraud check, changes the crypto scheme, adds an integration surface, or reveals a new attack pattern

## Notes for the reviewer

<!-- Anything you're unsure about, anything intentionally left out of scope, anything you couldn't verify in this environment. -->

# Contributing to VERITAS

> **VERITAS** — **V**erified **E**PR **R**ecycling with **I**ntegrity **T**amper-proof **A**rrival **S**ignatures
> Open-source community project.

Thanks for working on this. Read `SKILL.md` before your first PR — it has the non-negotiable invariants this whole project exists to protect, and every review will be checked against it.

## Setup

```bash
git clone <repo-url> && cd veritas
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt -r requirements-dev.txt
pre-commit install
pytest        # should pass before you change anything
```

If `pytest` doesn't pass cleanly on a fresh checkout, that's a bug — flag it before building on top of it.

## Code style

- **Formatting/linting:** `black` + `ruff`, run via `pre-commit` on every commit — don't hand-format around them.
- **Typing:** type hints on every public function signature; `mypy` runs in CI and failures block merge.
- **Docstrings:** every module, and every function whose behavior isn't obvious from its name and signature — especially anything in `crypto.py`, `fraud.py`, or `ledger.py`, where "obvious" is exactly the failure mode we're avoiding.
- **Structure:** `main.py` stays routing-only. If you're writing logic inside a route handler, it belongs in `service.py` instead.
- **No bare `except:`** — catch what you expect, let the rest surface. A silently swallowed exception in the mint or verification path is a security bug, not a style nitpick.

## Secrets

Never commit keys, credentials, or `.env` files. Device signing keys, DB credentials, and any government-portal API credentials go through the project's secrets manager (see `SKILL.md` invariant #10) — if you're not sure where that is yet, ask before hardcoding something "temporarily."

## Branching & commits

- Branch names: `<type>/<short-description>`, e.g. `fix/mint-race-window`, `feat/circular-trucking-check`.
- Commits: imperative mood, present tense (`Add capacity-ceiling fraud check`, not `Added` or `Adding`). Reference the phase from `BUILD_INSTRUCTIONS.md` if the PR completes one, e.g. `Phase 12: CPCB export endpoint`.
- Keep PRs scoped to one phase or one fix. A PR that touches `crypto.py` and the dashboard styling at the same time is two PRs.

## Tests

- New behavior needs a new test that fails without your change and passes with it — not a test that just happens to pass.
- Touching `database.py`'s mint path? Run the concurrency test locally, not just the sequential unit tests — `pytest tests/test_database.py -k concurrency -v`.
- Touching `crypto.py` or firmware signing? Run the cross-language round-trip test both directions before opening the PR.
- If your sandbox can't run something (no hardware, no network), say so explicitly in the PR description — don't let CI's green checkmark imply more than what actually ran.

## Pull request checklist

Every PR uses `.github/PULL_REQUEST_TEMPLATE.md`, which walks through the invariants in `SKILL.md` relevant to your change. Fill it in honestly — "not applicable" is a fine answer when it's true, and a reviewer will check.

## Review expectations

- A reviewer will re-derive whether invariants 1–14 still hold after your diff, not just whether your new tests pass. If a change makes it *possible* to mint without a valid physical record — even in an edge case you didn't intend to touch — that's a blocking review comment, not a nitpick.
- Docs (`ARCHITECTURE.md`, `THREAT-MODEL.md`) get updated in the same PR as the code change they describe, not in a follow-up.
- If you're unsure whether something counts as commercial-hardening scope creep vs. a real fix, open a draft PR and ask — cheaper than building the wrong thing for a day.

## Session logging — mandatory

After every working session, append an entry to `SESSION_LOG.md` at the repo root. An unlogged session is effectively lost work.

### Format

```markdown
## YYYY-MM-DD HH:MM IST — [your name]
**Done:** <what was completed>
**Verified live:** <what was actually run and passed>
**Syntax-checked only / not verified:** <what was not run due to environment limits>
**Invariants touched:** <list 1–14 numbers>
**Pending:** <what the next session should pick up>
```

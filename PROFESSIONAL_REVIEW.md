# Professional deep-dive review — IAM on-boarding agent

Date: 2026-10-28. Scope: everything in `iam-onboarding-agent/` as it
stood before this review, plus the fixes made during it. Verdict first,
evidence after.

## Verdict

**A solid professional foundation, not yet a production system.** The
architecture was already right; the gaps were the unglamorous things
that separate a demo from software you can trust: validation, tests,
persistent audit, packaging, and a real approval story. All of those
are now fixed or documented below. What remains before production is
short, specific, and listed at the end -- there are no vague "needs
hardening" items.

## What a great application should do (the standard applied)

A professional application, especially one that grants access, is
judged on ten dimensions. Each is rated as it stood *before* this
review, then what changed.

### 1. Architecture and generality — was strong, still strong

- Provider interface (`create_user`, `add_to_group`, `assign_license`,
  `disable_user`) keeps the agent vendor-neutral. ✅
- Policy lives in one table, not scattered through code. ✅
- Safe defaults: unknown roles get `all-staff` only. ✅
- No change needed.

### 2. Safety — was partial, now strong

- Before: human approval existed only as a demo auto-approver, and
  approvals were not attributed to anyone.
- Fixed: risk-tiered human-in-the-loop (`iam_agent/approval.py`).
  Routine plans auto-approve; privileged roles/groups/licences and
  unknown roles stop for a human. Every decision is audited with who
  made it. A segregation-of-duties check refuses toxic combinations
  before anything is created.
- Remaining: requester != approver is recorded but not enforced (see
  SECURITY.md §3). That is a production gate, not a nice-to-have.

### 3. Correctness — was fragile, now solid

- Before: any bad input (blank name, uppercase username) flowed
  straight into provider calls; re-running an on-boarding failed the
  whole run at the duplicate user.
- Fixed: `NewHire` validates itself at construction (username rules,
  non-blank fields). Re-runs resume idempotently: an existing account
  is logged as `skipped` and the run continues with groups and
  licences. Failures still stop the run, so partial state is visible
  instead of silently half-done.
- Remaining: no rollback/compensation for a run that fails halfway
  (e.g. user created, group add failed). Documented as the next
  reliability item, after retries.

### 4. Testing — was absent, now present

- Before: zero tests; correctness rested on eyeballing demo output.
- Fixed: 27 unit tests (stdlib `unittest`, no new dependencies)
  covering validation, policies, fail-closed defaults, SoD conflicts,
  dry runs, approvals, rejections, idempotent re-runs, and audit-file
  output. Run them with: `python -m unittest discover -s tests`
- Remaining: no coverage measurement and no CI pipeline. Both are
  one-file additions when the project moves to a hosted repository.

### 5. Observability — was memory-only, now durable

- Before: the audit log lived in memory and vanished when the process
  exited.
- Fixed: `--audit-file` writes append-only JSON lines, plus structured
  `logging` in the engine. One JSON object per line means the log is
  queryable with ordinary tools.
- Remaining: no metrics, no alerting on partial failures. Required
  before production (SECURITY.md §7).

### 6. Configuration — was hardcoded, now external

- Before: role policies could only change by editing Python.
- Fixed: `policies.json` (with `IAM_POLICIES_FILE` override) loads
  the role table at startup, validated on load. Bad policy files
  refuse to start rather than run on broken rules.

### 7. Operability — was demo-only, now usable

- Before: hires were hardcoded in `main.py`; there was no way to run
  the agent on real input.
- Fixed: `iam_agent/cli.py` -- `--dry-run`, `--audit-file`,
  `--hires hires.csv`, `--auto-approve` (flagged as tests-only, with a
  printed warning). Exit codes: 0 only when every hire finishes done
  or dry-run; 1 otherwise.

### 8. Packaging — was absent, now present

- Fixed: `pyproject.toml` (version 0.2.0, Python >= 3.10, `iam-onboard`
  console entry point) and `.gitignore` (caches, `.env`, audit files).
- Remaining: a changelog (added: CHANGELOG.md) needs discipline to
  maintain; versioning is manual until releases are automated.

### 9. Documentation — was good, now complete for this stage

- README (architecture, how to run, roadmap), SECURITY.md (secrets,
  least privilege, audit protection, PII), this review, and docstrings
  throughout. API reference beyond docstrings is intentionally skipped
  at this size.

### 10. IAM-specific completeness — joiner done, lifecycle not yet

- Joiner (on-boarding): implemented end to end. ✅
- Mover (role changes) and leaver (off-boarding): the provider
  interface already has `disable_user`, but no flows exist yet. ❌
- Access recertification (periodic re-confirmation of access): ❌
- SCIM or HR-system integration: ❌ (CSV input is the stepping stone)

## Production-readiness checklist (the honest remainder)

1. Real provider against a test tenant.
2. Requester != approver enforcement.
3. Durable audit store with restricted access and backups.
4. Retry with backoff + alerting on partial runs.
5. Rollback/compensation for half-finished runs.
6. Mover and leaver flows.
7. CI running the test suite on every change.
8. Access recertification process.

Nothing on that list is a surprise, and nothing on it requires
redesigning what already exists -- each is an addition to the current
shape, which is exactly what "professional" means at this stage.

## Update — v0.3.0 (2026-10-28): "a real system"

Items 2–7 above are now done: requester != approver is enforced,
the audit store is SQLite with a hash chain (tamper-evident) and on
by default with the persistent provider, retries and compensation
are implemented and tested, mover and leaver flows exist, and CI
runs compile + tests on every push. A SQLite provider now gives the
system a real, persistent identity store, and `--review` gives
operators the access picture. What remains from the list: a real
directory provider against a test tenant (item 1, needs tenant
access), alerting on partial runs (the notifier hook exists; wiring
it to a real channel is deployment config), and the access
recertification process (organizational, not just code).

## Update — v0.4.0 (2026-10-28): Entra provider

Item 1 is half done, honestly labelled: the Entra provider code
exists and is tested against a simulated Graph (49 tests total),
with a full setup guide (ENTRA_SETUP.md). What is *not* done is
verification against a live tenant — that requires a test tenant,
an app registration, and admin consent, which only the operator
can provide. Until that run happens, the provider should be
described as implemented and simulated-tested, not production-
proven.

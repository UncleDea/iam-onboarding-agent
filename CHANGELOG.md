# Changelog

## 1.0.0 — 2026-10-28

One install for one company. The first visit is a setup wizard
(company name, admin, and a different approver). An admin edits
policy in the app. The built-in directory can load a sample
company. Microsoft sign-in is optional and only matches an existing
app user.

Access rules live only in the policy file. A standard grant or an
offboard needs an approver or admin who is not the requester. A
privileged grant needs an admin who is not the requester. The
approved plan is the plan that runs. Nothing approves itself.

Onboarding creates the account disabled and enables it after groups
and licences. A move restores the previous access when a later step
fails. Entra uses a per-account temporary password, a required usage
location, employee type for the app role, and a manager when the
request names one. Health checks the database and, for Entra, a
token. App passwords are at least 12 characters.

Removed the three demo scripts, the printed bootstrap password, and
the shared Entra temporary password.

## 0.7.0 — 2026-10-28 (welcome email for real)

- Added: real welcome emails (`iam_agent/emailing.py`). The
  `send_welcome` step now sends an actual email: subject and body
  from a template (name, username, department, role, manager,
  start date) that never contains a password or secret.
- Added: `NewHire.email` (optional, validated). CSV input and the
  web form both accept it.
- Added: SMTP sender from the environment (IAM_SMTP_* plus
  IAM_WELCOME_FROM, falling back to IAM_NOTIFY_FROM) and a console
  sender for demos (IAM_EMAIL_CONSOLE=1).
- Behaviour by design: no address or no sender -> the step is
  logged as skipped, not failed; a sending failure is logged as
  failed but never rolls back a correctly created account.
- Added: 10 emailing tests (88 total), and the main demo now shows
  both paths (sent for Ada, skipped for Bob).

## 0.6.0 — 2026-10-28 (hardened for real use)

- Added: app user management — admin Users page (create, activate/
  deactivate, password reset) and self-service Profile password
  change; admin actions are written to the audit store.
- Added: account lockout (5 failed logins -> 15 minutes, both
  configurable) and per-IP login throttling (20 failures / 15 min).
- Added: password policy (min 8 characters); password changes and
  resets invalidate all sessions for that user.
- Added: security headers on every response (nosniff, DENY framing,
  no-referrer, same-origin CSP), Secure cookie flag behind TLS
  (IAM_COOKIE_SECURE=1), CSRF protection on logout as well as all
  other state-changing posts.
- Added: deployment pack — systemd unit, nginx + TLS example,
  online backup script with retention, and DEPLOYMENT.md (install,
  secrets, TLS, first-login tasks, backup/restore proof, log and
  alert wiring, live-tenant verification checklist).
- Added: CLI `--verify-audit` — prove a restored database's audit
  chain is intact (verified: valid after restore, invalid after
  tampering, exit code 1).
- Added: SMTP alert wiring in the app when IAM_SMTP_* is fully set;
  otherwise alerts are still recorded and counted.
- Added: 10 hardening tests (78 total).
- Not done (needs the operator): live Entra verification against a
  test tenant — documented as a checklist, not claimed.

## 0.5.0 — 2026-10-28 (foundations + observability + the app)

Foundations (the things that are painful to retrofit):
- Added: request records (`iam_agent/requests.py`) — every change
  is a request with a lifecycle (pending_approval -> approved ->
  running -> done/partial/failed, or rejected), requester, approver,
  reason, and result.
- Added: app login (`iam_agent/auth.py`) — PBKDF2-hashed passwords,
  server-side sessions, roles (admin/approver/requester).
- Added: centralized config (`iam_agent/config.py`) — one settings
  module, validated at startup, failing fast with a full list.
- Added: versioned migrations (`iam_agent/migrations.py`).
- Added: concurrency-safe database layer (`iam_agent/db.py`) —
  one locked connection, WAL mode, busy timeout; the SQLite
  provider and audit store now share it.
Observability, monitoring, reporting:
- Added: metrics, JSON/plain structured logging with request IDs,
  health checks (database, audit chain, provider), and alerting
  with a 15-minute cooldown (`iam_agent/observability.py`).
- Added: access, activity, approval, and summary reports as JSON
  and CSV (`iam_agent/reporting.py`), plus a CLI `--report` flag.
The app:
- Added: web app (`iam_agent/webapp.py`, `run_app.py`, templates)
  — standard library only, no installs. Login, dashboard,
  requests, approvals, access review, reports, audit, health,
  metrics. CSRF tokens, HttpOnly session cookies, escaped output.
- Added: service layer (`iam_agent/service.py`) — the app's single
  front door; enforces roles and requester != approver, times and
  counts runs, raises alerts on partial/failed runs.
- Added: `APP_GUIDE.md`. 68 tests total, including a full HTTP
  smoke test of the app and a live-process demo run.

## 0.4.0 — 2026-10-28 (Entra provider)

- Added: real Microsoft Entra ID provider (`iam_agent/entra_provider.py`)
  over Microsoft Graph — client-credentials flow, token caching,
  group lookup by display name, licence assignment via skuPartNumber
  mapping, full IdentityProvider interface (create/get/update,
  groups, licences, disable, list).
- Added: CLI `--provider entra` (configuration purely from
  `IAM_ENTRA_*` environment variables; the secret never appears on a
  command line).
- Added: `ENTRA_SETUP.md` — app registration, least-privilege
  permissions, admin consent, secret handling, licence mapping,
  dry-run-first procedure, troubleshooting.
- Added: 9 Entra tests against a fake Graph transport (endpoints,
  payloads, token reuse, error mapping, full engine run) — 49 tests
  total. Not yet verified against a live tenant: that needs a test
  tenant and admin consent, deliberately left to the operator.
- Fixed: Graph error messages now include the error code, not just
  the human message — the provider matches on codes like
  Request_ResourceNotFound.
- Removed: `examples/entra_provider_stub.py` (superseded by the real
  provider).

## 0.3.0 — 2026-10-28 (a real system)

- Added: SQLite provider (`iam_agent/sqlite_provider.py`) — accounts,
  groups, and licences persist across runs; the CLI can on-board on
  Monday and review on Friday.
- Added: hash-chained SQLite audit store (`iam_agent/audit_store.py`);
  `verify()` detects tampering. On by default with the SQLite provider.
- Added: mover flow (role/department change as a diff — old access is
  removed, not just accumulated) and leaver flow (disable first, then
  strip groups and licences), both with the same plan/approve/audit
  shape as on-boarding.
- Added: requester != approver enforcement — a requester approving
  their own request is refused, not just logged.
- Added: retries with backoff for transient provider failures, and
  compensation (rollback) of completed steps after a partial failure.
- Added: notifiers (`iam_agent/notifiers.py`) — console by default,
  SMTP via environment variables.
- Added: CLI modes `--review`, `--offboard`, `--move`, `--provider`,
  `--db`, `--requester`, `--notify`.
- Added: CI workflow running compile + tests on push and pull request.
- Added: 13 more unit tests (40 total).
- Fixed (found by end-to-end testing): approval classification and the
  terminal prompt crashed on move/offboard flows, which carry no role
  or display name; move/offboard now always ask a human directly.

## 0.2.0 — 2026-10-28 (professional deep dive)

- Added: risk-tiered human-in-the-loop approvals (`iam_agent/approval.py`,
  `main_hitl.py`). Routine plans auto-approve; privileged or unknown
  access stops for a named human, and the decision is audited.
- Added: input validation on `NewHire` (username rules, non-blank fields).
- Added: segregation-of-duties conflict refusal before any side effect.
- Added: idempotent re-runs — an existing account is skipped, not fatal.
- Added: persistent audit log as JSON lines (`--audit-file`), structured
  logging, policies from `policies.json` (`IAM_POLICIES_FILE` override).
- Added: CLI (`iam_agent/cli.py`) with `--dry-run`, `--hires`,
  `--audit-file`, `--auto-approve` (tests only).
- Added: 27 unit tests (stdlib `unittest`).
- Added: `pyproject.toml`, `.gitignore`, `SECURITY.md`,
  `PROFESSIONAL_REVIEW.md`.
- Fixed: dry-run results now carry a `status` field (found by the CLI
  dry-run during this review).

## 0.1.0 — 2026-10-28

- Initial from-scratch build: provider interface + mock provider, role
  policies, plan/approve/execute/audit engine, demo (`main.py`), human
  y/n approver demo (`main_human.py`), Entra provider stub.

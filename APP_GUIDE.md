# The IAM app — user guide

The app is a small web interface over the IAM engine. It runs on one
machine, serves one team, and needs nothing but Python 3.10+.

## Start it

```bash
python run_app.py
```

Then open http://127.0.0.1:8000/ in a browser.

On first start, with no app users yet, the app creates a bootstrap
admin and prints its password **once** to the console. To control
the admin account instead, set these before starting:

```bash
export IAM_APP_ADMIN_USER="admin"
export IAM_APP_ADMIN_PASSWORD="choose-a-strong-password"
```

Configuration lives in the environment; see `iam_agent/config.py`
for the full list (`IAM_PROVIDER`, `IAM_DB`, `IAM_APP_HOST`,
`IAM_APP_PORT`, `IAM_ENTRA_*`, ...). Defaults: SQLite provider,
database file `iam.db`, bind 127.0.0.1:8000.

## Who can do what

App users are separate from directory users. Roles:

- **requester** — submit on-board, move, and off-board requests.
- **approver** — approve or reject requests (never their own).
- **admin** — everything, including approvals.

There is no self-service signup page, deliberately: admins create
app users on the **Users** page (admin role only), where they can
also activate/deactivate accounts and reset passwords. Every admin
action is written to the audit store. Users change their own
password on the **Profile** page; changing a password signs out
all sessions for that user.

Failed logins lock an account for 15 minutes after 5 attempts
(both configurable), and one IP address is throttled after 20
failed logins in 15 minutes. Login failures show the same generic
message whether the account is unknown, inactive, or locked, so
failures never reveal which one it was.

## The workflow

1. A requester submits a request (on-board, move, or off-board).
   It sits in **pending_approval**.
2. An approver (or admin) who is not the requester opens it, sees
   the exact details, and approves or rejects with a reason.
3. Approving runs the change immediately through the engine, with
   the same audit trail, retries, and compensation as the CLI.
4. A rejected request changes nothing; the reason is recorded.

## Welcome emails

The last step of on-boarding sends a welcome email to the hire's
email address (optional field on the request form and in the CSV).
The email contains the hire's name, username, department, role,
manager, and start date -- never a password.

Configuration (environment):

- `IAM_SMTP_HOST`, `IAM_SMTP_PORT` (default 587), `IAM_SMTP_USER`,
  `IAM_SMTP_PASSWORD`, and `IAM_WELCOME_FROM` (or `IAM_NOTIFY_FROM`)
  for real sending.
- `IAM_EMAIL_CONSOLE=1` to print emails to the console instead
  (demos only).

If no address is on file, or no sender is configured, the step is
logged as **skipped** -- never failed. If sending itself fails,
the step is logged as **failed** but the on-boarding is not rolled
back: a failed email must not undo a correctly created account.

## Pages

- **Dashboard** — pending approvals, totals, recent requests, alerts.
- **Requests** — list with status filters; each request has a
  detail page with its payload, decision, and result.
- **New request** — one form per kind (on-board / move / off-board).
- **Access review** — every directory user with groups and licences.
- **Reports** — summary, access, activity, and approval reports,
  viewable as JSON or downloadable as CSV.
- **Audit** — the most recent audit entries.
- **Health** (`/health`, no login) — database, audit chain, and
  provider status as JSON. Point a monitor at it.
- **Metrics** (`/metrics`, login required) — run/decision counters
  and run durations as JSON.

## Observability, monitoring, reporting

- **Logs**: plain text by default; set `IAM_LOG_JSON=1` for JSON
  lines (one per line, with a request ID per web request) for a
  log aggregator.
- **Monitoring**: poll `/health`. A partial or failed run also
  raises an alert inside the app (dashboard count) and calls the
  notifier, at most once per user per 15 minutes.
- **Reporting**: the Reports page, or the CLI:
  `python -m iam_agent.cli --provider sqlite --db iam.db --report
  summary --format csv`.

## Running it beyond one machine

This app is single-process with SQLite — right for a small team
on one server. See [DEPLOYMENT.md](sandbox://workspace/iam-onboarding-agent/DEPLOYMENT.md) for the full checklist: systemd
service, nginx + TLS, an env file for secrets, nightly backups
with restore proof, log shipping, and alert wiring. For multiple
servers or a larger team, move the database layer to PostgreSQL
(the `Database` class is the seam).

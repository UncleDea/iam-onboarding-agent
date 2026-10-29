# Operate IAM Onboarding

One machine, one company, Python 3.10 or newer. Nothing else to install.

## Start

```bash
python run_app.py
```

Open http://127.0.0.1:8000/.

The first visit, when no app user exists, is setup. Enter the company name, an admin, and a different approver. Passwords are at least 12 characters. The app does not print a password.

To create the admin from the environment instead:

```bash
export IAM_APP_ADMIN_USER="admin"
export IAM_APP_ADMIN_PASSWORD="a-long-password"
```

Then create the approver on the Users page. Two people are required. One person cannot approve their own request, and there is no override.

Other settings are in `iam_agent/config.py`. Defaults: built-in directory, database file `iam.db`, bind 127.0.0.1:8000.

## Who can do what

App users are separate from directory users.

- **requester** — submit onboarding, move, and offboard requests.
- **approver** — decide a standard request, never their own.
- **admin** — decide any request, never their own, and manage users and policy.

A standard grant or an offboard needs an approver or an admin. A privileged grant needs an admin. Privileged means a role, group, or licence listed as privileged in the policy, or a role the policy does not name.

Admins create app users on the Users page, and can deactivate accounts and reset passwords. Those actions are in the audit log. A person changes their own password on Profile. That signs out every session for that user.

Five failed logins lock an account for 15 minutes. One address is throttled after 20 failed logins in 15 minutes. Both are configurable. A failed login looks the same for an unknown, inactive, or locked account.

## The workflow

1. A requester submits a request. The plan is stored with it.
2. A person who is allowed to decide opens it, reads the plan, and approves or rejects.
3. Approval runs that stored plan. If the policy has changed so the plan would differ, the request stays pending.
4. A rejection changes nothing. The reason is recorded.

Onboarding creates the account disabled, adds groups and licences, then enables it. The welcome message is outside that sequence: a missing address or a failed send does not undo the account.

A move records the previous groups, licences, role, and department, and restores them if a later step fails. If the restore itself fails, the request is marked partial. An offboard disables the account first. Groups the person inherited are recorded and left in place.

When the directory is Entra, the one-time password is shown once on the request page and is not written to the audit log, the welcome mail, or the stored result.

## Policy

The Policy page is for admins. It shows the policy file the process loaded. Saving uses the same checks as startup. A bad document is refused and the file is left as it was.

## Sample company

On the built-in directory, an admin can load three fictional people from Access review. That button is absent when the directory is Entra.

## Welcome email

The welcome step uses the hire's email address. The message has the name, username, department, role, manager, and start date. It never has a password.

- `IAM_SMTP_HOST`, `IAM_SMTP_PORT` (default 587), `IAM_SMTP_USER`, `IAM_SMTP_PASSWORD`, and `IAM_WELCOME_FROM` (or `IAM_NOTIFY_FROM`) send mail.
- `IAM_EMAIL_CONSOLE=1` prints the message instead.

No address, or no sender, is logged as skipped. A send failure is logged as failed and the account stays.

## Sign in with Microsoft

Optional, and separate from the directory connector. Set `IAM_APP_ENTRA_TENANT`, `IAM_APP_ENTRA_CLIENT_ID`, and `IAM_APP_ENTRA_CLIENT_SECRET`. `IAM_APP_ENTRA_REDIRECT` defaults to `http://<host>:<port>/login/microsoft/callback`.

The sign-in matches an existing app username, or the part of the Microsoft account name before `@`. It does not create users. Username and password stay available.

## Pages

- **Dashboard** — pending approvals, totals, recent requests, alerts.
- **Requests** — list and detail, including the frozen plan.
- **New request** — onboard, move, or offboard.
- **Access review** — directory users, groups, and licences.
- **Reports** — summary, access, activity, and approvals, on the page or as CSV.
- **Audit** — recent audit entries.
- **Policy** — admin only.
- **Users** — admin only.
- **Profile** — your password.
- **Health** (`/health`, no login) — the database answers, and Entra can obtain a token when that directory is configured. It does not list users or replay the audit chain. Use `--verify-audit` for the chain.
- **Metrics** (`/metrics`, login required) — counters and durations.

## Logs and reports

Set `IAM_LOG_JSON=1` for one JSON line per event, with a request id on web requests. A partial or failed run alerts inside the app and calls the notifier, at most once per person per 15 minutes.

```bash
python -m iam_agent.cli --provider sqlite --db iam.db --report summary --format csv
```

## Beyond one machine

This app is one process and one SQLite file, which is the right size for a small team on one server. See [DEPLOYMENT.md](DEPLOYMENT.md).

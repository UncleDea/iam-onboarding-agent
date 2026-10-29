# Deploying the IAM app for real use

This is the checklist that turns "it runs on my laptop" into "a
small team can rely on it". Work through it in order. Anything
marked **operator step** needs a human with access to the server
or tenant -- it cannot be done from the code alone.

## 1. Install as a service

- Copy the project to `/opt/iam-app` (or your chosen directory).
- Create a dedicated, unprivileged user: `useradd --system iamapp`.
- Give that user ownership of the install directory and the
  database file, nothing else.
- Install `deploy/iam-app.service` (adjust paths first), then
  `systemctl enable --now iam-app`.

## 2. Secrets in an env file, not in the repo

Create `/etc/iam-app/env` (mode `600`, owned by `iamapp`) with:

```bash
IAM_PROVIDER=sqlite
IAM_DB=/opt/iam-app/iam.db
IAM_APP_HOST=127.0.0.1
IAM_APP_PORT=8000
IAM_COOKIE_SECURE=1
# Optional. If unset, the first visit is the setup wizard.
IAM_APP_ADMIN_USER=admin
IAM_APP_ADMIN_PASSWORD=<at least 12 characters>
# Add IAM_SMTP_* for email alerts, IAM_ENTRA_* for the Entra provider.
```

The systemd unit loads this file. No secret ever goes in git, in
a chat message, or on a command line.

## 3. TLS in front, never direct

- Install `deploy/nginx.conf.example` as your nginx site (adjust
  the domain and certificate paths).
- Get a certificate: `certbot --nginx -d iam.example.com`.
- Confirm the app is reachable only through nginx, and that
  `IAM_COOKIE_SECURE=1` is set -- otherwise the session cookie
  could travel over plain HTTP.
- The app's own security headers (nosniff, DENY framing,
  no-referrer, same-origin CSP) are already set on every response.

## 4. First-day tasks

1. Complete setup with two people, or sign in as the admin from
   the environment and create a different approver on the Users
   page. Confirm a requester cannot open Users or Policy, and
   cannot approve their own request.
2. Try a wrong password five times on a test account and confirm
   it locks for 15 minutes.
3. Submit, approve, and reject one test request of each kind.
   On the built-in directory, an admin can load the sample company
   from Access review first.

## 5. Backups, and prove restores work

- Schedule `deploy/backup.py` nightly from cron (example in the
  script's docstring). It snapshots the database without stopping
  the app and prunes backups older than 7 days by default.
- At least once, **restore on purpose**: stop the app, copy a
  backup over `iam.db`, start the app, and run:
  `python -m iam_agent.cli --provider sqlite --db iam.db --verify-audit`
  A restore you have never tested is a hope, not a backup.

## 6. Logs and alerts

- Set `IAM_LOG_JSON=1` and ship the app's stdout to wherever your
  logs live. Each line carries a request ID.
- Set the `IAM_SMTP_*` variables so partial/failed runs email
  someone. Without them, alerts are still recorded and counted on
  the dashboard, but nobody is paged.
- Poll `/health` from your monitor. It checks that the database
  answers and, when Entra is configured, that a token can be
  obtained. It does not list the directory. Check the audit chain
  with `--verify-audit`.

## 7. Live Entra verification (**operator step**)

The Entra provider is implemented and tested against a simulated
Graph, not a live tenant. Before pointing it at anything real:

1. Follow `ENTRA_SETUP.md` against a **test tenant** first.
2. Dry-run, then create one test user, and verify in the Entra
   admin center: account enabled, department, employee type,
   groups, licence, and manager when one was named. Job title is
   not written by this app.
3. Off-board that test user and verify: disabled, groups and
   licences stripped.
4. Run `--verify-audit` and confirm the chain is valid.
5. Only then consider a production tenant -- and repeat the same
   checks there.

## 8. Ongoing hygiene

- Rotate the Entra client secret before it expires (set a
  calendar reminder when you create it).
- Review the Users page quarterly: remove accounts of people who
  no longer need app access.
- Review the access report quarterly with managers (the
  recertification workflow is still a future feature; until then,
  the report plus a meeting is the process).
- Keep the app updated: pull, run the tests, restart the service.

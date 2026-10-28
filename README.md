# IAM On-boarding Agent — built from scratch, provider-general

An agent that on-boards a new hire: it plans the account setup, waits for
a human to approve the plan, executes it against an identity system, and
writes every step to an audit log.

It is **not tied to any vendor**. The agent talks only to the
`IdentityProvider` interface. Today that is a fake in-memory provider, so
the whole thing runs with zero accounts or credentials. Tomorrow it can
be Entra ID, Google Workspace, Okta, or anything else — you write one
new provider class and nothing else changes.

## Run the app

```
python run_app.py
```

Then open http://127.0.0.1:8000/ — see [APP_GUIDE.md](sandbox://workspace/iam-onboarding-agent/APP_GUIDE.md) for login, roles, and workflow, and [DEPLOYMENT.md](sandbox://workspace/iam-onboarding-agent/DEPLOYMENT.md) for running it for real (systemd, TLS, backups). Standard library only: no installs needed.

## Run the demos

```
python main.py
```

Try the human-approval versions with:

```
python main_human.py     # every plan asks a human (y/n)
python main_hitl.py      # only risky plans ask a human; routine ones auto-approve
```

## Run it as a real system

The mock provider forgets everything when the process exits. The
SQLite provider does not — it is the standalone identity store:

```
# On-board two demo hires into a database file
python -m iam_agent.cli --provider sqlite --db iam.db --auto-approve

# Later: see everyone and everything they hold
python -m iam_agent.cli --provider sqlite --db iam.db --review

# Move someone (asks a human, shows the exact diff first)
python -m iam_agent.cli --provider sqlite --db iam.db --move bob.builder --new-role manager

# Off-board someone (disables first, then strips groups and licences)
python -m iam_agent.cli --provider sqlite --db iam.db --offboard ada.lovelace

# Verify nobody tampered with the audit log
python -c "from iam_agent.audit_store import SqliteAuditStore; s = SqliteAuditStore('iam.db'); print(s.verify())"
```

CSV input and dry runs still work:

```
python -m iam_agent.cli --dry-run
python -m iam_agent.cli --hires hires.csv --audit-file audit.jsonl
```

Run the tests (standard library only, no installs, no API keys):

```
python -m unittest discover -s tests
```

## How it is put together

```
main.py                  Demo: two hires, dry run, approved run
main_human.py            Demo: every plan asks a human (y/n)
main_hitl.py             Demo: risk-tiered approvals (only risky plans ask)
policies.json            Role -> groups + licences (editable without code)
iam_agent/
  models.py              NewHire (validated), PlanStep, AuditEntry
  policies.py            Role table loader + segregation-of-duties checks
  providers.py           IdentityProvider interface + MockProvider
  sqlite_provider.py     Real persistent provider (SQLite identity store)
  audit_store.py         Hash-chained, tamper-evident audit log (SQLite)
  engine.py              Plan -> approve -> execute -> audit, plus move/offboard,
                         retries, compensation, requester != approver
  approval.py            Risk-tiered human-in-the-loop routing
  retry.py               Transient-error retries with backoff
  notifiers.py           Console + SMTP (env-configured) notifications
  entra_provider.py      Real Microsoft Entra ID provider (Graph)
  db.py                  Concurrency-safe SQLite layer
  migrations.py          Versioned schema migrations
  config.py              Centralized, validated settings
  requests.py            Request records with lifecycle
  auth.py                App login, PBKDF2 passwords, sessions, roles
  service.py             The app's front door: rules, metrics, alerts
  observability.py       Metrics, structured logging, health, alerts
  reporting.py           Access/activity/approval/summary reports (JSON, CSV)
  emailing.py            Welcome emails (SMTP + console senders, template)
  webapp.py              The web app (stdlib http.server) + templates/
  cli.py                 Command-line entry point
tests/                   88 tests (validation, policies, engine, approvals,
                         sqlite provider, audit chain, retries, mover/leaver,
                         entra provider against a fake Graph, foundations,
                         service, observability, reporting, hardening,
                         welcome email, full HTTP app tests)
deploy/                  systemd unit, nginx + TLS example, backup script
PROFESSIONAL_REVIEW.md   Deep-dive audit against professional standards
SECURITY.md              Secrets, least privilege, audit protection, PII
ENTRA_SETUP.md           Connect to a real Entra tenant, step by step
APP_GUIDE.md             Run and operate the web app
DEPLOYMENT.md            Harden and deploy for real use
CHANGELOG.md             Version history
```

## Connecting to a real directory

The Entra provider is built. To point it at a real tenant, follow
[ENTRA_SETUP.md](sandbox://workspace/iam-onboarding-agent/ENTRA_SETUP.md):
create an app registration with least-privilege permissions, grant
admin consent, set the `IAM_ENTRA_*` environment variables, dry-run
first, then run for real:

```
python -m iam_agent.cli --provider entra --dry-run
python -m iam_agent.cli --provider entra --hires hires.csv
```

That last step — actually connecting — is deliberately left to you:
it touches a real identity system and needs your tenant and admin
consent. The provider has been verified against a simulated Graph,
not yet against a live tenant.

The safety design, in one line: **plan, approve, execute, audit**.
The agent never creates anything before a human approves the exact plan,
and every action is logged with a timestamp.

## The three ideas that make it general

1. **Provider interface.** `create_user`, `add_to_group`,
   `assign_license`, `disable_user`. Any system that can do those four
   things can be driven by this agent.
2. **Policy table.** Access rules live in `policies.py`, not in code
   scattered through the engine. Change the table, change the access.
3. **Safe defaults.** An unknown role gets only `all-staff` and no
   licences. A system that grants access should fail closed, not open.

## What to build next, in order

Done already: everything above, including the web app with login,
request lifecycle, approvals, observability, monitoring, reporting,
user management, lockout, security headers, a deployment pack, and
real welcome emails. The Entra provider is verified against a
simulated Graph; live-tenant verification still needs a test
tenant and admin consent.
Remaining:

1. **Live-tenant verification.** Run the Entra provider against a
   test tenant following ENTRA_SETUP.md, then a Google Workspace
   provider the same way.
2. **Access recertification workflow** and time-bound access.
3. **LLM layer** (last, not first) with policy guardrails.
3. **A web dashboard** — approve with a button, watch a hire's
   progress, run access reviews from a page instead of the CLI.
4. **HR-system and ticketing connections** — hires, moves, and
   leavers flowing in automatically instead of via CSV.
5. **LLM layer (last, not first).** Let a language model turn a
   sentence like "Onboard Ada, Engineering" into a `NewHire` and pick
   the plan — the same tool-calling pattern as a multi-agent system.
   The engine underneath does not change, and the LLM must never be
   the thing that decides access: it proposes, the policy engine
   disposes.

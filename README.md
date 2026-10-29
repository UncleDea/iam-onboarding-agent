# IAM Onboarding

One install for one company of a few people. A request is planned, a different person approves it, the change runs, and the audit log records it.

The company name comes from setup. Access rules come only from `policies.json`. Version 1.0.0.

## Start

Python 3.10 or newer. No packages to install.

```
python run_app.py
```

Open http://127.0.0.1:8000/. When no app user exists, the first page is setup: company name, an admin, and a different person who can approve. The app does not print a password.

To create the admin from the environment instead, set `IAM_APP_ADMIN_USER` and `IAM_APP_ADMIN_PASSWORD` (at least 12 characters) before the first start, then create the approver on the Users page.

Defaults: the built-in directory, database file `iam.db`, bind `127.0.0.1:8000`. See [APP_GUIDE.md](APP_GUIDE.md) for roles and pages, and [DEPLOYMENT.md](DEPLOYMENT.md) before anyone else can reach it.

## What the two people can do

- A requester submits onboarding, a move, or an offboard.
- An approver or an admin who is not the requester decides a standard request.
- Only an admin who is not the requester decides a privileged request: a privileged role, group, or licence, or a role the policy does not name.
- An admin edits policy, manages app users, and, on the built-in directory, can load a sample company.

The plan shown at approval is the plan that runs. If the policy changed in between, the decision waits.

## Command line

Real changes need both people. Dry-run only prints the plan.

```
python -m iam_agent.cli --provider sqlite --db iam.db --dry-run --hires hires.csv
python -m iam_agent.cli --provider sqlite --db iam.db --requester ada.admin --approver bob.approver --hires hires.csv
python -m iam_agent.cli --provider sqlite --db iam.db --review
python -m iam_agent.cli --provider sqlite --db iam.db --verify-audit
```

`--approver` is an app username. The role comes from that account.

## Tests

```
python -m unittest discover -s tests
```

## Layout

```
run_app.py               Start the web app
policies.json            Roles, groups, licences, conflicts, privileged grants
iam_agent/               Engine, providers, web app, auth, audit
deploy/                  systemd unit, nginx example, backup script
BUYER.md                 What this product is
APP_GUIDE.md             Operate the web app
DEPLOYMENT.md            One server, TLS, backups
ENTRA_SETUP.md           Point the directory at Microsoft Entra
SECURITY.md              Secrets, approvals, audit, personal data
CHANGELOG.md             Version history
```

## Microsoft Entra

Optional. Follow [ENTRA_SETUP.md](ENTRA_SETUP.md) on a test tenant first. The provider is tested against a simulated Graph, not a live tenant. That check is an operator step.

Sign-in with Microsoft, for people who already have an app account, is a separate app registration. See APP_GUIDE.md. It does not create users.

## Not in this version

No license check, no second company in the same install, no Google Workspace, no recertification campaign, no HR or ticket feed, and no language model. Changes made directly in the Entra portal are outside this audit.

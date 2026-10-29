# Security notes for the IAM on-boarding agent

This agent creates accounts and grants access. That makes it a high-value
target and a high-consequence tool. These notes are the rules that keep
it safe. Read them before connecting any real provider.

## 1. Secrets: never in code, never in logs

- Client secrets, API tokens, and passwords live in **environment
  variables** (or a vault) and are read at startup. They are never
  written into source files, and this repository has no `.env` file
  committed for exactly that reason (see `.gitignore`).
- The audit log and application logs must never contain a secret, a
  password, or a token. The engine logs descriptions and usernames
  only -- check any new log line against that rule before merging it.
- If a secret is ever committed by mistake, treat it as stolen: revoke
  it and issue a new one. Deleting the commit does not un-leak it.

## 2. Least privilege for the provider identity

The app registration (or service account) the agent uses must have only
the permissions it needs, for example in Entra ID:

- `User.ReadWrite.All` -- create and manage users
- `GroupMember.ReadWrite.All` -- add users to groups
- `Organization.Read.All` -- read licence information

It must **not** be a Global Administrator. If the agent is compromised,
the damage is bounded by what its identity can do. Review these
permissions whenever a new capability is added.

## 3. Approvals: a named person, and a different person

- Nothing approves itself. A standard grant or an offboard needs an
  approver or an admin who is not the requester. A privileged grant
  needs an admin who is not the requester. Privileged means a role,
  group, or licence listed in the policy, or a role the policy does
  not name.
- The decision is stored with the person who made it. The plan they
  saw is the plan that runs.
- Conflicting groups (for example `payment-create` together with
  `payment-approve`) are refused before anything is created.
- App passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and
  must be at least 12 characters. A missing username still runs a
  password check, so the timing does not reveal whether the account
  exists. An inactive account cannot keep a session.

## 4. The audit log is evidence: protect it

- Use `--audit-file` so entries are written as append-only JSON lines
  that survive the process.
- Restrict who can read and modify the audit file, and back it up. If
  someone can rewrite the log, the log proves nothing.
- Decide a retention period (for example, one year) and stick to it;
  "keep everything forever" is not a retention policy.

## 5. Personal data: collect the minimum

- A `NewHire` carries only what on-boarding needs: name, username,
  department, role, manager, start date. Do not add dates of birth,
  home addresses, ID numbers, or salary information to this system --
  it has no reason to hold them.
- Treat the audit log as containing personal data too, and handle
  access to it accordingly.

## 6. Supply chain: small on purpose

- This project uses the Python standard library only. That is a
  deliberate security choice: every third-party dependency is code you
  trust but did not write. When a real provider is added, each new
  dependency (for example MSAL) should be pinned and reviewed.

## 7. Before any production use

1. Two different people hold the admin and approver accounts.
2. The database file is restricted and backed up, and a restore has
   been tried. `--verify-audit` checks the hash chain. `/health` does
   not replay it.
3. If the directory is Entra, follow ENTRA_SETUP.md on a test tenant
   first. This build is not proof against a live tenant. Changes made
   in the Entra portal are outside this audit.
4. A temporary Entra password is generated per account, shown once,
   and is not written to the audit log, the welcome mail, or the
   stored result.
5. Review access on a schedule. This version records access and can
   offboard. It does not run a recertification campaign.

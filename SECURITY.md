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

## 3. Approvals: a human, a named human, a separate human

- Routine plans auto-approve; privileged, unknown, or unusual plans
  require a human (see `iam_agent/approval.py`).
- Every approval decision is audited with who decided it. An approval
  that cannot be attributed to a person is not an approval.
- Segregation of duties, the next step beyond this codebase: the person
  who requests an on-boarding must not be the person who approves it.
  Today the engine records the approver's name; a production system
  must also *enforce* requester != approver. Do not deploy without it.
- Segregation-of-duties conflicts (e.g. `payment-create` together with
  `payment-approve`) are refused before anything is created.

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

## 7. Before any production use, these must exist

1. A real provider running against a **test tenant** first.
2. Requester != approver enforcement.
3. A durable audit store (database, not a local file) with restricted
   access and backups.
4. Retry/backoff and alerting on partial failures, so a half-finished
   on-boarding is noticed within minutes, not discovered weeks later.
5. An access-recertification process: periodically re-confirm that
   people still need the access they hold. On-boarding without
   off-boarding and review is how access quietly accumulates forever.

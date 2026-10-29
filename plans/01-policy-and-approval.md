# Policy and approval

## Policy loader (this slice)

`policies.json` is the only rule source. Shape:

- `roles` — role name to `groups` and `licenses`
- `fallback` — access for an unknown role (`all-staff`, no licences)
- `conflicts` — pairs that must never be held together
- `privileged_roles`, `privileged_groups`, `privileged_licenses`

`load_policy()` reads an explicit path, then `IAM_POLICIES_FILE`, then `./policies.json`, then `policies.json` beside the project. It does not run at import. A missing file, a broken file, or the old flat role map refuses to load, and the error names the required keys. There is no role table in Python.

`OnboardingAgent` takes a `Policy`. When none is passed, it calls `load_policy()` from its constructor. `build_plan` uses that object for access and segregation. `classify` reads privileged roles, groups, and licences from the same object.

This slice does not yet change who may approve. `classify` still returns `auto` or `human`. The next slice in this file removes auto-approval.

## Approval (next slice)

`classify` returns `standard` or `privileged`. Nothing auto-approves. The service is the only door that executes. A standard grant or an offboard needs an approver or admin who is not the requester. A privileged grant needs an admin who is not the requester. The CLI looks the approver up in `app_users`. The engine refuses to execute when no approver was configured. Dry-run still returns the plan.

Submit stores the plan. Decide rebuilds and compares sorted groups, licences, and attributes. Drift leaves the request pending. The decision update sets `running` only while status is `pending_approval`. A request still `running` after a restart becomes `partial` and raises an alert.

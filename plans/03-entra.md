# Entra

Each new account gets its own temporary password. It is shown once on the request page and is not stored in the audit log, the welcome mail, or the request result.

`IAM_ENTRA_USAGE_LOCATION` is required. `usageLocation` is set before a licence is assigned. The shared temporary password setting is gone.

A group name must match exactly one group. Quotes in the name are escaped. The access picture uses transitive membership. Only direct memberships are removed. Inherited groups are listed on the plan and left in place.

The role is stored in `employeeType`. Job title is left alone. A manager on the hire is written as a Graph manager reference.

`/health` does not list users. That check is the next slice.

# Execution

`AlreadyExists` and `NotFound` are the provider errors. The engine does not match those words inside a message.

`create_user` creates a disabled account. The onboard plan enables it only after groups and licences are in place. Adding a group, assigning a licence, enabling, and disabling succeed when that end state is already true.

A later onboard continues only while that account is disabled. An active account fails the run and tells the operator to use move, and the existing account is left as it is.

A move stores the previous groups, licences, department, and role. If a step fails and that previous access is restored, the run is `failed`. If the restore fails, the run is `partial`. An offboard that fails while stripping access leaves the account disabled.

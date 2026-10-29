# Health and local login

`/health` checks that the database answers and, for Entra, that a token can be acquired. It does not list the directory and it does not rehash the audit chain. The body is the status and the name of any failed check.

New passwords use 600,000 PBKDF2 iterations and must be at least 12 characters. Older hashes still verify. A missing username still runs a password hash so the response time does not reveal the account. An inactive user has no session.

The bootstrap message points at the Profile page. The setup wizard in the next slice replaces printing a password.

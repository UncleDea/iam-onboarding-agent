"""Versioned database migrations for the app-era tables.

A migration is (version, description, SQL). The database records
which versions it has applied in schema_version; on startup, only
the missing ones run, in order. Schema changes after launch are
therefore safe and repeatable instead of hand-edited.

Note on scope: the identity tables (users, memberships, licenses)
and the audit_log table predate this system and are created
idempotently by their providers (CREATE TABLE IF NOT EXISTS). The
migrations here cover everything the app itself adds. If the
providers are ever refactored, their tables should move into this
list as migrations 4+.
"""

MIGRATIONS = [
    (1, "requests", """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            requester TEXT NOT NULL,
            status TEXT NOT NULL,
            approver TEXT,
            decision_reason TEXT,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            executed_at TEXT,
            result TEXT
        )
    """),
    (2, "app_users", """
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """),
    (3, "sessions", """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            csrf_token TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """),
    (4, "app_users failed_attempts", """
        ALTER TABLE app_users
        ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0
    """),
    (5, "app_users locked_until", """
        ALTER TABLE app_users ADD COLUMN locked_until TEXT
    """),
    (6, "app_meta", """
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """),
]


def migrate(db) -> list:
    """Apply pending migrations. Returns the versions applied."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "  version INTEGER PRIMARY KEY, description TEXT NOT NULL,"
        "  applied_at TEXT NOT NULL)")
    applied = {row["version"] for row in
               db.query("SELECT version FROM schema_version")}
    newly_applied = []
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for version, description, sql in MIGRATIONS:
        if version in applied:
            continue
        db.execute(sql)
        db.execute(
            "INSERT INTO schema_version (version, description, applied_at)"
            " VALUES (?, ?, ?)", (version, description, now))
        newly_applied.append(version)
    return newly_applied

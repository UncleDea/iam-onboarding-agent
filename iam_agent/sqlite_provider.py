"""A real, persistent identity provider backed by SQLite.

Accounts, groups, and licences live in a database file that survives
restarts, instead of in memory that vanishes when the process exits.
The provider shares one concurrency-safe Database with the rest of
the app (see db.py), so web requests from several threads cannot
corrupt it. It implements the same IdentityProvider interface as
the mock and Entra providers.
"""

from .db import Database


class SqliteProvider:
    """SQLite-backed provider. One file holds the whole directory."""

    def __init__(self, path: str = None, db: Database = None):
        if db is not None:
            self._db = db
            self._owns_db = False
        else:
            self._db = Database(path)
            self._owns_db = True
        self.path = path or self._db.path
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "  username TEXT PRIMARY KEY, display_name TEXT NOT NULL,"
            "  department TEXT NOT NULL, role TEXT NOT NULL,"
            "  manager TEXT NOT NULL, start_date TEXT NOT NULL,"
            "  active INTEGER NOT NULL DEFAULT 1)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS memberships ("
            "  username TEXT NOT NULL, group_name TEXT NOT NULL,"
            "  PRIMARY KEY (username, group_name))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS licenses ("
            "  username TEXT NOT NULL, license_name TEXT NOT NULL,"
            "  PRIMARY KEY (username, license_name))"
        )

    # -- IdentityProvider interface ------------------------------------

    def create_user(self, hire) -> dict:
        existing = self.get_user(hire.username)
        if existing is not None:
            raise ValueError(f"user {hire.username!r} already exists")
        self._db.execute(
            "INSERT INTO users (username, display_name, department,"
            "  role, manager, start_date, active) VALUES (?, ?, ?, ?,"
            "  ?, ?, 1)",
            (hire.username, hire.display_name, hire.department,
             hire.role, hire.manager, hire.start_date),
        )
        return self.get_user(hire.username)

    def get_user(self, username: str):
        row = self._db.query_one(
            "SELECT username, display_name, department, role, manager,"
            "  start_date, active FROM users WHERE username = ?",
            (username,))
        if row is None:
            return None
        groups = [r["group_name"] for r in self._db.query(
            "SELECT group_name FROM memberships WHERE username = ?"
            " ORDER BY group_name", (username,))]
        licenses = [r["license_name"] for r in self._db.query(
            "SELECT license_name FROM licenses WHERE username = ?"
            " ORDER BY license_name", (username,))]
        return {
            "username": row["username"], "display_name": row["display_name"],
            "department": row["department"], "role": row["role"],
            "manager": row["manager"], "start_date": row["start_date"],
            "active": bool(row["active"]),
            "groups": groups, "licenses": licenses,
        }

    def update_user(self, username: str, **fields) -> None:
        allowed = {"department", "role", "manager", "start_date"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        assignments = ", ".join(f"{key} = ?" for key in updates)
        self._db.execute(
            f"UPDATE users SET {assignments} WHERE username = ?",
            (*updates.values(), username),
        )

    def add_to_group(self, username: str, group: str) -> None:
        self._require(username)
        self._db.execute(
            "INSERT OR IGNORE INTO memberships VALUES (?, ?)",
            (username, group),
        )

    def remove_from_group(self, username: str, group: str) -> None:
        self._db.execute(
            "DELETE FROM memberships WHERE username = ? AND group_name = ?",
            (username, group),
        )

    def assign_license(self, username: str, license_name: str) -> None:
        self._require(username)
        self._db.execute(
            "INSERT OR IGNORE INTO licenses VALUES (?, ?)",
            (username, license_name),
        )

    def revoke_license(self, username: str, license_name: str) -> None:
        self._db.execute(
            "DELETE FROM licenses WHERE username = ? AND license_name = ?",
            (username, license_name),
        )

    def disable_user(self, username: str) -> None:
        self._require(username)
        self._db.execute(
            "UPDATE users SET active = 0 WHERE username = ?", (username,),
        )

    def list_users(self) -> list:
        rows = self._db.query("SELECT username FROM users ORDER BY username")
        return [self.get_user(row["username"]) for row in rows]

    def close(self) -> None:
        if self._owns_db:
            self._db.close()

    def _require(self, username: str) -> None:
        if self.get_user(username) is None:
            raise ValueError(f"unknown user {username!r}")

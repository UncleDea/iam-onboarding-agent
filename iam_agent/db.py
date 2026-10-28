"""Concurrency-safe SQLite access for the whole system.

Why this module exists: the CLI runs one command at a time, but a
web app serves several people at once. A raw sqlite3 connection
created in one thread cannot be used from another, and two writers
can collide. So every database access in the app goes through this
one class:

- a single connection with check_same_thread=False,
- a re-entrant lock around every statement,
- WAL mode + a 30s busy timeout, so a brief write lock waits
  instead of failing.

This is the right size for a small internal app (one process, one
server). It is not a replacement for PostgreSQL if the app ever
needs multiple servers -- at that point this class is the seam to
swap out, and nothing above it changes shape.
"""

import sqlite3
import threading


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False,
                                     timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass  # in-memory databases have no WAL; fine
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.commit()

    def execute(self, sql: str, params=()):
        """Run a write (or DDL) statement and commit. Returns cursor."""
        with self._lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return cursor

    def query(self, sql: str, params=()):
        """Run a SELECT and return a list of plain dicts."""
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

    def query_one(self, sql: str, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()

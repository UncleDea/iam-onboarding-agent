"""Tamper-evident audit store backed by SQLite.

Each audit row carries the SHA-256 hash of the previous row plus its
own contents, forming a hash chain. If anyone edits or deletes a row
after the fact, `verify()` fails -- the log can prove its own history.
The store shares the app's concurrency-safe Database (see db.py).
"""

import hashlib
import json

from .db import Database


def _entry_hash(prev_hash: str, timestamp: str, action: str,
                 target: str, status: str, note: str) -> str:
    payload = json.dumps(
        {"prev": prev_hash, "timestamp": timestamp, "action": action,
         "target": target, "status": status, "note": note},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SqliteAuditStore:
    def __init__(self, path: str = None, db: Database = None):
        if db is not None:
            self._db = db
            self._owns_db = False
        else:
            self._db = Database(path)
            self._owns_db = True
        self.path = path or self._db.path
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  timestamp TEXT NOT NULL, action TEXT NOT NULL,"
            "  target TEXT NOT NULL, status TEXT NOT NULL,"
            "  note TEXT NOT NULL, prev_hash TEXT NOT NULL,"
            "  entry_hash TEXT NOT NULL)"
        )

    def append(self, entry) -> None:
        prev = self._db.query_one(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        prev_hash = prev["entry_hash"] if prev else "GENESIS"
        entry_hash = _entry_hash(prev_hash, entry.timestamp, entry.action,
                                 entry.target, entry.status, entry.note)
        self._db.execute(
            "INSERT INTO audit_log (timestamp, action, target, status,"
            "  note, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.timestamp, entry.action, entry.target, entry.status,
             entry.note, prev_hash, entry_hash),
        )

    def list_entries(self, limit: int = 100) -> list:
        return self._db.query(
            "SELECT timestamp, action, target, status, note FROM audit_log"
            " ORDER BY id DESC LIMIT ?", (limit,))

    def verify(self) -> bool:
        """Recompute the whole chain. False means the log was tampered with."""
        rows = self._db.query(
            "SELECT timestamp, action, target, status, note, prev_hash,"
            "  entry_hash FROM audit_log ORDER BY id")
        prev_hash = "GENESIS"
        for row in rows:
            if row["prev_hash"] != prev_hash:
                return False
            if _entry_hash(prev_hash, row["timestamp"], row["action"],
                           row["target"], row["status"],
                           row["note"]) != row["entry_hash"]:
                return False
            prev_hash = row["entry_hash"]
        return True

    def close(self) -> None:
        if self._owns_db:
            self._db.close()

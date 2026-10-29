"""Request records: the object the app is built around.

Before this module, a run happened and left audit lines behind, but
there was no "request" a UI could show. Now every change -- on-board,
move, off-board -- is a request with a lifecycle:

    pending_approval -> approved -> running -> done | partial
    pending_approval -> rejected
    approved -> running -> failed  (execution raised unexpectedly)

The record carries who requested it, who decided it, why a rejection
happened, and the execution result. The approval inbox, the request
history, and the approval report are all views over this table.

Enforcement note: this store records decisions; it does not make
them. The rule "requester cannot approve their own request" lives
in the service layer, where the acting user is known.
"""

import json
from datetime import datetime, timezone

STATUSES = ("pending_approval", "approved", "running", "done",
            "partial", "rejected", "failed")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RequestStore:
    def __init__(self, db):
        self._db = db

    def create(self, kind: str, payload: dict, requester: str) -> dict:
        if kind not in ("onboard", "move", "offboard"):
            raise ValueError(f"unknown request kind {kind!r}")
        cursor = self._db.execute(
            "INSERT INTO requests (kind, payload, requester, status,"
            "  created_at) VALUES (?, ?, ?, 'pending_approval', ?)",
            (kind, json.dumps(payload), requester, _now()))
        return self.get(cursor.lastrowid)

    def get(self, request_id: int):
        row = self._db.query_one(
            "SELECT * FROM requests WHERE id = ?", (request_id,))
        return self._decode(row) if row else None

    def list(self, status: str = None, requester: str = None) -> list:
        sql = "SELECT * FROM requests"
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if requester:
            clauses.append("requester = ?")
            params.append(requester)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        return [self._decode(row) for row in self._db.query(sql, params)]

    def decide(self, request_id: int, approver: str, approved: bool,
               reason: str = "") -> dict:
        cursor = self._db.execute(
            "UPDATE requests SET status = ?, approver = ?,"
            "  decision_reason = ?, decided_at = ?"
            " WHERE id = ? AND status = 'pending_approval'",
            ("running" if approved else "rejected", approver, reason,
             _now(), request_id))
        if cursor.rowcount != 1:
            current = self.get(request_id)
            if current is None:
                raise ValueError(f"unknown request {request_id}")
            raise ValueError(
                f"request {request_id} is {current['status']}, "
                "not pending approval")
        return self.get(request_id)

    def mark_running(self, request_id: int) -> dict:
        self._db.execute(
            "UPDATE requests SET status = 'running' WHERE id = ?",
            (request_id,))
        return self.get(request_id)

    def finish(self, request_id: int, status: str, result: dict) -> dict:
        if status not in ("done", "partial", "failed"):
            raise ValueError(f"invalid finish status {status!r}")
        self._db.execute(
            "UPDATE requests SET status = ?, executed_at = ?, result = ?"
            " WHERE id = ?",
            (status, _now(), json.dumps(result), request_id))
        return self.get(request_id)

    @staticmethod
    def _decode(row: dict) -> dict:
        row = dict(row)
        row["payload"] = json.loads(row["payload"])
        row["result"] = (json.loads(row["result"])
                         if row.get("result") else None)
        return row

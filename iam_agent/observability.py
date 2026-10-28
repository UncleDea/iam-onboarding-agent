"""Observability: metrics, structured logging, health, alerts.

An app you cannot see inside is an app you cannot run. This module
gives the system four senses, all small and dependency-free:

- METRICS: thread-safe counters and timings (runs by outcome,
  approvals, rejections, run durations). Exposed as JSON for the
  app's /metrics page and for any external monitor to scrape.
- LOGGING: one setup function. Plain text for a terminal, JSON
  lines for a log aggregator, each line carrying a request_id when
  one is active (set per web request via contextvars).
- HEALTH: a single check that answers "is the system OK?" -- the
  database answers, the audit chain verifies, the provider lists
  users. One failed check means unhealthy, with the reason attached.
- ALERTS: when a run ends partial or failed, an alert is recorded
  and the notifier is called -- but at most once per target per
  15 minutes, so a broken provider does not spam anyone.
"""

import contextvars
import json
import logging
import threading
import time
from datetime import datetime, timezone

request_id_var = contextvars.ContextVar("request_id", default=None)


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = {}
        self._timings = {}

    def increment(self, name: str, tags: dict = None, value: int = 1):
        key = (name, tuple(sorted((tags or {}).items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def observe(self, name: str, seconds: float):
        with self._lock:
            samples = self._timings.setdefault(name, [])
            samples.append(seconds)
            del samples[:-100]  # keep the last 100, not forever

    def snapshot(self) -> dict:
        with self._lock:
            counters = {}
            for (name, tags), value in self._counters.items():
                label = name + (f"[{','.join(f'{k}={v}' for k, v in tags)}]"
                                if tags else "")
                counters[label] = value
            timings = {}
            for name, samples in self._timings.items():
                if samples:
                    timings[name] = {
                        "count": len(samples),
                        "avg_seconds": round(sum(samples) / len(samples), 3),
                        "max_seconds": round(max(samples), 3),
                    }
            return {"counters": counters, "timings": timings}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        return json.dumps(payload)


def setup_logging(json_format: bool = False, level: int = logging.INFO):
    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    return root


def check_health(db, audit_store, provider) -> dict:
    """Run every health check. Returns {status, checks} where
    status is 'healthy' only if every check passed."""
    checks = {}
    try:
        db.query_one("SELECT 1 AS ok")
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 -- health reports, not raises
        checks["database"] = f"error: {exc}"
    try:
        checks["audit_chain"] = ("ok" if audit_store is None
                                 or audit_store.verify()
                                 else "INVALID: chain verification failed")
    except Exception as exc:  # noqa: BLE001
        checks["audit_chain"] = f"error: {exc}"
    try:
        users = provider.list_users() if provider is not None else []
        checks["provider"] = f"ok ({len(users)} users)"
    except Exception as exc:  # noqa: BLE001
        checks["provider"] = f"error: {exc}"
    status = ("healthy" if all(v == "ok" or v.startswith("ok (")
                              for v in checks.values())
              else "unhealthy")
    return {"status": status, "checks": checks}


class AlertManager:
    """Record alerts and notify, with a cooldown per target so one
    broken run does not produce a hundred notifications."""

    COOLDOWN_SECONDS = 15 * 60

    def __init__(self, notifier=None):
        self.notifier = notifier
        self._lock = threading.Lock()
        self._last_alert = {}
        self.alerts = []

    def alert(self, target: str, status: str, summary: str) -> bool:
        """Record an alert; notify unless one fired recently for the
        same target. Returns True if a notification was sent."""
        now = time.time()
        with self._lock:
            self.alerts.append({"target": target, "status": status,
                                "summary": summary,
                                "at": datetime.now(timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%SZ")})
            last = self._last_alert.get(target, 0)
            if now - last < self.COOLDOWN_SECONDS:
                return False
            self._last_alert[target] = now
        if self.notifier is not None:
            try:
                self.notifier.notify(target, f"ALERT: {status}", summary)
            except Exception:  # noqa: BLE001 -- alerts never break runs
                pass
        return True

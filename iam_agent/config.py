"""Centralized configuration.

Every setting the system needs lives here, read once from the
environment at startup, with one validation step that fails fast
and lists everything missing. Before this module, settings were
read in scattered places (CLI, provider, notifier), which meant a
misconfigured deployment started up fine and failed mysteriously
later. Now it fails at startup with a clear list.

Environment variables (all optional unless noted):

    IAM_PROVIDER            mock | sqlite | entra (default: sqlite)
    IAM_DB                  SQLite file (default: iam.db)
    IAM_AUDIT_FILE          optional JSONL audit file
    IAM_LOG_JSON            1 for JSON log lines, 0 for plain text
    IAM_APP_HOST            web app bind host (default: 127.0.0.1)
    IAM_APP_PORT            web app port (default: 8000)
    IAM_APP_ADMIN_USER      bootstrap admin username
    IAM_APP_ADMIN_PASSWORD  bootstrap admin password
    IAM_COOKIE_SECURE       1 to add the Secure flag to the session
                            cookie (set this behind TLS)
    IAM_LOCKOUT_THRESHOLD   failed logins before lockout (default: 5)
    IAM_LOCKOUT_MINUTES     lockout duration in minutes (default: 15)
    IAM_ENTRA_*             see ENTRA_SETUP.md (required when
                            IAM_PROVIDER=entra)
    IAM_SMTP_*              see notifiers.py (optional)
"""

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    provider: str = "sqlite"
    db_path: str = "iam.db"
    audit_file: str = None
    log_json: bool = False
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    app_admin_user: str = None
    app_admin_password: str = None
    session_hours: int = 8
    cookie_secure: bool = False
    lockout_threshold: int = 5
    lockout_minutes: int = 15
    entra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls):
        return cls(
            provider=os.environ.get("IAM_PROVIDER", "sqlite"),
            db_path=os.environ.get("IAM_DB", "iam.db"),
            audit_file=os.environ.get("IAM_AUDIT_FILE"),
            log_json=os.environ.get("IAM_LOG_JSON", "0") == "1",
            app_host=os.environ.get("IAM_APP_HOST", "127.0.0.1"),
            app_port=int(os.environ.get("IAM_APP_PORT", "8000")),
            app_admin_user=os.environ.get("IAM_APP_ADMIN_USER"),
            app_admin_password=os.environ.get("IAM_APP_ADMIN_PASSWORD"),
            session_hours=int(os.environ.get("IAM_SESSION_HOURS", "8")),
            cookie_secure=os.environ.get("IAM_COOKIE_SECURE", "0") == "1",
            lockout_threshold=int(os.environ.get("IAM_LOCKOUT_THRESHOLD",
                                                 "5")),
            lockout_minutes=int(os.environ.get("IAM_LOCKOUT_MINUTES",
                                               "15")),
            entra={name: os.environ.get(name) for name in (
                "IAM_ENTRA_TENANT_ID", "IAM_ENTRA_CLIENT_ID",
                "IAM_ENTRA_CLIENT_SECRET", "IAM_ENTRA_DOMAIN",
                "IAM_ENTRA_TEMP_PASSWORD", "IAM_ENTRA_LICENSE_MAP")},
        )

    def validate(self) -> None:
        """Raise ValueError listing every problem, or return None."""
        problems = []
        if self.provider not in ("mock", "sqlite", "entra"):
            problems.append(f"unknown IAM_PROVIDER {self.provider!r}")
        if self.provider == "entra":
            missing = [name for name in (
                "IAM_ENTRA_TENANT_ID", "IAM_ENTRA_CLIENT_ID",
                "IAM_ENTRA_CLIENT_SECRET", "IAM_ENTRA_DOMAIN",
                "IAM_ENTRA_TEMP_PASSWORD") if not self.entra.get(name)]
            problems.extend(f"missing {name}" for name in missing)
        if problems:
            raise ValueError("invalid configuration: " + "; ".join(problems))

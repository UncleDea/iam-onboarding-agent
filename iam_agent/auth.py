"""App login: who may use the app, and what they may do.

This is separate from the directory the app manages. The directory
holds employees; this module holds the app's own users -- the people
allowed to submit and approve requests. Keeping them separate is
deliberate: the app must work (and be administrable) even if the
directory is unreachable.

- Passwords are hashed with PBKDF2-HMAC-SHA256 (600k iterations, a
  fresh 16-byte salt per password). Only hashes are stored.
- Sessions are random tokens stored server-side with an expiry.
  The browser cookie holds only the token, never identity or roles.
- Roles: admin (everything), approver (approve/reject requests),
  requester (submit requests). An admin may also approve; a
  requester may not approve anything, including their own request.
- Lockout: after N failed logins (default 5), the account locks for
  M minutes (default 15). Lockout is per account, so guessing one
  password cannot lock out everyone.
- Password policy: at least 12 characters, enforced on creation,
  reset, and change. Changing or resetting a password invalidates
  every existing session for that user.
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

ROLES = ("admin", "approver", "requester")

_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_meta(db, key: str, default: str = "") -> str:
    row = db.query_one("SELECT value FROM app_meta WHERE key = ?", (key,))
    return row["value"] if row else default


def set_meta(db, key: str, value: str) -> None:
    db.execute(
        "INSERT INTO app_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value))


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt, _ITERATIONS)
    return (f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}"
            f"${digest.hex()}")


_DUMMY_HASH = hash_password("not-a-real-password")


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


class AuthStore:
    def __init__(self, db, session_hours: int = 8,
                 lockout_threshold: int = 5, lockout_minutes: int = 15):
        self._db = db
        self.session_hours = session_hours
        self.lockout_threshold = lockout_threshold
        self.lockout_minutes = lockout_minutes

    @staticmethod
    def _check_password(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                "password must be at least "
                f"{MIN_PASSWORD_LENGTH} characters")

    def create_user(self, username: str, password: str,
                    role: str) -> dict:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        self._check_password(password)
        if self.get_user(username) is not None:
            raise ValueError(f"app user {username!r} already exists")
        self._db.execute(
            "INSERT INTO app_users (username, password_hash, role,"
            "  created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, _now()))
        return self.get_user(username)

    def get_user(self, username: str):
        row = self._db.query_one(
            "SELECT id, username, role, active, created_at, failed_attempts,"
            "  locked_until FROM app_users WHERE username = ?",
            (username,))
        return row

    def list_users(self) -> list:
        return self._db.query(
            "SELECT id, username, role, active, created_at, failed_attempts,"
            "  locked_until FROM app_users ORDER BY username")

    def set_password(self, username: str, new_password: str) -> None:
        """Admin reset: no current password needed, but every session
        for the user is invalidated, so a compromised session dies
        with the old password."""
        self._check_password(new_password)
        if self.get_user(username) is None:
            raise ValueError(f"unknown app user {username!r}")
        self._db.execute(
            "UPDATE app_users SET password_hash = ?, failed_attempts = 0,"
            "  locked_until = NULL WHERE username = ?",
            (hash_password(new_password), username))
        self._db.execute("DELETE FROM sessions WHERE username = ?",
                         (username,))

    def set_active(self, username: str, active: bool) -> None:
        if self.get_user(username) is None:
            raise ValueError(f"unknown app user {username!r}")
        self._db.execute(
            "UPDATE app_users SET active = ? WHERE username = ?",
            (1 if active else 0, username))
        if not active:
            self._db.execute("DELETE FROM sessions WHERE username = ?",
                             (username,))

    def change_password(self, username: str, current: str,
                        new: str) -> bool:
        """Self-service change. Returns False if the current password
        is wrong (and counts as a failed login for lockout)."""
        row = self._db.query_one(
            "SELECT password_hash FROM app_users WHERE username = ?",
            (username,))
        if row is None or not verify_password(current,
                                              row["password_hash"]):
            self._record_failure(username)
            return False
        self.set_password(username, new)
        return True

    def _record_failure(self, username: str) -> None:
        row = self._db.query_one(
            "SELECT failed_attempts FROM app_users WHERE username = ?",
            (username,))
        if row is None:
            return
        attempts = (row.get("failed_attempts") or 0) + 1
        locked_until = None
        if attempts >= self.lockout_threshold:
            locked_until = (datetime.now(timezone.utc)
                            + timedelta(minutes=self.lockout_minutes))
            locked_until = locked_until.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._db.execute(
            "UPDATE app_users SET failed_attempts = ?, locked_until = ?"
            " WHERE username = ?",
            (attempts, locked_until, username))

    def authenticate(self, username: str, password: str):
        """Return a session token, or None if credentials are wrong,
        the account is inactive, or it is locked out. The caller
        shows the same generic message in all three cases, so a
        login failure never reveals which one it was."""
        row = self._db.query_one(
            "SELECT username, password_hash, role, active, locked_until"
            " FROM app_users WHERE username = ?", (username,))
        if row is None:
            verify_password(password, _DUMMY_HASH)
            return None
        if not row["active"]:
            verify_password(password, row["password_hash"])
            return None
        if row.get("locked_until") and row["locked_until"] > _now():
            return None
        if not verify_password(password, row["password_hash"]):
            self._record_failure(username)
            return None
        self._db.execute(
            "UPDATE app_users SET failed_attempts = 0, locked_until = NULL"
            " WHERE username = ?", (username,))
        return self._issue_session(username)

    def start_session(self, username: str):
        """Open a session for a person Microsoft has already identified.

        Refuses an unknown or inactive account. It does not create users.
        """
        row = self._db.query_one(
            "SELECT username, active, locked_until FROM app_users "
            "WHERE username = ?", (username,))
        if row is None or not row["active"]:
            return None
        if row.get("locked_until") and row["locked_until"] > _now():
            return None
        return self._issue_session(username)

    def _issue_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        expires = (datetime.now(timezone.utc)
                   + timedelta(hours=self.session_hours))
        self._db.execute(
            "INSERT INTO sessions (token, username, csrf_token,"
            "  expires_at) VALUES (?, ?, ?, ?)",
            (token, username, csrf,
             expires.strftime("%Y-%m-%dT%H:%M:%SZ")))
        return token

    def get_session(self, token: str):
        """Return {username, role, csrf_token} or None if expired/unknown."""
        row = self._db.query_one(
            "SELECT s.username, s.csrf_token, s.expires_at, u.role"
            " FROM sessions s JOIN app_users u ON u.username = s.username"
            " WHERE s.token = ? AND u.active = 1", (token,))
        if row is None or row["expires_at"] <= _now():
            return None
        return {"username": row["username"], "role": row["role"],
                "csrf_token": row["csrf_token"]}

    def logout(self, token: str) -> None:
        self._db.execute("DELETE FROM sessions WHERE token = ?", (token,))

    def ensure_admin(self, username: str, password: str):
        """Create the bootstrap admin if no app users exist yet.
        Returns True if an admin was created, False if users already
        exist (in which case nothing changes)."""
        existing = self._db.query_one("SELECT COUNT(*) AS n FROM app_users")
        if existing and existing["n"] > 0:
            return False
        self.create_user(username, password, "admin")
        return True

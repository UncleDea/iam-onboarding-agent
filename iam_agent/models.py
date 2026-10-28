"""Data shapes for the IAM on-boarding agent.

These are plain containers with no behaviour. The engine builds plans out
of PlanSteps, and every executed step is recorded as an AuditEntry.
"""

import re
from dataclasses import dataclass, field

# Usernames become account names in real systems, so they must be safe
# there too: lowercase, starting with a letter or digit, then letters,
# digits, dots, underscores or dashes. Rejecting bad input here -- at
# the boundary -- is far cheaper than debugging a failed API call later.
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class NewHire:
    """One person to on-board. Nothing here is tied to any vendor."""

    first_name: str
    last_name: str
    username: str  # e.g. "ada.lovelace" -- the part before the @
    department: str
    role: str  # e.g. "engineer", "sales", "manager" (see policies.py)
    manager: str = ""
    start_date: str = ""  # free text, e.g. "2026-11-02"
    email: str = ""  # optional: where the welcome email goes

    def __post_init__(self) -> None:
        if not self.first_name.strip() or not self.last_name.strip():
            raise ValueError("first_name and last_name must not be blank")
        if not _USERNAME_RE.match(self.username):
            raise ValueError(
                f"invalid username {self.username!r}: use 3-64 lowercase "
                "letters, digits, '.', '_' or '-', starting with a "
                "letter or digit"
            )
        if not self.department.strip() or not self.role.strip():
            raise ValueError("department and role must not be blank")
        if self.email and not _EMAIL_RE.match(self.email):
            raise ValueError(f"invalid email address {self.email!r}")

    @property
    def display_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


@dataclass
class PlanStep:
    """One action the agent intends to take."""

    action: str  # "create_user", "add_to_group", "assign_license", "send_welcome"
    description: str  # human-readable, shown at approval time
    details: dict = field(default_factory=dict)


@dataclass
class AuditEntry:
    """One line in the audit log: what happened, to whom, and how it went."""

    timestamp: str
    action: str
    target: str
    status: str  # "done", "skipped", "rejected", "failed"
    note: str = ""

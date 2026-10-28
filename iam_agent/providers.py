"""Identity providers: the seam that keeps the agent general.

An IdentityProvider is any system that can hold user accounts -- Entra ID,
Google Workspace, Okta, or a plain database. The engine only ever talks
to this interface, so swapping the system underneath means writing one
new class, not rewriting the agent.

MockProvider is a fake provider that keeps everything in memory. It lets
you run and test the whole agent with zero accounts, credentials, or
network access. Replace it with a real provider when you are ready (see
examples/entra_provider_stub.py for the shape of one).
"""

from abc import ABC, abstractmethod


class IdentityProvider(ABC):
    """The contract every provider must fulfil."""

    @abstractmethod
    def create_user(self, hire) -> dict:
        """Create the account. Returns the created user record."""

    @abstractmethod
    def get_user(self, username: str):
        """Return the user record, or None if there is no such user."""

    @abstractmethod
    def update_user(self, username: str, **fields) -> None:
        """Update stored attributes (department, role, manager, ...)."""

    @abstractmethod
    def add_to_group(self, username: str, group: str) -> None:
        """Add an existing user to a group."""

    @abstractmethod
    def remove_from_group(self, username: str, group: str) -> None:
        """Remove a user from a group (no-op if not a member)."""

    @abstractmethod
    def assign_license(self, username: str, license_name: str) -> None:
        """Give an existing user a licence."""

    @abstractmethod
    def revoke_license(self, username: str, license_name: str) -> None:
        """Take a licence away (no-op if not held)."""

    @abstractmethod
    def disable_user(self, username: str) -> None:
        """Disable an account (the first step of off-boarding)."""


class MockProvider(IdentityProvider):
    """In-memory provider for learning and testing."""

    def __init__(self):
        self.users = {}  # username -> record
        self._next_id = 1

    def create_user(self, hire) -> dict:
        if hire.username in self.users:
            raise ValueError(f"user {hire.username!r} already exists")
        record = {
            "id": f"user-{self._next_id:03d}",
            "username": hire.username,
            "display_name": hire.display_name,
            "department": hire.department,
            "role": hire.role,
            "manager": hire.manager,
            "groups": [],
            "licenses": [],
            "active": True,
        }
        self._next_id += 1
        self.users[hire.username] = record
        return record

    def get_user(self, username: str):
        return self.users.get(username)

    def update_user(self, username: str, **fields) -> None:
        user = self._get(username)
        for key, value in fields.items():
            if key in ("department", "role", "manager"):
                user[key] = value

    def add_to_group(self, username: str, group: str) -> None:
        user = self._get(username)
        if group not in user["groups"]:
            user["groups"].append(group)

    def remove_from_group(self, username: str, group: str) -> None:
        user = self._get(username)
        if group in user["groups"]:
            user["groups"].remove(group)

    def assign_license(self, username: str, license_name: str) -> None:
        user = self._get(username)
        if license_name not in user["licenses"]:
            user["licenses"].append(license_name)

    def revoke_license(self, username: str, license_name: str) -> None:
        user = self._get(username)
        if license_name in user["licenses"]:
            user["licenses"].remove(license_name)

    def disable_user(self, username: str) -> None:
        self._get(username)["active"] = False

    def list_users(self) -> list:
        return list(self.users.values())

    def _get(self, username: str) -> dict:
        try:
            return self.users[username]
        except KeyError:
            raise ValueError(f"unknown user {username!r}") from None

"""Access policy loaded from one JSON file.

Operators change roles, the unknown-role fallback, segregation pairs,
and which access counts as privileged by editing that file (or, later,
the Policy page, which writes the same file). Nothing in this module
chooses access on its own, and nothing here runs at import time.
"""

import json
import os
from pathlib import Path


_REQUIRED = (
    "roles",
    "fallback",
    "conflicts",
    "privileged_roles",
    "privileged_groups",
    "privileged_licenses",
)


class PolicyError(ValueError):
    """The policy file is missing or does not match the required shape."""


class Policy:
    """The rules for one organisation, already validated."""

    def __init__(self, roles, fallback, conflicts, privileged_roles,
                 privileged_groups, privileged_licenses):
        self.roles = {
            name.lower(): {
                "groups": list(access["groups"]),
                "licenses": list(access["licenses"]),
            }
            for name, access in roles.items()
        }
        self.fallback = {
            "groups": list(fallback["groups"]),
            "licenses": list(fallback["licenses"]),
        }
        self.conflicts = [frozenset(pair) for pair in conflicts]
        self.privileged_roles = {role.lower() for role in privileged_roles}
        self.privileged_groups = set(privileged_groups)
        self.privileged_licenses = set(privileged_licenses)
        self.source = ""

    def access_for(self, role: str) -> dict:
        """Groups and licences for a role.

        An unknown role gets the fallback. That default is in the
        policy file, and it is closed: all-staff, no licences, unless
        the file says otherwise.
        """
        found = self.roles.get(role.lower())
        if found is None:
            return {
                "groups": list(self.fallback["groups"]),
                "licenses": list(self.fallback["licenses"]),
            }
        return {
            "groups": list(found["groups"]),
            "licenses": list(found["licenses"]),
        }

    def find_conflicts(self, groups) -> list:
        """Conflicting pairs contained in `groups`."""
        held = set(groups)
        return [sorted(conflict) for conflict in self.conflicts
                if conflict <= held]

    def with_roles(self, extra: dict) -> "Policy":
        """Copy with extra roles merged in. Used by tests."""
        roles = {name: dict(access) for name, access in self.roles.items()}
        for name, access in extra.items():
            roles[name.lower()] = {
                "groups": list(access["groups"]),
                "licenses": list(access["licenses"]),
            }
        copied = Policy(
            roles, self.fallback, [sorted(pair) for pair in self.conflicts],
            self.privileged_roles, self.privileged_groups,
            self.privileged_licenses)
        copied.source = self.source
        return copied


def _access_lists(value, where: str) -> dict:
    if not isinstance(value, dict) or "groups" not in value \
            or "licenses" not in value:
        raise PolicyError(f"{where} needs 'groups' and 'licenses' lists")
    if not isinstance(value["groups"], list) \
            or not isinstance(value["licenses"], list):
        raise PolicyError(f"{where} 'groups' and 'licenses' must be lists")
    return value


def _parse(data, source: str) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError(f"policies file {source} must be a JSON object")
    missing = [key for key in _REQUIRED if key not in data]
    if missing:
        raise PolicyError(
            f"policies file {source} must contain "
            + ", ".join(_REQUIRED)
            + f"; missing {', '.join(missing)}"
        )
    roles = data["roles"]
    if not isinstance(roles, dict) or not roles:
        raise PolicyError(f"policies file {source}: 'roles' must be an object")
    parsed_roles = {
        name: _access_lists(access, f"role {name!r}")
        for name, access in roles.items()
    }
    fallback = _access_lists(data["fallback"], "fallback")
    conflicts = data["conflicts"]
    if not isinstance(conflicts, list):
        raise PolicyError(f"policies file {source}: 'conflicts' must be a list")
    for pair in conflicts:
        if not isinstance(pair, list) or len(pair) < 2 \
                or not all(isinstance(item, str) for item in pair):
            raise PolicyError(
                f"policies file {source}: each conflict must be a list "
                "of two or more group names")
    for key in ("privileged_roles", "privileged_groups",
                "privileged_licenses"):
        if not isinstance(data[key], list) \
                or not all(isinstance(item, str) for item in data[key]):
            raise PolicyError(
                f"policies file {source}: '{key}' must be a list of strings")
    return Policy(
        parsed_roles, fallback, conflicts,
        data["privileged_roles"], data["privileged_groups"],
        data["privileged_licenses"])


def policy_document(policy: Policy) -> dict:
    return {
        "roles": policy.roles,
        "fallback": policy.fallback,
        "conflicts": [sorted(pair) for pair in policy.conflicts],
        "privileged_roles": sorted(policy.privileged_roles),
        "privileged_groups": sorted(policy.privileged_groups),
        "privileged_licenses": sorted(policy.privileged_licenses),
    }


def save_policy(policy: Policy, path) -> None:
    """Write a validated policy. Callers validate before this."""
    Path(path).write_text(
        json.dumps(policy_document(policy), indent=2) + "\n",
        encoding="utf-8")


def policy_candidates(path=None) -> list:
    """Paths tried, in order. The first file that exists is the policy."""
    candidates = []
    if path is not None:
        candidates.append(Path(path))
    if os.environ.get("IAM_POLICIES_FILE"):
        candidates.append(Path(os.environ["IAM_POLICIES_FILE"]))
    candidates.append(Path.cwd() / "policies.json")
    candidates.append(Path(__file__).resolve().parent.parent / "policies.json")
    return candidates


def load_policy(path=None) -> Policy:
    """Load and validate the policy. Call this at startup, not at import."""
    tried = []
    for candidate in policy_candidates(path):
        tried.append(str(candidate))
        if not candidate.is_file():
            continue
        data = json.loads(candidate.read_text(encoding="utf-8"))
        policy = _parse(data, str(candidate))
        policy.source = str(candidate)
        return policy
    raise PolicyError(
        "no policies file found. Looked for "
        + ", ".join(tried)
        + ". A policy file must contain "
        + ", ".join(_REQUIRED))

"""Access policies: which role gets which groups and licences.

This is the "brain" of what access means in your organisation. Change this
file and the agent's behaviour changes everywhere, without touching the
engine or any provider. A real deployment would load this from a file or
a database; a plain dictionary keeps the from-scratch version readable.
"""

import json
import os
from pathlib import Path

_DEFAULT_ROLE_ACCESS = {
    "engineer": {
        "groups": ["all-staff", "engineering"],
        "licenses": ["office-standard"],
    },
    "sales": {
        "groups": ["all-staff", "sales"],
        "licenses": ["office-standard", "crm"],
    },
    "manager": {
        "groups": ["all-staff", "managers"],
        "licenses": ["office-standard"],
    },
}

FALLBACK = {"groups": ["all-staff"], "licenses": []}

# Segregation of duties: groups that must never be held together, because
# one person could then both perform and approve the same sensitive act.
# The engine refuses to build a plan that violates this, before anything
# is created. Add your own pairs here as the organisation grows.
CONFLICTING_GROUPS = [
    frozenset({"payment-create", "payment-approve"}),
]


def load_role_access(path=None) -> dict:
    """Load the role table, so operators change policy without code.

    Lookup order: IAM_POLICIES_FILE env var, ./policies.json in the
    working directory, policies.json next to the project, then the
    built-in defaults. A file must be an object mapping role names to
    {"groups": [...], "licenses": [...]}; anything else is an error,
    because silently running on a broken policy file would be worse
    than refusing to start.
    """
    candidates = []
    if path is not None:
        candidates.append(Path(path))
    if os.environ.get("IAM_POLICIES_FILE"):
        candidates.append(Path(os.environ["IAM_POLICIES_FILE"]))
    candidates.append(Path.cwd() / "policies.json")
    candidates.append(Path(__file__).resolve().parent.parent / "policies.json")
    for candidate in candidates:
        if candidate.is_file():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"policies file {candidate} must be a JSON object")
            for role, access in data.items():
                if not isinstance(access, dict) or "groups" not in access \
                        or "licenses" not in access:
                    raise ValueError(
                        f"policies file {candidate}: role {role!r} needs "
                        "'groups' and 'licenses' lists"
                    )
            return {role.lower(): access for role, access in data.items()}
    return dict(_DEFAULT_ROLE_ACCESS)


ROLE_ACCESS = load_role_access()


def access_for(role: str) -> dict:
    """Return the groups and licences for a role.

    Unknown roles get the fallback: every employee lands in "all-staff"
    and nothing else. That is a deliberate safe default -- an unknown
    role should never silently grant extra access.
    """
    return ROLE_ACCESS.get(role.lower(), FALLBACK)


def find_conflicts(groups) -> list:
    """Return the conflicting group sets contained in `groups`."""
    held = set(groups)
    return [sorted(conflict) for conflict in CONFLICTING_GROUPS
            if conflict <= held]

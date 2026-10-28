"""Human-in-the-loop approval routing.

Not every approval needs a human. Making a person click "yes" on every
routine on-boarding trains them to click "yes" without reading -- which
is worse than useless. So approvals are routed by risk:

- STANDARD plans auto-approve: known role, ordinary groups and licences.
- HUMAN plans stop for a person: privileged roles, privileged groups or
  licences, or a role the policy table does not know at all.

The router returns (approved, decided_by) tuples instead of a bare
boolean, so the engine can audit *who* decided -- "auto" for routine
plans, a person's name for human ones. An approval nobody can attribute
to anyone is not an approval at all.
"""

from . import policies


# Groups whose membership is powerful enough that a human must sign off.
PRIVILEGED_GROUPS = {"managers", "admins", "domain-admins", "finance-admins"}

# Licences that unlock administrative tooling.
PRIVILEGED_LICENSES = {"admin-tools"}

# Roles that are privileged by definition, whatever groups they map to.
HUMAN_REQUIRED_ROLES = {"manager", "admin", "administrator"}


def classify(plan, hire):
    """Decide how a plan must be approved.

    Returns (level, reason) where level is "auto" or "human".
    Only groups being *added* count toward privilege: move and
    offboard plans remove groups, and removing access never needs
    the same scrutiny as granting it. `hire` may be a minimal
    object without a role (move/offboard flows), which is treated
    as an unknown role only when nothing else classifies it.
    """
    groups = {step.details.get("group") for step in plan
              if step.action == "add_to_group"}
    licences = {step.details.get("license") for step in plan
                if step.action == "assign_license"}
    role = getattr(hire, "role", "") or ""

    if role.lower() in HUMAN_REQUIRED_ROLES:
        return "human", f"role {role!r} is privileged"
    privileged_groups = groups & PRIVILEGED_GROUPS
    if privileged_groups:
        return "human", ("privileged group(s): "
                         + ", ".join(sorted(privileged_groups)))
    privileged_licences = licences & PRIVILEGED_LICENSES
    if privileged_licences:
        return "human", ("privileged licence(s): "
                         + ", ".join(sorted(privileged_licences)))
    if role and role.lower() not in policies.ROLE_ACCESS:
        return "human", f"unknown role {role!r} needs human judgement"
    return "auto", "standard access only"


def terminal_human_approver(plan, hire) -> bool:
    """Ask a human at the terminal. Returns True only on 'y'."""
    print(f"\nHUMAN APPROVAL requested for {hire.display_name}:")
    for i, step in enumerate(plan, 1):
        print(f"  {i}. {step.description}")
    answer = input("Approve this plan? [y/n]: ").strip().lower()
    return answer.startswith("y")


def make_approver(human_fn=terminal_human_approver, human_name="human"):
    """Build an engine approver with risk-based routing.

    human_fn is called only for plans classified "human". It must take
    (plan, hire) and return a boolean. The returned callable returns
    (approved, decided_by) tuples for the audit trail.
    """
    def approver(plan, hire):
        level, reason = classify(plan, hire)
        if level == "auto":
            return True, f"auto ({reason})"
        return bool(human_fn(plan, hire)), human_name

    return approver

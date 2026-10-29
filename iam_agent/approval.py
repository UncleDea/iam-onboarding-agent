"""Who may approve a frozen plan.

Every grant waits for a person. The level only changes which role
that person must hold:

- standard: an approver or an admin, never the requester
- privileged: an admin, never the requester

Privileged means a privileged role, a privileged group or licence
being added, or a role the policy does not know. Those lists live
on the Policy loaded from policies.json. Removing access is
standard: an offboard does not become privileged because it drops
an admin group.
"""


def _granted_roles(plan, hire) -> list:
    roles = []
    role = getattr(hire, "role", "") or ""
    if role:
        roles.append(role)
    for step in plan:
        if step.action in ("create_user", "update_user"):
            granted = (step.details or {}).get("role") or ""
            if granted:
                roles.append(granted)
    return roles


def classify(plan, hire, policy):
    """Return (level, reason) where level is "standard" or "privileged"."""
    groups = {step.details.get("group") for step in plan
              if step.action == "add_to_group" and step.details.get("group")}
    licences = {step.details.get("license") for step in plan
                if step.action == "assign_license"
                and step.details.get("license")}
    for role in _granted_roles(plan, hire):
        if role.lower() in policy.privileged_roles:
            return "privileged", f"role {role!r} is privileged"
        if role.lower() not in policy.roles:
            return "privileged", f"unknown role {role!r} needs an admin"
    privileged_groups = groups & policy.privileged_groups
    if privileged_groups:
        return "privileged", ("privileged group(s): "
                              + ", ".join(sorted(privileged_groups)))
    privileged_licences = licences & policy.privileged_licenses
    if privileged_licences:
        return "privileged", ("privileged licence(s): "
                              + ", ".join(sorted(privileged_licences)))
    return "standard", "standard access only"


def may_decide(actor_role: str, level: str, requester: str,
               approver: str):
    """Return (allowed, reason). reason is empty when allowed is True."""
    if requester == approver:
        return False, "requester cannot approve their own request"
    if actor_role not in ("admin", "approver"):
        return False, f"role {actor_role!r} may not decide requests"
    if level == "privileged" and actor_role != "admin":
        return False, "privileged access requires an admin"
    if level not in ("standard", "privileged"):
        return False, f"unknown approval level {level!r}"
    return True, ""


def terminal_human_approver(plan, hire) -> bool:
    """Ask a human at the terminal. Returns True only on 'y'."""
    print(f"\nApproval requested for {hire.display_name}:")
    for i, step in enumerate(plan, 1):
        print(f"  {i}. {step.description}")
    answer = input("Approve this plan? [y/n]: ").strip().lower()
    return answer.startswith("y")


def make_approver(human_fn=terminal_human_approver, human_name="human",
                  policy=None):
    """Build an engine approver that always asks human_fn.

    `policy` is accepted so older callers keep working. The level is
    not used to skip the person: the service decides which role may
    approve, and this helper only collects a yes or no.
    """
    del policy

    def approver(plan, hire):
        return bool(human_fn(plan, hire)), human_name

    return approver

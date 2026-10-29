"""Reporting: turn stored state into answers a human can act on.

Four reports, each available as JSON (for machines and the app) and
CSV (for spreadsheets and auditors):

- access: every user, their groups and licences, plus totals.
- activity: audit entries grouped by action and status, and per day.
- approvals: requests grouped by status, plus how long decisions
  took (created_at -> decided_at) where both timestamps exist.
- summary: the three above, condensed to headline numbers.

Reports read from the provider, the audit store, and the request
store -- the same sources the app itself uses, so a report can
never disagree with what the app shows.
"""

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime


def access_report(provider) -> dict:
    users = provider.list_users()
    groups = Counter()
    licenses = Counter()
    for user in users:
        groups.update(user.get("groups", []))
        licenses.update(user.get("licenses", []))
    return {
        "total_users": len(users),
        "active_users": sum(1 for u in users if u.get("active")),
        "disabled_users": sum(1 for u in users if not u.get("active")),
        "groups": dict(groups),
        "licenses": dict(licenses),
        "users": users,
    }


def group_index(provider, policy) -> list:
    """Who is in each group. Derived from the policy and the directory.

    A group is listed if the policy names it or anyone holds it.
    Privileged groups come first. Inherited membership stays separate
    from direct membership.
    """
    names = set(policy.privileged_groups)
    names.update(policy.fallback["groups"])
    for access in policy.roles.values():
        names.update(access["groups"])
    direct = {}
    inherited = {}
    for user in provider.list_users():
        username = user.get("username") or ""
        for group in user.get("groups") or []:
            names.add(group)
            direct.setdefault(group, []).append(username)
        for group in user.get("inherited_groups") or []:
            names.add(group)
            inherited.setdefault(group, []).append(username)
    rows = [{
        "name": name,
        "privileged": name in policy.privileged_groups,
        "members": sorted(direct.get(name, [])),
        "inherited": sorted(inherited.get(name, [])),
    } for name in names]
    rows.sort(key=lambda row: (not row["privileged"], row["name"]))
    return rows


def activity_report(audit_entries) -> dict:
    by_action = Counter()
    by_status = Counter()
    by_day = Counter()
    for entry in audit_entries:
        by_action[entry["action"]] += 1
        by_status[entry["status"]] += 1
        by_day[entry["timestamp"][:10]] += 1
    return {
        "total_entries": len(audit_entries),
        "by_action": dict(by_action),
        "by_status": dict(by_status),
        "by_day": dict(sorted(by_day.items())),
    }


def approval_report(requests) -> dict:
    by_status = Counter()
    decision_seconds = []
    for request in requests:
        by_status[request["status"]] += 1
        if request.get("created_at") and request.get("decided_at"):
            fmt = "%Y-%m-%dT%H:%M:%SZ"
            try:
                delta = (datetime.strptime(request["decided_at"], fmt)
                         - datetime.strptime(request["created_at"], fmt))
                decision_seconds.append(delta.total_seconds())
            except ValueError:
                pass
    report = {
        "total_requests": len(requests),
        "by_status": dict(by_status),
    }
    if decision_seconds:
        report["avg_decision_seconds"] = round(
            sum(decision_seconds) / len(decision_seconds), 1)
        report["max_decision_seconds"] = max(decision_seconds)
    return report


def summary_report(provider, audit_entries, requests) -> dict:
    access = access_report(provider)
    activity = activity_report(audit_entries)
    approvals = approval_report(requests)
    return {
        "users": {"total": access["total_users"],
                  "active": access["active_users"],
                  "disabled": access["disabled_users"]},
        "audit_entries": activity["total_entries"],
        "audit_by_status": activity["by_status"],
        "requests": approvals,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_csv(report: dict, kind: str) -> str:
    """Flatten one report kind to CSV. Access gives one row per user;
    activity and approvals give metric/value rows."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if kind == "access":
        writer.writerow(["username", "display_name", "department", "role",
                         "active", "groups", "licenses"])
        for user in report["users"]:
            writer.writerow([user["username"], user.get("display_name", ""),
                             user.get("department", ""), user.get("role", ""),
                             user.get("active", ""),
                             ";".join(user.get("groups", [])),
                             ";".join(user.get("licenses", []))])
    else:
        writer.writerow(["metric", "value"])
        def _flatten(prefix, value):
            if isinstance(value, dict):
                for key, sub in value.items():
                    _flatten(f"{prefix}.{key}" if prefix else key, sub)
            elif isinstance(value, list):
                writer.writerow([prefix, f"{len(value)} items"])
            else:
                writer.writerow([prefix, value])
        _flatten("", report)
    return buffer.getvalue()

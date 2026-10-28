"""The on-boarding agent itself -- now a real system core.

Every flow follows the same shape, because that shape is the safety
design:

1. PLAN  -- build a checklist (no side effects).
2. APPROVE -- a human (or a routed auto-decision) approves the exact
   plan. The requester can never approve their own request.
3. EXECUTE -- run the steps through the provider, retrying transient
   failures. If a step fails, already-done steps are compensated
   (undone) in reverse order, so nobody is left half-provisioned.
4. AUDIT -- every decision, step, and compensation is logged, in
   memory, to a JSONL file, and/or to a tamper-evident SQLite store.
5. NOTIFY -- someone is told the outcome (manager, hire, ticket).

Dry-run mode stops after step 1, so you can see exactly what *would*
happen before anything real occurs.
"""

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone

from .emailing import welcome_body, welcome_subject
from .models import AuditEntry, NewHire, PlanStep
from .policies import access_for, find_conflicts
from .retry import TransientError, call_with_retry

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# What undoes each action, for compensation on partial failure.
_COMPENSATION = {
    "create_user": "disable_user",
    "add_to_group": "remove_from_group",
    "assign_license": "revoke_license",
}


class OnboardingAgent:
    def __init__(self, provider, approver=None, audit_file=None,
                 audit_store=None, notifier=None, retry_attempts: int = 3,
                 email_sender=None):
        """provider: an IdentityProvider. approver: optional callable
        taking (plan, hire) and returning a boolean or a
        (approved, decided_by) tuple -- see iam_agent.approval.
        audit_file: optional JSONL path. audit_store: optional
        SqliteAuditStore. notifier: optional object with
        notify(username, status, summary). retry_attempts: tries per
        step for transient failures. email_sender: optional object
        with send(to, subject, body) -- see iam_agent.emailing.
        """
        self.provider = provider
        self.approver = approver
        self.audit_file = audit_file
        self.audit_store = audit_store
        self.notifier = notifier
        self.retry_attempts = retry_attempts
        self.email_sender = email_sender
        self.audit = []

    # -- on-boarding ----------------------------------------------------

    def build_plan(self, hire: NewHire) -> list:
        """Build the full checklist for one hire. Pure: no side effects.

        Raises ValueError on a segregation-of-duties conflict. Failing
        here -- before approval, before any side effect -- is deliberate:
        a plan that would grant a toxic combination must never reach
        an approver's desk looking normal.
        """
        access = access_for(hire.role)
        conflicts = find_conflicts(access["groups"])
        if conflicts:
            raise ValueError(
                f"segregation-of-duties conflict for role {hire.role!r}: "
                f"{conflicts[0]} must never be held together"
            )
        plan = [
            PlanStep(
                "create_user",
                f"Create account for {hire.display_name} ({hire.username})",
                {"department": hire.department, "role": hire.role},
            )
        ]
        for group in access["groups"]:
            plan.append(PlanStep(
                "add_to_group",
                f"Add {hire.username} to group {group!r}",
                {"group": group},
            ))
        for licence in access["licenses"]:
            plan.append(PlanStep(
                "assign_license",
                f"Assign licence {licence!r} to {hire.username}",
                {"license": licence},
            ))
        plan.append(PlanStep(
            "send_welcome",
            f"Prepare welcome message for {hire.display_name}",
            {"manager": hire.manager, "start_date": hire.start_date},
        ))
        return plan

    def run(self, hire: NewHire, dry_run: bool = False,
            requester: str = None) -> dict:
        """Run one on-boarding end to end. Returns a result summary."""
        plan = self.build_plan(hire)
        if dry_run:
            return {"hire": hire.username, "planned": plan, "executed": [],
                    "status": "dry-run"}

        approved, decided_by = self._approve(plan, hire, requester)
        if not approved:
            self._log("approve", hire.username, "rejected",
                      f"plan not approved by {decided_by}")
            result = {"hire": hire.username, "planned": plan,
                      "executed": [], "status": "rejected"}
            self._notify(hire.username, result["status"], "plan rejected")
            return result
        self._log("approve", hire.username, "done",
                  f"plan approved by {decided_by}")

        executed = []
        status = "done"
        for step in plan:
            if step.action == "send_welcome":
                # The welcome email is deliberately outside the
                # retry/compensation machinery: it is non-critical.
                # A missing address or sender skips it; a sending
                # failure is logged, not allowed to roll back an
                # account that was correctly created.
                welcome_status, note = self._send_welcome(hire, step)
                self._log(step.action, hire.username, welcome_status, note)
                executed.append(step)
                continue
            try:
                self._execute_with_retry(step, hire)
                self._log(step.action, hire.username, "done",
                          step.description)
                executed.append(step)
            except ValueError as exc:
                # Idempotent resume: if the account already exists, the
                # run is being repeated (or partially retried). Skip
                # creation and continue with groups and licences instead
                # of failing the whole on-boarding.
                if step.action == "create_user" and "already exists" in str(exc):
                    self._log(step.action, hire.username, "skipped",
                              f"{hire.username} already exists; continuing")
                    executed.append(step)
                    continue
                self._log(step.action, hire.username, "failed", str(exc))
                status = "partial"
                break
            except Exception as exc:  # noqa: BLE001 -- reported, not hidden
                self._log(step.action, hire.username, "failed", str(exc))
                status = "partial"
                break
        if status == "partial":
            self._compensate(executed, hire)
        logger.info("onboarding %s: %s", hire.username, status)
        result = {"hire": hire.username, "planned": plan,
                  "executed": executed, "status": status}
        self._notify(hire.username, status,
                     f"{len(executed)}/{len(plan)} steps executed")
        return result

    # -- mover ----------------------------------------------------------

    def build_move_plan(self, username: str, new_role: str,
                        new_department: str = None) -> list:
        """Plan a role/department move as a diff: remove what the old
        role had that the new role does not, add what the new role has
        that the old one did not. Access never just accumulates."""
        current = self.provider.get_user(username)
        if current is None:
            raise ValueError(f"unknown user {username!r}")
        target = access_for(new_role)
        plan = []
        for group in sorted(set(current["groups"]) - set(target["groups"])):
            plan.append(PlanStep("remove_from_group",
                                 f"Remove {username} from group {group!r}",
                                 {"group": group}))
        for group in sorted(set(target["groups"]) - set(current["groups"])):
            plan.append(PlanStep("add_to_group",
                                 f"Add {username} to group {group!r}",
                                 {"group": group}))
        for licence in sorted(set(current["licenses"]) - set(target["licenses"])):
            plan.append(PlanStep("revoke_license",
                                 f"Revoke licence {licence!r} from {username}",
                                 {"license": licence}))
        for licence in sorted(set(target["licenses"]) - set(current["licenses"])):
            plan.append(PlanStep("assign_license",
                                 f"Assign licence {licence!r} to {username}",
                                 {"license": licence}))
        plan.append(PlanStep("update_user",
                             f"Move {username} to role {new_role!r}",
                             {"role": new_role,
                              **({"department": new_department}
                                  if new_department else {})}))
        return plan

    def move(self, username: str, new_role: str, new_department: str = None,
             dry_run: bool = False, requester: str = None) -> dict:
        plan = self.build_move_plan(username, new_role, new_department)
        if dry_run:
            return {"hire": username, "planned": plan, "executed": [],
                    "status": "dry-run"}
        approved, decided_by = self._approve(
            plan, _MoveHire(username), requester)
        if not approved:
            self._log("approve", username, "rejected",
                      f"move not approved by {decided_by}")
            return {"hire": username, "planned": plan, "executed": [],
                    "status": "rejected"}
        self._log("approve", username, "done",
                  f"move approved by {decided_by}")
        executed = []
        for step in plan:
            try:
                self._execute_with_retry(step, _MoveHire(username))
                self._log(step.action, username, "done", step.description)
                executed.append(step)
            except Exception as exc:  # noqa: BLE001
                self._log(step.action, username, "failed", str(exc))
                break
        status = "done" if len(executed) == len(plan) else "partial"
        return {"hire": username, "planned": plan, "executed": executed,
                "status": status}

    # -- leaver ---------------------------------------------------------

    def build_offboard_plan(self, username: str) -> list:
        """Plan a leaving: disable first (immediate lockout), then strip
        every group and licence. Order matters: disable first, so a
        failure later cannot leave an active account behind."""
        current = self.provider.get_user(username)
        if current is None:
            raise ValueError(f"unknown user {username!r}")
        plan = [PlanStep("disable_user", f"Disable account {username}", {})]
        for group in current["groups"]:
            plan.append(PlanStep("remove_from_group",
                                 f"Remove {username} from group {group!r}",
                                 {"group": group}))
        for licence in current["licenses"]:
            plan.append(PlanStep("revoke_license",
                                 f"Revoke licence {licence!r} from {username}",
                                 {"license": licence}))
        return plan

    def offboard(self, username: str, dry_run: bool = False,
                 requester: str = None) -> dict:
        plan = self.build_offboard_plan(username)
        if dry_run:
            return {"hire": username, "planned": plan, "executed": [],
                    "status": "dry-run"}
        approved, decided_by = self._approve(
            plan, _MoveHire(username), requester)
        if not approved:
            self._log("approve", username, "rejected",
                      f"offboarding not approved by {decided_by}")
            return {"hire": username, "planned": plan, "executed": [],
                    "status": "rejected"}
        self._log("approve", username, "done",
                  f"offboarding approved by {decided_by}")
        executed = []
        for step in plan:
            try:
                self._execute_with_retry(step, _MoveHire(username))
                self._log(step.action, username, "done", step.description)
                executed.append(step)
            except Exception as exc:  # noqa: BLE001
                self._log(step.action, username, "failed", str(exc))
                break
        status = "done" if len(executed) == len(plan) else "partial"
        return {"hire": username, "planned": plan, "executed": executed,
                "status": status}

    # -- internals ------------------------------------------------------

    def _approve(self, plan, hire, requester):
        """Return (approved, decided_by), enforcing requester != approver."""
        if self.approver is None:
            return True, "auto (no approver configured)"
        decision = self.approver(plan, hire)
        if isinstance(decision, tuple):
            approved, decided_by = decision
        else:
            approved, decided_by = decision, "human"
        if approved and requester and decided_by == requester:
            # Segregation of duties: you cannot approve your own request.
            # This is refused here, not just logged, because an approval
            # that violates it is void.
            self._log("approve", hire.username, "rejected",
                      f"requester {requester!r} cannot approve own request")
            return False, decided_by
        return bool(approved), decided_by

    def _send_welcome(self, hire, step: PlanStep):
        """Send the welcome email. Returns (status, note) where
        status is done, skipped, or failed. Never raises: welcome
        mail must not break on-boarding."""
        recipient = getattr(hire, "email", "") or ""
        if not recipient:
            return ("skipped",
                    f"{step.description} -- skipped: no email address "
                    "on file")
        if self.email_sender is None:
            return ("skipped",
                    f"{step.description} -- skipped: no email sender "
                    "configured (see IAM_SMTP_* / IAM_EMAIL_CONSOLE)")
        try:
            self.email_sender.send(recipient, welcome_subject(hire),
                                   welcome_body(hire))
        except Exception as exc:  # noqa: BLE001 -- logged, run continues
            logger.warning("welcome email to %s failed: %s", recipient, exc)
            return ("failed",
                    f"{step.description} -- welcome email failed: {exc} "
                    "(on-boarding itself succeeded)")
        return ("done",
                f"{step.description} -- welcome email sent to {recipient}")

    def _execute_with_retry(self, step: PlanStep, hire) -> None:
        call_with_retry(lambda: self._execute(step, hire),
                        attempts=self.retry_attempts)

    def _execute(self, step: PlanStep, hire) -> None:
        username = hire.username
        if step.action == "create_user":
            self.provider.create_user(hire)
        elif step.action == "add_to_group":
            self.provider.add_to_group(username, step.details["group"])
        elif step.action == "remove_from_group":
            self.provider.remove_from_group(username, step.details["group"])
        elif step.action == "assign_license":
            self.provider.assign_license(username, step.details["license"])
        elif step.action == "revoke_license":
            self.provider.revoke_license(username, step.details["license"])
        elif step.action == "update_user":
            self.provider.update_user(username, **{
                k: v for k, v in step.details.items()
                if k in ("role", "department")})
        elif step.action == "disable_user":
            self.provider.disable_user(username)
        elif step.action == "send_welcome":
            pass  # No real email yet: this step is where an email
            # provider plugs in later. The audit entry still records it.
        else:
            raise ValueError(f"unknown action {step.action!r}")

    def _compensate(self, executed: list, hire) -> None:
        """Undo completed steps in reverse order after a partial failure."""
        for step in reversed(executed):
            undo = _COMPENSATION.get(step.action)
            if undo is None:
                continue
            try:
                self._execute(PlanStep(undo, "", step.details), hire)
                self._log(f"rollback_{step.action}", hire.username, "done",
                          f"compensated {step.description}")
            except Exception as exc:  # noqa: BLE001
                self._log(f"rollback_{step.action}", hire.username,
                          "failed", str(exc))

    def _notify(self, username: str, status: str, summary: str) -> None:
        if self.notifier is not None:
            try:
                self.notifier.notify(username, status, summary)
            except Exception as exc:  # noqa: BLE001 -- notify must
                # never break the run it reports on
                logger.warning("notifier failed for %s: %s", username, exc)

    def _log(self, action: str, target: str, status: str, note: str) -> None:
        entry = AuditEntry(_now(), action, target, status, note)
        self.audit.append(entry)
        if self.audit_file is not None:
            # One JSON object per line: append-only, machine-readable,
            # and readable with ordinary tools (grep, jq) later.
            with open(self.audit_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(entry)) + "\n")
        if self.audit_store is not None:
            self.audit_store.append(entry)


class _MoveHire:
    """Minimal stand-in so approval, execution, and audit can run
    move/offboard flows, which only know a username."""

    def __init__(self, username: str):
        self.username = username
        self.display_name = username
        self.role = ""

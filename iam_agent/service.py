"""Service layer: the app's single front door to the system.

The web app (and any future client) never touches the engine,
stores, or providers directly. It calls this service, which owns
the rules that span modules:

- Who may do what: only approver/admin roles may decide; a
  requester can never approve their own request.
- The lifecycle: submit -> pending_approval -> approved -> running
  -> done/partial/failed, or pending_approval -> rejected.
- Observability: every run is timed and counted; partial and
  failed runs raise alerts.
- One lock around execution, because the app is single-process:
  two simultaneous runs against the same directory could otherwise
  interleave in confusing ways.

The service is deliberately boring: it validates, delegates to the
engine, and records the outcome. All the interesting decisions
(policy, approval routing, provider behaviour) stay where they are.
"""

import threading
import time

from .approval import classify, may_decide
from .engine import OnboardingAgent, pack_plan, plan_fingerprint, unpack_plan
from .models import NewHire
from .observability import AlertManager, Metrics
from .policies import load_policy
from .requests import RequestStore


class IAMService:
    def __init__(self, provider, audit_store=None, audit_file=None,
                 request_store: RequestStore = None, notifier=None,
                 metrics: Metrics = None, alerts: AlertManager = None,
                 email_sender=None, policy=None):
        self.provider = provider
        self.audit_store = audit_store
        self.audit_file = audit_file
        self.requests = request_store
        self.notifier = notifier
        self.metrics = metrics or Metrics()
        self.alerts = alerts or AlertManager(notifier)
        self.email_sender = email_sender
        self.policy = policy if policy is not None else load_policy()
        self.pending_passwords = {}
        self._lock = threading.RLock()

    def _planner(self) -> OnboardingAgent:
        return OnboardingAgent(self.provider, policy=self.policy)

    def _subject(self, request):
        payload = request["payload"]
        if request["kind"] == "onboard":
            return NewHire(**self._hire_fields(payload))
        role = payload.get("new_role") or ""
        username = payload.get("username") or ""

        class _Subject:
            pass

        subject = _Subject()
        subject.role = role
        subject.username = username
        subject.display_name = username
        return subject

    @staticmethod
    def _hire_fields(payload) -> dict:
        return {
            "first_name": payload["first_name"],
            "last_name": payload["last_name"],
            "username": payload["username"],
            "department": payload["department"],
            "role": payload["role"],
            "manager": payload.get("manager", ""),
            "start_date": payload.get("start_date", ""),
            "email": payload.get("email", ""),
        }

    def _fresh_plan(self, request):
        agent = self._planner()
        payload = request["payload"]
        if request["kind"] == "onboard":
            return agent.build_plan(NewHire(**self._hire_fields(payload)))
        if request["kind"] == "move":
            return agent.build_move_plan(
                payload["username"], payload["new_role"],
                payload.get("new_department"))
        return agent.build_offboard_plan(payload["username"])

    def _stored_plan(self, request):
        raw = request["payload"].get("plan")
        if not raw:
            raise ValueError("request has no frozen plan")
        return unpack_plan(raw)

    def _classify_request(self, request):
        return classify(self._stored_plan(request), self._subject(request),
                        self.policy)

    def decision_block_reason(self, request, username: str,
                              role: str) -> str:
        """Empty when this person may decide the request."""
        level, _reason = self._classify_request(request)
        _allowed, why = may_decide(role, level, request["requester"],
                                   username)
        return why

    def load_sample_company(self) -> int:
        """Create a few fictional people in the built-in directory.

        Refuses any other provider, so this cannot touch Entra.
        """
        name = type(self.provider).__name__
        if name != "SqliteProvider":
            raise ValueError(
                "the sample company loads only into the built-in directory")
        created = 0
        samples = [
            NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                    "engineer", manager="carol.manager",
                    start_date="2026-11-02",
                    email="ada.lovelace@example.com"),
            NewHire("Grace", "Hopper", "grace.hopper", "Engineering",
                    "engineer", manager="carol.manager",
                    start_date="2026-11-02",
                    email="grace.hopper@example.com"),
            NewHire("Bob", "Builder", "bob.builder", "Sales", "sales",
                    manager="carol.manager", start_date="2026-11-02"),
        ]
        for hire in samples:
            if self.provider.get_user(hire.username) is not None:
                continue
            self.provider.create_user(hire)
            access = self.policy.access_for(hire.role)
            for group in access["groups"]:
                self.provider.add_to_group(hire.username, group)
            for licence in access["licenses"]:
                self.provider.assign_license(hire.username, licence)
            self.provider.enable_user(hire.username)
            created += 1
        return created

    def take_temporary_password(self, request_id: int):
        """The one-time directory password, if this process still holds it."""
        return self.pending_passwords.pop(request_id, None)

    def recover_interrupted(self) -> list:
        """Mark runs left 'running' by a dead process as partial."""
        recovered = []
        for request in self.requests.list(status="running"):
            finished = self.requests.finish(request["id"], "partial", {
                "error": "the process stopped before this run finished",
            })
            self.alerts.alert(
                request["payload"].get("username", str(request["id"])),
                "partial",
                f"{request['kind']} request {request['id']} was still "
                "running when the process started")
            recovered.append(finished)
        return recovered

    # -- submission ------------------------------------------------------

    def submit_onboard(self, hire_data: dict, requester: str) -> dict:
        hire = NewHire(**hire_data)
        plan = self._planner().build_plan(hire)
        return self.requests.create("onboard", {
            "first_name": hire.first_name, "last_name": hire.last_name,
            "username": hire.username, "department": hire.department,
            "role": hire.role, "manager": hire.manager,
            "start_date": hire.start_date, "email": hire.email,
            "plan": pack_plan(plan),
        }, requester)

    def submit_move(self, username: str, new_role: str, requester: str,
                    new_department: str = None) -> dict:
        if self.provider.get_user(username) is None:
            raise ValueError(f"unknown user {username!r}")
        plan = self._planner().build_move_plan(
            username, new_role, new_department)
        return self.requests.create("move", {
            "username": username, "new_role": new_role,
            "new_department": new_department,
            "plan": pack_plan(plan)}, requester)

    def submit_offboard(self, username: str, requester: str) -> dict:
        if self.provider.get_user(username) is None:
            raise ValueError(f"unknown user {username!r}")
        plan = self._planner().build_offboard_plan(username)
        return self.requests.create(
            "offboard",
            {"username": username, "plan": pack_plan(plan)},
            requester)

    # -- decisions ---------------------------------------------------------

    def approve(self, request_id: int, approver: str,
                role: str) -> dict:
        return self._decide(request_id, approver, role, True, "")

    def reject(self, request_id: int, approver: str, role: str,
               reason: str = "") -> dict:
        return self._decide(request_id, approver, role, False, reason)

    def _decide(self, request_id, approver, role, approved, reason):
        request = self.requests.get(request_id)
        if request is None:
            raise ValueError(f"unknown request {request_id}")
        blocked = self.decision_block_reason(request, approver, role)
        if blocked:
            raise ValueError(blocked)
        if approved:
            fresh = self._fresh_plan(request)
            if plan_fingerprint(fresh) != plan_fingerprint(
                    self._stored_plan(request)):
                raise ValueError(
                    "this request is out of date; reject it and submit again")
        decided = self.requests.decide(request_id, approver, approved, reason)
        self.metrics.increment("decisions",
                               {"outcome": "approved" if approved
                                else "rejected"})
        if not approved:
            return decided
        return self._execute(decided, approver)

    # -- execution ---------------------------------------------------------

    def _execute(self, request: dict, approver: str) -> dict:
        with self._lock:
            agent = OnboardingAgent(
                self.provider,
                approver=lambda p, h: (True, approver),
                audit_file=self.audit_file,
                audit_store=self.audit_store,
                notifier=self.notifier,
                email_sender=self.email_sender,
                policy=self.policy)
            stored = self._stored_plan(request)
            started = time.time()
            try:
                payload = request["payload"]
                if request["kind"] == "onboard":
                    result = agent.run(
                        NewHire(**self._hire_fields(payload)),
                        requester=request["requester"], plan=stored)
                elif request["kind"] == "move":
                    result = agent.move(
                        payload["username"], payload["new_role"],
                        payload.get("new_department"),
                        requester=request["requester"], plan=stored)
                else:
                    result = agent.offboard(
                        payload["username"],
                        requester=request["requester"], plan=stored)
                status = result["status"]
            except Exception as exc:  # noqa: BLE001 -- recorded, not hidden
                status = "failed"
                result = {"hire": request["payload"].get("username"),
                          "error": str(exc)}
            duration = time.time() - started
            self.metrics.increment("runs", {"status": status})
            self.metrics.observe("run_duration_seconds", duration)
            finished = self.requests.finish(request["id"], status, {
                "engine_status": status,
                "executed": len(result.get("executed", [])),
                "planned": len(result.get("planned", [])),
                "error": result.get("error"),
            })
            secret = result.pop("temporary_password", None)
            if secret:
                self.pending_passwords[request["id"]] = secret
            if status in ("partial", "failed"):
                self.alerts.alert(
                    request["payload"].get("username", str(request["id"])),
                    status,
                    f"{request['kind']} request {request['id']} ended "
                    f"{status}")
            return finished

    # -- reads ---------------------------------------------------------------

    def get_request(self, request_id: int):
        return self.requests.get(request_id)

    def list_requests(self, status: str = None, requester: str = None):
        return self.requests.list(status=status, requester=requester)

    def dashboard_stats(self) -> dict:
        requests = self.requests.list()
        by_status = {}
        for request in requests:
            by_status[request["status"]] = by_status.get(
                request["status"], 0) + 1
        users = self.provider.list_users()
        return {
            "pending_approval": by_status.get("pending_approval", 0),
            "total_requests": len(requests),
            "requests_by_status": by_status,
            "total_users": len(users),
            "active_users": sum(1 for u in users if u.get("active")),
            "alerts": len(self.alerts.alerts),
        }

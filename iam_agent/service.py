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

from .engine import OnboardingAgent
from .models import NewHire
from .observability import AlertManager, Metrics
from .requests import RequestStore


class IAMService:
    def __init__(self, provider, audit_store=None, audit_file=None,
                 request_store: RequestStore = None, notifier=None,
                 metrics: Metrics = None, alerts: AlertManager = None,
                 email_sender=None):
        self.provider = provider
        self.audit_store = audit_store
        self.audit_file = audit_file
        self.requests = request_store
        self.notifier = notifier
        self.metrics = metrics or Metrics()
        self.alerts = alerts or AlertManager(notifier)
        self.email_sender = email_sender
        self._lock = threading.RLock()

    # -- submission ------------------------------------------------------

    def submit_onboard(self, hire_data: dict, requester: str) -> dict:
        hire = NewHire(**hire_data)  # validates before anything is stored
        return self.requests.create("onboard", {
            "first_name": hire.first_name, "last_name": hire.last_name,
            "username": hire.username, "department": hire.department,
            "role": hire.role, "manager": hire.manager,
            "start_date": hire.start_date, "email": hire.email,
        }, requester)

    def submit_move(self, username: str, new_role: str, requester: str,
                    new_department: str = None) -> dict:
        if self.provider.get_user(username) is None:
            raise ValueError(f"unknown user {username!r}")
        return self.requests.create("move", {
            "username": username, "new_role": new_role,
            "new_department": new_department}, requester)

    def submit_offboard(self, username: str, requester: str) -> dict:
        if self.provider.get_user(username) is None:
            raise ValueError(f"unknown user {username!r}")
        return self.requests.create("offboard", {"username": username},
                                    requester)

    # -- decisions ---------------------------------------------------------

    def approve(self, request_id: int, approver: str,
                role: str) -> dict:
        return self._decide(request_id, approver, role, True, "")

    def reject(self, request_id: int, approver: str, role: str,
               reason: str = "") -> dict:
        return self._decide(request_id, approver, role, False, reason)

    def _decide(self, request_id, approver, role, approved, reason):
        if role not in ("admin", "approver"):
            raise ValueError(f"role {role!r} may not decide requests")
        request = self.requests.get(request_id)
        if request is None:
            raise ValueError(f"unknown request {request_id}")
        if request["requester"] == approver:
            raise ValueError("requester cannot approve their own request")
        decided = self.requests.decide(request_id, approver, approved,
                                       reason)
        self.metrics.increment("decisions",
                               {"outcome": "approved" if approved
                                else "rejected"})
        if not approved:
            return decided
        return self._execute(decided, approver)

    # -- execution ---------------------------------------------------------

    def _execute(self, request: dict, approver: str) -> dict:
        with self._lock:
            self.requests.mark_running(request["id"])
            agent = OnboardingAgent(
                self.provider,
                approver=lambda p, h: (True, approver),
                audit_file=self.audit_file,
                audit_store=self.audit_store,
                notifier=self.notifier,
                email_sender=self.email_sender)
            started = time.time()
            try:
                payload = request["payload"]
                if request["kind"] == "onboard":
                    result = agent.run(NewHire(**payload))
                elif request["kind"] == "move":
                    result = agent.move(payload["username"],
                                        payload["new_role"],
                                        payload.get("new_department"))
                else:
                    result = agent.offboard(payload["username"])
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

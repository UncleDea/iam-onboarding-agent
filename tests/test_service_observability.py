import unittest

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.audit_store import SqliteAuditStore
from iam_agent.db import Database
from iam_agent.migrations import migrate
from iam_agent.models import AuditEntry
from iam_agent.observability import (AlertManager, Metrics, check_health)
from iam_agent.reporting import (access_report, activity_report,
                                 approval_report, summary_report)
from iam_agent.requests import RequestStore
from iam_agent.service import IAMService
import os
import tempfile


class TestObservability(unittest.TestCase):
    def test_metrics_snapshot(self):
        metrics = Metrics()
        metrics.increment("runs", {"status": "done"}, 2)
        metrics.observe("run_duration_seconds", 0.5)
        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["counters"]["runs[status=done]"], 2)
        self.assertEqual(snapshot["timings"]["run_duration_seconds"]["count"], 1)

    def test_alert_cooldown(self):
        alerts = AlertManager()
        self.assertTrue(alerts.alert("ada.lovelace", "partial", "half done"))
        self.assertFalse(alerts.alert("ada.lovelace", "partial", "again"))
        self.assertEqual(len(alerts.alerts), 2)  # recorded, not notified

    def test_health_reports_provider_failure(self):
        class BrokenProvider:
            class graph:
                @staticmethod
                def token():
                    raise RuntimeError("down")
        db = Database(":memory:")
        health = check_health(db, None, BrokenProvider())
        self.assertEqual(health["status"], "unhealthy")
        self.assertEqual(health["failed"], ["provider"])
        self.assertNotIn("down", str(health))
        db.close()


class TestReporting(unittest.TestCase):
    def test_reports(self):
        provider = MockProvider()
        agent = OnboardingAgent(provider, approver=lambda p, h: True)
        agent.run(NewHire("Ada", "Lovelace", "ada.lovelace",
                          "Engineering", "engineer"))
        access = access_report(provider)
        self.assertEqual(access["total_users"], 1)
        self.assertEqual(access["groups"]["engineering"], 1)
        activity = activity_report([
            {"action": "create_user", "status": "done",
             "timestamp": "2026-10-28T00:00:00Z"},
            {"action": "create_user", "status": "failed",
             "timestamp": "2026-10-28T00:00:00Z"},
        ])
        self.assertEqual(activity["by_status"]["done"], 1)
        approvals = approval_report([{"status": "done",
                                      "created_at": "2026-10-28T00:00:00Z",
                                      "decided_at": "2026-10-28T00:01:00Z"}])
        self.assertEqual(approvals["avg_decision_seconds"], 60.0)


class TestService(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        self.db = Database(self.path)
        migrate(self.db)
        self.audit = SqliteAuditStore(db=self.db)
        self.service = IAMService(
            MockProvider(), audit_store=self.audit,
            request_store=RequestStore(self.db))

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_submit_approve_runs_and_finishes(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        finished = self.service.approve(request["id"], "boss", "approver")
        self.assertEqual(finished["status"], "done")
        self.assertIsNotNone(
            self.service.provider.get_user("ada.lovelace"))

    def test_requester_cannot_approve_own(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        with self.assertRaises(ValueError):
            self.service.approve(request["id"], "alice", "approver")

    def test_requester_role_cannot_decide(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        with self.assertRaises(ValueError):
            self.service.approve(request["id"], "boss", "requester")

    def test_reject_creates_nothing(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        rejected = self.service.reject(request["id"], "boss", "approver",
                                       "not now")
        self.assertEqual(rejected["status"], "rejected")
        self.assertIsNone(self.service.provider.get_user("ada.lovelace"))

    def test_partial_run_raises_alert(self):
        class FailingProvider(MockProvider):
            def add_to_group(self, username, group):
                if group == "engineering":
                    raise ValueError("group service down")
                return super().add_to_group(username, group)
        service = IAMService(
            FailingProvider(), audit_store=self.audit,
            request_store=RequestStore(self.db))
        request = service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        finished = service.approve(request["id"], "boss", "approver")
        self.assertEqual(finished["status"], "partial")
        self.assertEqual(len(service.alerts.alerts), 1)

    def test_privileged_grant_needs_an_admin(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "manager", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        with self.assertRaises(ValueError):
            self.service.approve(request["id"], "boss", "approver")
        self.assertEqual(
            self.service.get_request(request["id"])["status"],
            "pending_approval")
        finished = self.service.approve(request["id"], "ada.admin", "admin")
        self.assertEqual(finished["status"], "done")

    def test_drift_leaves_the_request_pending(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        self.service.policy = self.service.policy.with_roles({
            "engineer": {"groups": ["all-staff"], "licenses": []},
        })
        with self.assertRaises(ValueError):
            self.service.approve(request["id"], "boss", "approver")
        self.assertEqual(
            self.service.get_request(request["id"])["status"],
            "pending_approval")
        self.assertIsNone(self.service.provider.get_user("ada.lovelace"))

    def test_a_second_decision_is_refused(self):
        request = self.service.submit_onboard({
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02",
        }, "alice")
        self.service.approve(request["id"], "boss", "approver")
        with self.assertRaises(ValueError):
            self.service.approve(request["id"], "ada.admin", "admin")

    def test_running_request_is_partial_after_restart(self):
        request = self.service.requests.create(
            "onboard", {"username": "ada.lovelace"}, "alice")
        self.service.requests.decide(request["id"], "boss", True)
        recovered = self.service.recover_interrupted()
        self.assertEqual(recovered[0]["status"], "partial")
        self.assertEqual(len(self.service.alerts.alerts), 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.retry import TransientError


def hire(username="ada.lovelace", role="engineer"):
    return NewHire("Ada", "Lovelace", username, "Engineering", role)


class FlakyProvider(MockProvider):
    """Fails transiently N times, then works -- like a real API."""

    def __init__(self, failures=2):
        super().__init__()
        self.failures = failures
        self.calls = 0

    def add_to_group(self, username, group):
        self.calls += 1
        if self.calls <= self.failures:
            raise TransientError("simulated outage")
        return super().add_to_group(username, group)


class FailingProvider(MockProvider):
    """Fails permanently on the second group add."""

    def add_to_group(self, username, group):
        if group == "engineering":
            raise ValueError("group service down")
        return super().add_to_group(username, group)


class TestRealSystemBehaviours(unittest.TestCase):
    def test_transient_failures_are_retried(self):
        agent = OnboardingAgent(FlakyProvider(),
                                approver=lambda p, h: True)
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")
        self.assertIn("engineering",
                      agent.provider.users["ada.lovelace"]["groups"])

    def test_partial_failure_compensates(self):
        agent = OnboardingAgent(FailingProvider(),
                                approver=lambda p, h: True)
        result = agent.run(hire())
        self.assertEqual(result["status"], "partial")
        user = agent.provider.users["ada.lovelace"]
        # Created, then compensated: disabled and stripped of groups.
        self.assertFalse(user["active"])
        self.assertEqual(user["groups"], [])
        rollbacks = [e for e in agent.audit
                     if e.action.startswith("rollback_")]
        self.assertTrue(rollbacks)

    def test_requester_cannot_approve_own_request(self):
        approver = lambda p, h: (True, "ada.lovelace")  # noqa: E731
        agent = OnboardingAgent(MockProvider(), approver=approver)
        result = agent.run(hire(), requester="ada.lovelace")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(agent.provider.users, {})

    def test_move_removes_old_access_and_adds_new(self):
        agent = OnboardingAgent(MockProvider(),
                                approver=lambda p, h: (True, "boss"))
        agent.run(hire())
        result = agent.move("ada.lovelace", "sales")
        self.assertEqual(result["status"], "done")
        user = agent.provider.users["ada.lovelace"]
        self.assertIn("sales", user["groups"])
        self.assertNotIn("engineering", user["groups"])
        self.assertIn("crm", user["licenses"])
        self.assertEqual(user["role"], "sales")

    def test_offboard_disables_and_strips_everything(self):
        agent = OnboardingAgent(MockProvider(),
                                approver=lambda p, h: (True, "boss"))
        agent.run(hire())
        result = agent.offboard("ada.lovelace")
        self.assertEqual(result["status"], "done")
        user = agent.provider.users["ada.lovelace"]
        self.assertFalse(user["active"])
        self.assertEqual(user["groups"], [])
        self.assertEqual(user["licenses"], [])

    def test_offboard_unknown_user_refused(self):
        agent = OnboardingAgent(MockProvider())
        with self.assertRaises(ValueError):
            agent.offboard("ghost")


if __name__ == "__main__":
    unittest.main()

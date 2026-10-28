import unittest
from unittest import mock

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent import policies
from iam_agent.approval import classify, make_approver


def hire(role, username="ada.lovelace"):
    return NewHire("Ada", "Lovelace", username, "Engineering", role)


def plan_for(agent, hire_):
    return agent.build_plan(hire_)


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.agent = OnboardingAgent(MockProvider())

    def test_standard_role_auto_approves(self):
        level, _ = classify(plan_for(self.agent, hire("engineer")),
                            hire("engineer"))
        self.assertEqual(level, "auto")

    def test_manager_role_needs_human(self):
        level, reason = classify(plan_for(self.agent, hire("manager")),
                                 hire("manager"))
        self.assertEqual(level, "human")
        self.assertIn("privileged", reason)

    def test_unknown_role_needs_human(self):
        level, _ = classify(plan_for(self.agent, hire("chief-wizard")),
                            hire("chief-wizard"))
        self.assertEqual(level, "human")

    def test_privileged_group_needs_human(self):
        with mock.patch.dict(policies.ROLE_ACCESS, {
            "ops": {"groups": ["all-staff", "domain-admins"],
                    "licenses": []},
        }):
            level, _ = classify(plan_for(self.agent, hire("ops")),
                                hire("ops"))
        self.assertEqual(level, "human")


class TestRouter(unittest.TestCase):
    def test_standard_plan_never_calls_human(self):
        calls = []
        approver = make_approver(lambda p, h: calls.append(h) or True)
        agent = OnboardingAgent(MockProvider(), approver=approver)
        result = agent.run(hire("engineer"))
        self.assertEqual(result["status"], "done")
        self.assertEqual(calls, [])
        approve_entries = [e for e in agent.audit if e.action == "approve"]
        self.assertIn("auto", approve_entries[0].note)

    def test_human_decision_is_audited_by_name(self):
        approver = make_approver(lambda p, h: False, human_name="alice")
        agent = OnboardingAgent(MockProvider(), approver=approver)
        result = agent.run(hire("manager"))
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(agent.provider.users, {})
        approve_entries = [e for e in agent.audit if e.action == "approve"]
        self.assertEqual(approve_entries[0].status, "rejected")
        self.assertIn("alice", approve_entries[0].note)


if __name__ == "__main__":
    unittest.main()

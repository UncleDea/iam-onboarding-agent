import unittest

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.approval import classify, make_approver
from iam_agent.policies import load_policy


def hire(role, username="ada.lovelace"):
    return NewHire("Ada", "Lovelace", username, "Engineering", role)


def plan_for(agent, hire_):
    return agent.build_plan(hire_)


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()
        self.agent = OnboardingAgent(MockProvider(), policy=self.policy)

    def test_standard_role_is_standard(self):
        level, _ = classify(plan_for(self.agent, hire("engineer")),
                            hire("engineer"), self.policy)
        self.assertEqual(level, "standard")

    def test_manager_role_is_privileged(self):
        level, reason = classify(plan_for(self.agent, hire("manager")),
                                 hire("manager"), self.policy)
        self.assertEqual(level, "privileged")
        self.assertIn("privileged", reason)

    def test_unknown_role_is_privileged(self):
        level, _ = classify(plan_for(self.agent, hire("chief-wizard")),
                            hire("chief-wizard"), self.policy)
        self.assertEqual(level, "privileged")

    def test_privileged_group_is_privileged(self):
        policy = self.policy.with_roles({
            "ops": {"groups": ["all-staff", "domain-admins"],
                    "licenses": []},
        })
        agent = OnboardingAgent(MockProvider(), policy=policy)
        level, _ = classify(plan_for(agent, hire("ops")), hire("ops"),
                            policy)
        self.assertEqual(level, "privileged")


class TestRouter(unittest.TestCase):
    def test_every_plan_asks_the_named_person(self):
        calls = []
        approver = make_approver(lambda p, h: calls.append(h) or True,
                                 human_name="casey")
        agent = OnboardingAgent(MockProvider(), approver=approver)
        result = agent.run(hire("engineer"))
        self.assertEqual(result["status"], "done")
        self.assertEqual(len(calls), 1)
        approve_entries = [e for e in agent.audit if e.action == "approve"]
        self.assertIn("casey", approve_entries[0].note)

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

import json
import tempfile
import unittest

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.policies import load_policy


def hire(username="ada.lovelace", role="engineer"):
    return NewHire("Ada", "Lovelace", username, "Engineering", role)


class TestEngine(unittest.TestCase):
    def test_dry_run_creates_nothing(self):
        agent = OnboardingAgent(MockProvider())
        result = agent.run(hire(), dry_run=True)
        self.assertEqual(agent.provider.users, {})
        self.assertTrue(result["planned"])

    def test_approved_run_creates_user_and_access(self):
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True)
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")
        user = agent.provider.users["ada.lovelace"]
        self.assertIn("engineering", user["groups"])
        self.assertIn("office-standard", user["licenses"])

    def test_rejection_creates_nothing_and_is_audited(self):
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: False)
        result = agent.run(hire())
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(agent.provider.users, {})
        self.assertEqual(agent.audit[-1].status, "rejected")

    def test_rerun_of_an_active_account_is_refused(self):
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True)
        agent.run(hire())
        result = agent.run(hire())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(agent.provider.users), 1)
        self.assertTrue(agent.provider.users["ada.lovelace"]["active"])
        self.assertIn("engineering",
                      agent.provider.users["ada.lovelace"]["groups"])

    def test_disabled_account_can_be_resumed(self):
        provider = MockProvider()
        provider.create_user(hire())
        agent = OnboardingAgent(provider, approver=lambda p, h: True)
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")
        user = provider.users["ada.lovelace"]
        self.assertTrue(user["active"])
        self.assertIn("engineering", user["groups"])

    def test_sod_conflict_refuses_before_any_side_effect(self):
        policy = load_policy().with_roles({
            "treasurer": {"groups": ["payment-create", "payment-approve"],
                          "licenses": []},
        })
        agent = OnboardingAgent(MockProvider(), policy=policy)
        with self.assertRaises(ValueError):
            agent.run(hire(role="treasurer"))
        self.assertEqual(agent.provider.users, {})

    def test_audit_file_gets_json_lines(self):
        with tempfile.NamedTemporaryFile("r", suffix=".jsonl",
                                         delete=False) as tmp:
            path = tmp.name
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True,
                                audit_file=path)
        agent.run(hire())
        with open(path, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
        created = [line for line in lines
                   if line["action"] == "create_user"]
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["status"], "done")

    def test_run_without_approver_creates_nothing(self):
        agent = OnboardingAgent(MockProvider())
        result = agent.run(hire())
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(agent.provider.users, {})

    def test_move_refuses_a_segregation_conflict(self):
        policy = load_policy().with_roles({
            "treasurer": {"groups": ["payment-create", "payment-approve"],
                          "licenses": []},
        })
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True,
                                policy=policy)
        agent.run(hire())
        with self.assertRaises(ValueError):
            agent.move("ada.lovelace", "treasurer")
        self.assertIn("engineering",
                      agent.provider.users["ada.lovelace"]["groups"])


if __name__ == "__main__":
    unittest.main()

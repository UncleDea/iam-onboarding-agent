import json
import tempfile
import unittest
from unittest import mock

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent import policies


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

    def test_rerun_resumes_idempotently(self):
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True)
        agent.run(hire())
        result = agent.run(hire())  # second on-boarding of same person
        self.assertEqual(result["status"], "done")
        self.assertEqual(len(agent.provider.users), 1)
        skipped = [e for e in agent.audit
                   if e.action == "create_user" and e.status == "skipped"]
        self.assertEqual(len(skipped), 1)

    def test_sod_conflict_refuses_before_any_side_effect(self):
        with mock.patch.dict(policies.ROLE_ACCESS, {
            "treasurer": {"groups": ["payment-create", "payment-approve"],
                          "licenses": []},
        }):
            agent = OnboardingAgent(MockProvider())
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


if __name__ == "__main__":
    unittest.main()

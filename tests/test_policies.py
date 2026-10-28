import unittest

from iam_agent.policies import access_for, find_conflicts


class TestPolicies(unittest.TestCase):
    def test_known_role(self):
        access = access_for("engineer")
        self.assertIn("engineering", access["groups"])
        self.assertIn("office-standard", access["licenses"])

    def test_role_lookup_is_case_insensitive(self):
        self.assertEqual(access_for("ENGINEER"), access_for("engineer"))

    def test_unknown_role_fails_closed(self):
        access = access_for("chief-wizard")
        self.assertEqual(access["groups"], ["all-staff"])
        self.assertEqual(access["licenses"], [])

    def test_conflict_detected(self):
        self.assertEqual(
            find_conflicts(["payment-create", "payment-approve"]),
            [["payment-approve", "payment-create"]])

    def test_no_conflict_when_only_one_side_held(self):
        self.assertEqual(find_conflicts(["payment-create"]), [])


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest

from iam_agent.policies import PolicyError, load_policy


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()

    def test_known_role(self):
        access = self.policy.access_for("engineer")
        self.assertIn("engineering", access["groups"])
        self.assertIn("office-standard", access["licenses"])

    def test_role_lookup_is_case_insensitive(self):
        self.assertEqual(self.policy.access_for("ENGINEER"),
                         self.policy.access_for("engineer"))

    def test_analyst_agent_and_caregiver_are_standard_roles(self):
        for role, group in (("Analyst", "analysts"),
                            ("agent", "agents"),
                            ("careGiver", "caregivers")):
            access = self.policy.access_for(role)
            self.assertIn("all-staff", access["groups"])
            self.assertIn(group, access["groups"])
            self.assertIn("office-standard", access["licenses"])
            self.assertNotIn(role.lower(), self.policy.privileged_roles)

    def test_unknown_role_fails_closed(self):
        access = self.policy.access_for("chief-wizard")
        self.assertEqual(access["groups"], ["all-staff"])
        self.assertEqual(access["licenses"], [])

    def test_conflict_detected(self):
        self.assertEqual(
            self.policy.find_conflicts(
                ["payment-create", "payment-approve"]),
            [["payment-approve", "payment-create"]])

    def test_no_conflict_when_only_one_side_held(self):
        self.assertEqual(self.policy.find_conflicts(["payment-create"]), [])

    def test_privileged_sets_come_from_the_file(self):
        self.assertIn("manager", self.policy.privileged_roles)
        self.assertIn("domain-admins", self.policy.privileged_groups)
        self.assertIn("admin-tools", self.policy.privileged_licenses)

    def test_old_flat_file_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as tmp:
            json.dump({"engineer": {"groups": ["all-staff"],
                                    "licenses": []}}, tmp)
            path = tmp.name
        with self.assertRaises(PolicyError) as ctx:
            load_policy(path)
        message = str(ctx.exception)
        self.assertIn("roles", message)
        self.assertIn("privileged_groups", message)

    def test_explicit_path_is_used(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as tmp:
            json.dump({
                "roles": {"clerk": {"groups": ["all-staff"],
                                    "licenses": []}},
                "fallback": {"groups": ["all-staff"], "licenses": []},
                "conflicts": [],
                "privileged_roles": [],
                "privileged_groups": [],
                "privileged_licenses": [],
            }, tmp)
            path = tmp.name
        policy = load_policy(path)
        self.assertIn("clerk", policy.roles)
        self.assertEqual(policy.access_for("clerk")["groups"], ["all-staff"])


if __name__ == "__main__":
    unittest.main()

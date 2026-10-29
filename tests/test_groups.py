import unittest

from iam_agent.policies import load_policy
from iam_agent.reporting import group_index


class _Directory:
    def __init__(self, users):
        self._users = users

    def list_users(self):
        return self._users


class TestGroupIndex(unittest.TestCase):
    def test_policy_groups_members_and_inherited_stay_apart(self):
        policy = load_policy()
        rows = group_index(_Directory([
            {"username": "ada", "groups": ["engineering", "all-staff"],
             "inherited_groups": ["everyone"]},
            {"username": "bob", "groups": ["visitors"]},
        ]), policy)
        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["engineering"]["members"], ["ada"])
        self.assertEqual(by_name["engineering"]["inherited"], [])
        self.assertFalse(by_name["engineering"]["privileged"])
        self.assertEqual(by_name["everyone"]["inherited"], ["ada"])
        self.assertEqual(by_name["everyone"]["members"], [])
        self.assertFalse(by_name["everyone"]["privileged"])
        self.assertEqual(by_name["analysts"]["members"], [])
        self.assertTrue(by_name["managers"]["privileged"])
        self.assertFalse(by_name["visitors"]["privileged"])
        privileged = [row["name"] for row in rows if row["privileged"]]
        self.assertEqual(privileged, sorted(privileged))
        self.assertLess(rows.index(by_name["managers"]),
                        rows.index(by_name["all-staff"]))


if __name__ == "__main__":
    unittest.main()

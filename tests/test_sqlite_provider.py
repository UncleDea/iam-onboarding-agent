import os
import tempfile
import unittest

from iam_agent import SqliteProvider
from iam_agent.providers import AlreadyExists
from iam_agent.models import NewHire


def hire(username="ada.lovelace", role="engineer"):
    return NewHire("Ada", "Lovelace", username, "Engineering", role)


class TestSqliteProvider(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)  # sqlite creates it
        self.provider = SqliteProvider(self.path)

    def tearDown(self):
        self.provider.close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_create_get_and_persist_across_reopen(self):
        self.provider.create_user(hire())
        self.provider.add_to_group("ada.lovelace", "engineering")
        self.provider.assign_license("ada.lovelace", "office-standard")
        self.provider.close()
        reopened = SqliteProvider(self.path)
        try:
            user = reopened.get_user("ada.lovelace")
            self.assertEqual(user["groups"], ["engineering"])
            self.assertEqual(user["licenses"], ["office-standard"])
            self.assertFalse(user["active"])
            reopened.enable_user("ada.lovelace")
            self.assertTrue(reopened.get_user("ada.lovelace")["active"])
        finally:
            reopened.close()

    def test_duplicate_create_raises(self):
        self.provider.create_user(hire())
        with self.assertRaises(AlreadyExists):
            self.provider.create_user(hire())

    def test_disable_and_update(self):
        self.provider.create_user(hire())
        self.provider.update_user("ada.lovelace", role="manager")
        self.provider.disable_user("ada.lovelace")
        user = self.provider.get_user("ada.lovelace")
        self.assertEqual(user["role"], "manager")
        self.assertFalse(user["active"])

    def test_remove_and_revoke_are_no_ops_when_absent(self):
        self.provider.create_user(hire())
        self.provider.remove_from_group("ada.lovelace", "nope")
        self.provider.revoke_license("ada.lovelace", "nope")
        self.assertEqual(self.provider.get_user("ada.lovelace")["groups"], [])

    def test_unknown_user_returns_none(self):
        self.assertIsNone(self.provider.get_user("ghost"))

import os
import tempfile
import unittest

from iam_agent.audit_store import SqliteAuditStore
from iam_agent.models import AuditEntry


def entry(action="create_user", target="ada.lovelace", status="done"):
    return AuditEntry("2026-10-28T00:00:00Z", action, target, status, "note")


class TestAuditStore(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        self.store = SqliteAuditStore(self.path)

    def tearDown(self):
        self.store.close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_chain_verifies_when_untouched(self):
        self.store.append(entry())
        self.store.append(entry(action="add_to_group"))
        self.assertTrue(self.store.verify())
        self.assertEqual(len(self.store.list_entries()), 2)

    def test_chain_fails_after_tampering(self):
        self.store.append(entry())
        self.store.append(entry(action="add_to_group"))
        self.store._db.execute(
            "UPDATE audit_log SET note = 'forged' WHERE id = 1")
        self.assertFalse(self.store.verify())

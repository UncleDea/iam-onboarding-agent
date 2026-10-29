import os
import tempfile
import unittest

from iam_agent.auth import AuthStore, hash_password, verify_password
from iam_agent.config import Settings
from iam_agent.db import Database
from iam_agent.migrations import MIGRATIONS, migrate
from iam_agent.requests import RequestStore


class TempDb(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        self.db = Database(self.path)
        migrate(self.db)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        settings = Settings.from_env()
        self.assertEqual(settings.provider, "sqlite")

    def test_entra_validation_lists_missing(self):
        settings = Settings(provider="entra", entra={})
        with self.assertRaises(ValueError) as ctx:
            settings.validate()
        self.assertIn("IAM_ENTRA_TENANT_ID", str(ctx.exception))


class TestMigrations(TempDb):
    def test_all_migrations_applied_once(self):
        first = migrate(self.db)
        self.assertEqual(first, [])
        versions = {row["version"] for row in
                    self.db.query("SELECT version FROM schema_version")}
        self.assertEqual(versions, {v for v, _, _ in MIGRATIONS})

    def test_database_is_thread_safe_enough(self):
        import threading
        errors = []

        def write(i):
            try:
                self.db.execute(
                    "INSERT INTO requests (kind, payload, requester,"
                    "  status, created_at) VALUES ('onboard', '{}', ?,"
                    "  'pending_approval', 't')", (f"user{i}",))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(i,))
                   for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.db.query("SELECT * FROM requests")), 20)


class TestRequests(TempDb):
    def test_lifecycle(self):
        store = RequestStore(self.db)
        request = store.create("onboard", {"username": "ada.lovelace"},
                               "alice")
        self.assertEqual(request["status"], "pending_approval")
        decided = store.decide(request["id"], "boss", True)
        self.assertEqual(decided["status"], "running")
        self.assertEqual(decided["approver"], "boss")
        finished = store.finish(request["id"], "done", {"engine_status": "done"})
        self.assertEqual(finished["status"], "done")
        self.assertEqual(finished["result"]["engine_status"], "done")

    def test_cannot_decide_twice(self):
        store = RequestStore(self.db)
        request = store.create("offboard", {"username": "ada.lovelace"},
                               "alice")
        store.decide(request["id"], "boss", False, "nope")
        with self.assertRaises(ValueError):
            store.decide(request["id"], "boss", True)


class TestAuth(TempDb):
    def test_password_hash_and_verify(self):
        self.assertTrue(verify_password("secret",
                                        hash_password("secret")))
        self.assertFalse(verify_password("wrong",
                                          hash_password("secret")))

    def test_login_session_and_logout(self):
        auth = AuthStore(self.db)
        auth.create_user("alice", "pw123456789012", "requester")
        token = auth.authenticate("alice", "pw123456789012")
        self.assertIsNotNone(token)
        self.assertIsNone(auth.authenticate("alice", "wrong"))
        session = auth.get_session(token)
        self.assertEqual(session["username"], "alice")
        self.assertEqual(session["role"], "requester")
        auth.logout(token)
        self.assertIsNone(auth.get_session(token))

    def test_ensure_admin_only_when_empty(self):
        auth = AuthStore(self.db)
        self.assertTrue(auth.ensure_admin("admin", "admin-password"))
        self.assertFalse(auth.ensure_admin("admin2", "admin-password"))


if __name__ == "__main__":
    unittest.main()

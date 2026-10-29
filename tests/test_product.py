import os
import tempfile
import threading
import unittest
import urllib.parse

from iam_agent.auth import AuthStore
from iam_agent.config import Settings
from iam_agent.db import Database
from iam_agent.microsoft_login import MicrosoftLogin
from iam_agent.migrations import migrate
from iam_agent.policies import load_policy, save_policy
from iam_agent.service import IAMService
from iam_agent.sqlite_provider import SqliteProvider
from iam_agent.requests import RequestStore
from iam_agent.webapp import build_app, make_server
from tests.test_webapp import http_request


class TestSetup(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        settings = Settings(provider="mock", db_path=self.path,
                            app_host="127.0.0.1", app_port=0)
        self.ctx = build_app(settings)
        self.server = make_server(settings, self.ctx)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.ctx["db"].close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_first_visit_opens_setup_and_creates_two_people(self):
        status, headers, _, _ = http_request(self.port, "GET", "/login")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/setup")
        body = urllib.parse.urlencode({
            "company": "Northwind",
            "admin_user": "ada.admin",
            "admin_password": "a-long-password",
            "approver_user": "bob.approver",
            "approver_password": "another-long-pw",
        })
        status, headers, _, _ = http_request(
            self.port, "POST", "/setup", body=body)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/login")
        status, _, page, _ = http_request(self.port, "GET", "/login")
        self.assertEqual(status, 200)
        self.assertIn("Northwind", page)
        self.assertIn("IAM Onboarding", page)


class TestSampleCompany(unittest.TestCase):
    def test_sample_loads_only_into_sqlite(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)
        db = Database(path)
        migrate(db)
        provider = SqliteProvider(db=db)
        service = IAMService(provider, request_store=RequestStore(db))
        try:
            created = service.load_sample_company()
            self.assertEqual(created, 3)
            user = provider.get_user("ada.lovelace")
            self.assertTrue(user["active"])
            self.assertIn("engineering", user["groups"])
            self.assertEqual(service.load_sample_company(), 0)
        finally:
            db.close()
            if os.path.exists(path):
                os.unlink(path)

    def test_sample_refuses_a_non_sqlite_provider(self):
        from iam_agent import MockProvider
        service = IAMService(MockProvider(), request_store=None)
        with self.assertRaises(ValueError):
            service.load_sample_company()


class TestPolicyRoundTrip(unittest.TestCase):
    def test_save_and_load(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        policy = load_policy()
        try:
            save_policy(policy, path)
            loaded = load_policy(path)
            self.assertEqual(loaded.access_for("engineer"),
                             policy.access_for("engineer"))
            self.assertEqual(loaded.source, path)
        finally:
            os.unlink(path)


class TestMicrosoftLogin(unittest.TestCase):
    def test_account_name_comes_from_graph_and_matches_an_app_user(self):
        def fake(method, url, headers, body):
            if method == "POST":
                return 200, {"access_token": "token"}
            return 200, {"userPrincipalName": "ada.admin@example.com"}

        login = MicrosoftLogin("tenant", "client", "secret",
                               "http://localhost/callback", request_fn=fake)
        self.assertEqual(login.account_name("code"),
                         "ada.admin@example.com")
        self.assertIn("client_id=client", login.authorize_url("state"))

        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)
        db = Database(path)
        migrate(db)
        auth = AuthStore(db)
        auth.create_user("ada.admin", "a-long-password", "admin")
        try:
            self.assertIsNotNone(auth.start_session("ada.admin"))
            self.assertIsNone(auth.start_session("nobody"))
        finally:
            db.close()
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()

import http.client
import os
import tempfile
import threading
import unittest
import urllib.parse

from iam_agent.auth import AuthStore
from iam_agent.config import Settings
from iam_agent.db import Database
from iam_agent.migrations import migrate
from iam_agent.webapp import LoginThrottle, build_app, make_server


class TempDbAuth(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        self.db = Database(self.path)
        migrate(self.db)
        self.auth = AuthStore(self.db, lockout_threshold=3,
                              lockout_minutes=15)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


class TestLockout(TempDbAuth):
    def test_lockout_after_threshold(self):
        self.auth.create_user("alice", "alice-password", "requester")
        for _ in range(3):
            self.assertIsNone(self.auth.authenticate("alice", "wrong"))
        # Correct password is now refused while locked.
        self.assertIsNone(self.auth.authenticate("alice", "alice-password"))
        user = self.auth.get_user("alice")
        self.assertIsNotNone(user["locked_until"])

    def test_success_resets_failures(self):
        self.auth.create_user("alice", "alice-password", "requester")
        self.auth.authenticate("alice", "wrong")
        self.assertIsNotNone(self.auth.authenticate("alice",
                                                    "alice-password"))
        self.assertEqual(self.auth.get_user("alice")["failed_attempts"], 0)


class TestPasswordRules(TempDbAuth):
    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            self.auth.create_user("alice", "short", "requester")

    def test_set_password_invalidates_sessions(self):
        self.auth.create_user("alice", "alice-password", "requester")
        token = self.auth.authenticate("alice", "alice-password")
        self.assertIsNotNone(self.auth.get_session(token))
        self.auth.set_password("alice", "new-password-1")
        self.assertIsNone(self.auth.get_session(token))
        self.assertIsNotNone(self.auth.authenticate("alice",
                                                    "new-password-1"))

    def test_change_password_requires_current(self):
        self.auth.create_user("alice", "alice-password", "requester")
        self.assertFalse(self.auth.change_password("alice", "wrong",
                                                   "new-password-1"))
        self.assertTrue(self.auth.change_password("alice", "alice-password",
                                                  "new-password-1"))

    def test_deactivated_user_cannot_log_in(self):
        self.auth.create_user("alice", "alice-password", "requester")
        self.auth.set_active("alice", False)
        self.assertIsNone(self.auth.authenticate("alice", "alice-password"))


class TestLoginThrottle(unittest.TestCase):
    def test_throttle_blocks_after_limit(self):
        throttle = LoginThrottle(max_attempts=2, window_seconds=60)
        self.assertTrue(throttle.allow("1.2.3.4"))
        throttle.record("1.2.3.4")
        throttle.record("1.2.3.4")
        self.assertFalse(throttle.allow("1.2.3.4"))
        self.assertTrue(throttle.allow("5.6.7.8"))


def http_request(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8")
    headers_out = dict(resp.getheaders())
    conn.close()
    return resp.status, headers_out, data


class TestUserManagementPages(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        settings = Settings(provider="mock", db_path=self.path,
                            app_host="127.0.0.1", app_port=0)
        self.ctx = build_app(settings)
        auth = self.ctx["auth"]
        auth.create_user("admin", "admin-password", "admin")
        auth.create_user("alice", "alice-password", "requester")
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

    def _login(self, username, password):
        status, headers, _ = http_request(
            self.port, "POST", "/login",
            urllib.parse.urlencode({"username": username,
                                    "password": password}))
        self.assertEqual(status, 303)
        return headers["Set-Cookie"].split(";")[0]

    def _csrf(self, cookie, path):
        _, _, body = http_request(self.port, "GET", path, cookie=cookie)
        marker = "name='csrf_token' value='"
        start = body.index(marker) + len(marker)
        return body[start:body.index("'", start)]

    def test_admin_creates_user_and_requester_cannot_open_users(self):
        admin = self._login("admin", "admin-password")
        csrf = self._csrf(admin, "/users")
        status, headers, _ = http_request(
            self.port, "POST", "/users/new",
            urllib.parse.urlencode({
                "csrf_token": csrf, "username": "carol",
                "new_password": "carol-password", "role": "approver"}),
            cookie=admin)
        self.assertEqual(status, 303)
        # New user can log in.
        self._login("carol", "carol-password")
        # Requester gets 403 on the users page.
        alice = self._login("alice", "alice-password")
        status, _, _, = http_request(self.port, "GET", "/users", cookie=alice)
        self.assertEqual(status, 403)

    def test_deactivate_blocks_login_and_security_headers_present(self):
        admin = self._login("admin", "admin-password")
        csrf = self._csrf(admin, "/users")
        status, _, _ = http_request(
            self.port, "POST", "/users/alice/toggle-active",
            urllib.parse.urlencode({"csrf_token": csrf}), cookie=admin)
        self.assertEqual(status, 303)
        status, _, _ = http_request(
            self.port, "POST", "/login",
            urllib.parse.urlencode({"username": "alice",
                                    "password": "alice-password"}))
        self.assertEqual(status, 200)  # login page re-rendered, no session
        # Security headers on a normal page.
        status, headers, _ = http_request(self.port, "GET", "/dashboard",
                                          cookie=admin)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_profile_password_change(self):
        alice = self._login("alice", "alice-password")
        csrf = self._csrf(alice, "/profile")
        status, _, body = http_request(
            self.port, "POST", "/profile/password",
            urllib.parse.urlencode({
                "csrf_token": csrf, "current_password": "alice-password",
                "new_password": "alice-new-pass",
                "confirm_password": "alice-new-pass"}),
            cookie=alice)
        self.assertEqual(status, 200)
        self.assertIn("Password changed", body)
        self._login("alice", "alice-new-pass")


if __name__ == "__main__":
    unittest.main()

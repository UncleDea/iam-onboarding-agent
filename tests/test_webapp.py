"""End-to-end smoke test of the web app over real HTTP.

Starts the app on an ephemeral port with a temporary database,
logs in, submits an on-boarding request as one user, approves it
as another, and checks the user shows up in the access review.
"""

import http.client
import os
import tempfile
import threading
import unittest
import urllib.parse

from iam_agent.auth import AuthStore
from iam_agent.config import Settings
from iam_agent.webapp import build_app, make_server


def http_request(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read().decode("utf-8")
    set_cookie = response.getheader("Set-Cookie")
    conn.close()
    return response.status, dict(response.getheaders()), data, set_cookie


class TestWebApp(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.path)
        settings = Settings(provider="mock", db_path=self.path,
                            app_host="127.0.0.1", app_port=0)
        self.ctx = build_app(settings)
        auth = self.ctx["auth"]
        auth.create_user("alice", "alice-password", "requester")
        auth.create_user("boss", "boss-password", "approver")
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
        body = urllib.parse.urlencode({"username": username,
                                       "password": password})
        status, _, _, cookie = http_request(self.port, "POST", "/login",
                                            body=body)
        self.assertEqual(status, 303)
        return cookie.split(";")[0]

    def _csrf(self, cookie):
        status, _, body, _ = http_request(self.port, "GET", "/requests/new",
                                          cookie=cookie)
        self.assertEqual(status, 200)
        marker = "name='csrf_token' value='"
        start = body.index(marker) + len(marker)
        return body[start:body.index("'", start)]

    def test_full_flow(self):
        # Health is public.
        status, _, body, _ = http_request(self.port, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertIn("healthy", body)

        # Login wall: dashboard without a session redirects.
        status, headers, _, _ = http_request(self.port, "GET", "/dashboard")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/login")

        # Alice submits an on-boarding request.
        alice = self._login("alice", "alice-password")
        status, _, dash, _ = http_request(self.port, "GET", "/dashboard",
                                          cookie=alice)
        self.assertIn("href='/dashboard' aria-current='page'", dash)
        self.assertNotIn("href='/requests' aria-current", dash)
        status, _, listing, _ = http_request(self.port, "GET", "/requests",
                                             cookie=alice)
        self.assertIn("href='/requests' aria-current='page'", listing)
        self.assertNotIn("href='/dashboard' aria-current", listing)
        status, _, pending, _ = http_request(
            self.port, "GET", "/requests?status=pending_approval",
            cookie=alice)
        self.assertIn('pending_approval" aria-current=\'page\'', pending)
        csrf = self._csrf(alice)
        body = urllib.parse.urlencode({
            "csrf_token": csrf, "kind": "onboard",
            "first_name": "Ada", "last_name": "Lovelace",
            "username": "ada.lovelace", "department": "Engineering",
            "role": "engineer", "manager": "", "start_date": "2026-11-02"})
        status, headers, _, _ = http_request(
            self.port, "POST", "/requests/new", body=body, cookie=alice)
        self.assertEqual(status, 303)
        request_path = headers["Location"]
        self.assertTrue(request_path.startswith("/requests/"))

        # Alice cannot approve her own request.
        boss = self._login("boss", "boss-password")
        status, _, detail, _ = http_request(self.port, "GET", request_path,
                                            cookie=alice)
        self.assertEqual(status, 200)
        self.assertIn("pending_approval", detail)

        # Boss approves; the user is created.
        csrf = self._csrf(boss)
        status, headers, _, _ = http_request(
            self.port, "POST", request_path + "/approve",
            body=urllib.parse.urlencode({"csrf_token": csrf}),
            cookie=boss)
        self.assertEqual(status, 303)
        status, _, detail, _ = http_request(self.port, "GET", request_path,
                                            cookie=boss)
        self.assertIn("done", detail)

        # Access review shows the new user.
        status, _, review, _ = http_request(self.port, "GET", "/review",
                                            cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("ada.lovelace", review)

        status, _, groups, _ = http_request(self.port, "GET", "/groups",
                                            cookie=alice)
        self.assertEqual(status, 200)
        self.assertIn("href='/groups' aria-current='page'", groups)
        self.assertIn(">managers</td><td>yes</td>", groups)
        self.assertIn(">analysts</td><td></td><td></td><td></td>", groups)
        self.assertIn(">engineering</td><td></td><td>ada.lovelace</td>",
                      groups)
        status, _, denied, _ = http_request(
            self.port, "POST", "/groups",
            body=urllib.parse.urlencode({
                "csrf_token": csrf, "group": "managers",
                "username": "ada.lovelace"}),
            cookie=boss)
        self.assertEqual(status, 404)
        status, _, review, _ = http_request(self.port, "GET", "/review",
                                            cookie=boss)
        self.assertIn("engineering", review)
        self.assertNotIn(">managers</td><td>yes</td><td>ada.lovelace</td>",
                         review)

        # Metrics and reports work.
        status, _, metrics, _ = http_request(self.port, "GET", "/metrics",
                                             cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("runs", metrics)
        status, _, report, _ = http_request(
            self.port, "GET", "/reports?kind=summary&format=json",
            cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("total", report)


if __name__ == "__main__":
    unittest.main()

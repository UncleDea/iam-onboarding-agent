"""Optional sign-in with Microsoft for people who already have an app account.

This does not grant access by itself. After Microsoft identifies the
person, the app looks for an existing username and refuses anyone it
does not already know. The directory connector is a separate setting.
"""

import json
import urllib.error
import urllib.parse
import urllib.request


class MicrosoftLogin:
    def __init__(self, tenant: str, client_id: str, client_secret: str,
                 redirect_uri: str, request_fn=None):
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._request = request_fn or self._urllib

    def authorize_url(self, state: str) -> str:
        query = urllib.parse.urlencode({
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": "openid profile email User.Read",
            "state": state,
        })
        return (f"https://login.microsoftonline.com/{self.tenant}"
                f"/oauth2/v2.0/authorize?{query}")

    def account_name(self, code: str) -> str:
        """Return the Microsoft account name for an authorization code."""
        body = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }).encode("utf-8")
        status, payload = self._request(
            "POST",
            f"https://login.microsoftonline.com/{self.tenant}"
            "/oauth2/v2.0/token",
            {"Content-Type": "application/x-www-form-urlencoded"},
            body)
        if status != 200 or "access_token" not in payload:
            raise ValueError("Microsoft did not accept that sign-in")
        status, profile = self._request(
            "GET", "https://graph.microsoft.com/v1.0/me"
            "?$select=userPrincipalName,mail",
            {"Authorization": f"Bearer {payload['access_token']}"},
            None)
        if status != 200:
            raise ValueError("Microsoft did not return an account name")
        name = profile.get("userPrincipalName") or profile.get("mail") or ""
        if not name:
            raise ValueError("Microsoft did not return an account name")
        return name

    @staticmethod
    def _urllib(method, url, headers, body):
        request = urllib.request.Request(url, data=body, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return exc.code, {}

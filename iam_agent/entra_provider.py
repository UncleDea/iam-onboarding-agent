"""A real Microsoft Entra ID provider, over Microsoft Graph.

This is the provider the engine was designed for: it implements the
same IdentityProvider interface as the mock and SQLite providers, so
every flow -- on-board, move, off-board, approval, audit, retries,
compensation -- works unchanged against a real directory.

Authentication is the OAuth 2.0 client-credentials flow: the app
registration authenticates with its own client secret and gets a
token for Graph. No user signs in, and no user credential is ever
handled here. Configuration comes only from the environment:

    IAM_ENTRA_TENANT_ID       e.g. maofu.onmicrosoft.com or a GUID
    IAM_ENTRA_CLIENT_ID       the app registration's client ID
    IAM_ENTRA_CLIENT_SECRET   the client secret (never in code, never
                              in logs, never as a CLI argument)
    IAM_ENTRA_DOMAIN          e.g. maofu.onmicrosoft.com -- used to
                              build userPrincipalNames from usernames
    IAM_ENTRA_USAGE_LOCATION  required ISO country code, e.g. US
    IAM_ENTRA_LICENSE_MAP     optional JSON: policy licence name ->
                              Graph skuPartNumber, e.g.
                              {"office-standard": "ENTERPRISEPACK"}

Deliberate choices, worth knowing before you run it:

- Standard library only (urllib). MSAL would also be a fine choice;
  doing the token flow directly keeps the dependency list at zero
  and makes every request visible in this one file.
- Tokens are cached in memory until shortly before expiry.
- Graph 429s and 5xx errors become TransientError, so the engine's
  retry logic applies. Other Graph errors become ValueError with
  Graph's own message -- except that nothing secret is ever included.
- Licence names in policies (e.g. "office-standard") are not Graph
  skuPartNumbers. The license map translates them; an unmapped
  licence is a loud error, not a guess, because silently assigning
  the wrong licence would be worse than failing.
- Usernames become UPNs via IAM_ENTRA_DOMAIN. If a username already
  contains "@", it is used as-is.
"""

import json
import os
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request

from .providers import AlreadyExists, IdentityProvider, NotFound
from .retry import TransientError

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _graph_message(payload: dict) -> str:
    """Graph's error as 'code: message'. The code matters: callers
    match on it (Request_ResourceNotFound, Request_ResourceAlreadyExists),
    and the message alone does not carry it."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        code = error.get("code") or ""
        message = error.get("message") or ""
        if code and message:
            return f"{code}: {message}"
        return code or message or "unknown error"
    return "unknown error"


class GraphClient:
    """Minimal Graph client: token acquisition, requests, pagination.

    request_fn is injectable for tests: it takes
    (method, url, headers, body_bytes) and returns (status, payload).
    Production uses the urllib implementation.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 request_fn=None):
        self.token_url = (
            f"https://login.microsoftonline.com/{tenant_id}"
            "/oauth2/v2.0/token")
        self.client_id = client_id
        self.client_secret = client_secret
        self._request_fn = request_fn or self._urllib_request
        self._token = None
        self._token_expires_at = 0.0

    def token(self) -> str:
        """Return a valid access token, fetching a fresh one if needed."""
        if self._token and time.time() < self._token_expires_at:
            return self._token
        body = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }).encode("utf-8")
        status, payload = self._request_fn(
            "POST", self.token_url,
            {"Content-Type": "application/x-www-form-urlencoded"}, body)
        if status != 200:
            raise ValueError(
                f"Entra token request failed ({status}): "
                f"{_graph_message(payload)}")
        self._token = payload["access_token"]
        # Refresh a minute early so a token never expires mid-request.
        self._token_expires_at = time.time() + int(payload["expires_in"]) - 60
        return self._token

    def request(self, method: str, path: str, body: dict = None) -> dict:
        """One Graph call. path may be a relative path or a full
        @odata.nextLink URL."""
        url = path if path.startswith("http") else GRAPH_BASE + path
        headers = {
            "Authorization": f"Bearer {self.token()}",
            "Content-Type": "application/json",
        }
        data = json.dumps(body).encode("utf-8") if body is not None else None
        status, payload = self._request_fn(method, url, headers, data)
        if 200 <= status < 300:
            return payload
        if status == 429 or status >= 500:
            raise TransientError(
                f"Graph {method} {path} transient failure ({status}): "
                f"{_graph_message(payload)}")
        raise ValueError(
            f"Graph {method} {path} failed ({status}): "
            f"{_graph_message(payload)}")

    def get_all(self, path: str) -> list:
        """GET a collection, following @odata.nextLink to the end."""
        items = []
        url = path
        while url:
            payload = self.request("GET", url)
            items.extend(payload.get("value", []))
            url = payload.get("@odata.nextLink")
        return items

    @staticmethod
    def _urllib_request(method, url, headers, body):
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


class EntraProvider(IdentityProvider):
    """Entra ID provider backed by Microsoft Graph."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 domain: str, usage_location: str = "US",
                 license_map: dict = None, graph: GraphClient = None,
                 temp_password: str = None):
        if not usage_location:
            raise ValueError(
                "EntraProvider needs IAM_ENTRA_USAGE_LOCATION "
                "(for example US) before it can assign licences")
        del temp_password
        self.domain = domain
        self.usage_location = usage_location
        self.license_map = dict(license_map or {})
        self.graph = graph or GraphClient(tenant_id, client_id, client_secret)
        self._group_id_cache = {}
        self._sku_cache = None
        self._passwords = {}

    @classmethod
    def from_env(cls, graph: GraphClient = None):
        """Build from environment. Missing values are listed, not
        guessed -- a half-configured provider must fail fast."""
        missing = [name for name in (
            "IAM_ENTRA_TENANT_ID", "IAM_ENTRA_CLIENT_ID",
            "IAM_ENTRA_CLIENT_SECRET", "IAM_ENTRA_DOMAIN",
            "IAM_ENTRA_USAGE_LOCATION") if not os.environ.get(name)]
        if missing:
            raise ValueError(
                "Entra provider missing environment variables: "
                + ", ".join(missing))
        license_map = {}
        raw_map = os.environ.get("IAM_ENTRA_LICENSE_MAP", "")
        if raw_map:
            license_map = json.loads(raw_map)
        return cls(
            tenant_id=os.environ["IAM_ENTRA_TENANT_ID"],
            client_id=os.environ["IAM_ENTRA_CLIENT_ID"],
            client_secret=os.environ["IAM_ENTRA_CLIENT_SECRET"],
            domain=os.environ["IAM_ENTRA_DOMAIN"],
            usage_location=os.environ["IAM_ENTRA_USAGE_LOCATION"],
            license_map=license_map,
            graph=graph,
        )

    # -- IdentityProvider interface ------------------------------------

    def create_user(self, hire) -> dict:
        upn = self._upn(hire.username)
        password = self._new_password()
        body = {
            "accountEnabled": False,
            "displayName": hire.display_name,
            "mailNickname": hire.username.split("@")[0],
            "userPrincipalName": upn,
            "department": hire.department,
            "employeeType": hire.role,
            "usageLocation": self.usage_location,
            "passwordProfile": {
                "password": password,
                "forceChangePasswordNextSignIn": True,
            },
        }
        try:
            created = self.graph.request("POST", "/users", body)
        except ValueError as exc:
            if "Request_ResourceAlreadyExists" in str(exc):
                raise AlreadyExists(
                    f"user {hire.username!r} already exists") from None
            raise
        self._passwords[hire.username] = password
        if getattr(hire, "manager", ""):
            manager_id = self._require_user_id(hire.manager)
            user_id = created.get("id") or self._require_user_id(hire.username)
            self.graph.request(
                "PUT", f"/users/{user_id}/manager/$ref",
                {"@odata.id": f"{GRAPH_BASE}/users/{manager_id}"})
        return self.get_user(hire.username) or {"id": created.get("id"),
                                                "username": hire.username}

    def take_temporary_password(self, username: str):
        """Return the one-time password, once. It is not logged."""
        return self._passwords.pop(username, None)

    def get_user(self, username: str):
        try:
            user = self.graph.request(
                "GET",
                f"/users/{self._upn(username)}?$select=id,displayName,"
                "department,employeeType,accountEnabled,assignedLicenses")
        except ValueError as exc:
            if "Request_ResourceNotFound" in str(exc):
                return None
            raise
        direct = self._group_names(
            f"/users/{user['id']}/memberOf?$select=displayName")
        transitive = self._group_names(
            f"/users/{user['id']}/transitiveMemberOf?$select=displayName")
        return {
            "username": username,
            "display_name": user["displayName"],
            "department": user.get("department") or "",
            "role": user.get("employeeType") or "",
            "manager": "",
            "active": bool(user.get("accountEnabled")),
            "groups": sorted(direct),
            "inherited_groups": sorted(set(transitive) - set(direct)),
            "licenses": sorted(
                self._license_name(sku["skuId"])
                for sku in user.get("assignedLicenses", [])),
        }

    def update_user(self, username: str, **fields) -> None:
        user_id = self._require_user_id(username)
        body = {}
        if "department" in fields:
            body["department"] = fields["department"]
        if "role" in fields:
            body["employeeType"] = fields["role"]
        if body:
            self.graph.request("PATCH", f"/users/{user_id}", body)

    def add_to_group(self, username: str, group: str) -> None:
        user_id = self._require_user_id(username)
        group_id = self._group_id(group)
        try:
            self.graph.request(
                "POST", f"/groups/{group_id}/members/$ref",
                {"@odata.id": f"{GRAPH_BASE}/users/{user_id}"})
        except ValueError as exc:
            if "already exist" in str(exc).lower():
                return
            raise

    def remove_from_group(self, username: str, group: str) -> None:
        user_id = self._require_user_id(username)
        group_id = self._group_id(group)
        self.graph.request(
            "DELETE", f"/groups/{group_id}/members/{user_id}/$ref")

    def assign_license(self, username: str, license_name: str) -> None:
        user_id = self._require_user_id(username)
        sku_id = self._sku_id(license_name)
        self.graph.request(
            "POST", f"/users/{user_id}/assignLicense",
            {"addLicenses": [{"skuId": sku_id}], "removeLicenses": []})

    def revoke_license(self, username: str, license_name: str) -> None:
        user_id = self._require_user_id(username)
        sku_id = self._sku_id(license_name)
        self.graph.request(
            "POST", f"/users/{user_id}/assignLicense",
            {"addLicenses": [], "removeLicenses": [sku_id]})

    def disable_user(self, username: str) -> None:
        user_id = self._require_user_id(username)
        self.graph.request("PATCH", f"/users/{user_id}",
                           {"accountEnabled": False})

    def enable_user(self, username: str) -> None:
        user_id = self._require_user_id(username)
        self.graph.request("PATCH", f"/users/{user_id}",
                           {"accountEnabled": True})

    def list_users(self) -> list:
        users = self.graph.get_all(
            "/users?$select=id,displayName,department,employeeType,"
            "accountEnabled,assignedLicenses&$top=100")
        result = []
        for user in users:
            direct = self._group_names(
                f"/users/{user['id']}/memberOf?$select=displayName")
            transitive = self._group_names(
                f"/users/{user['id']}/transitiveMemberOf"
                "?$select=displayName")
            result.append({
                "username": user.get("userPrincipalName", ""),
                "display_name": user["displayName"],
                "department": user.get("department") or "",
                "role": user.get("employeeType") or "",
                "active": bool(user.get("accountEnabled")),
                "groups": sorted(direct),
                "inherited_groups": sorted(set(transitive) - set(direct)),
                "licenses": sorted(
                    self._license_name(sku["skuId"])
                    for sku in user.get("assignedLicenses", [])),
            })
        return result

    # -- helpers ---------------------------------------------------------

    def _upn(self, username: str) -> str:
        if "@" in username:
            return username
        return f"{username}@{self.domain}"

    def _require_user_id(self, username: str) -> str:
        try:
            user = self.graph.request(
                "GET",
                f"/users/{self._upn(username)}?$select=id")
        except ValueError as exc:
            if "Request_ResourceNotFound" in str(exc):
                raise NotFound(f"unknown user {username!r}") from None
            raise
        return user["id"]

    def _group_id(self, display_name: str) -> str:
        if display_name not in self._group_id_cache:
            safe = display_name.replace("'", "''")
            groups = self.graph.get_all(
                "/groups?$filter=" + urllib.parse.quote(
                    f"displayName eq '{safe}'")
                + "&$select=id")
            if len(groups) != 1:
                raise ValueError(
                    f"group {display_name!r} matched {len(groups)} groups; "
                    "a name must match exactly one")
            self._group_id_cache[display_name] = groups[0]["id"]
        return self._group_id_cache[display_name]

    def _group_names(self, path: str) -> list:
        try:
            items = self.graph.get_all(path)
        except ValueError as exc:
            if "Request_ResourceNotFound" in str(exc):
                return []
            raise
        return [item["displayName"] for item in items
                if item.get("@odata.type") == "#microsoft.graph.group"
                and item.get("displayName")]

    def _new_password(self) -> str:
        alphabet = string.ascii_letters + string.digits
        body = "".join(secrets.choice(alphabet) for _ in range(24))
        return body + "aA1!"

    def _subscribed_skus(self) -> list:
        if self._sku_cache is None:
            self._sku_cache = self.graph.get_all(
                "/subscribedSkus?$select=skuId,skuPartNumber")
        return self._sku_cache

    def _sku_id(self, license_name: str) -> str:
        part_number = self.license_map.get(license_name)
        if part_number is None:
            raise ValueError(
                f"licence {license_name!r} has no Graph skuPartNumber "
                "mapping; set IAM_ENTRA_LICENSE_MAP (see ENTRA_SETUP.md)")
        for sku in self._subscribed_skus():
            if sku["skuPartNumber"] == part_number:
                return sku["skuId"]
        raise ValueError(
            f"licence {license_name!r} (skuPartNumber {part_number}) is "
            "not subscribed in this tenant")

    def _license_name(self, sku_id: str) -> str:
        """Translate a skuId back to a policy licence name when the
        mapping knows it; otherwise return the skuPartNumber, so the
        access picture stays readable either way."""
        for name, part_number in self.license_map.items():
            for sku in self._subscribed_skus():
                if (sku["skuId"] == sku_id
                        and sku["skuPartNumber"] == part_number):
                    return name
        for sku in self._subscribed_skus():
            if sku["skuId"] == sku_id:
                return sku["skuPartNumber"]
        return sku_id

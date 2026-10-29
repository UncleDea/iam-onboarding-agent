"""Tests for the Entra provider against a fake Graph transport.

No network, no tenant, no secrets: the fake records every request
and returns canned responses, so these tests verify the exact
endpoints, payloads, and error mapping the real provider would use.
"""

import unittest

from iam_agent.entra_provider import EntraProvider, GraphClient
from iam_agent.providers import AlreadyExists
from iam_agent.models import NewHire
from iam_agent.retry import TransientError


class FakeGraph:
    """Canned Graph: keyed by (method, path-without-query)."""

    def __init__(self, routes):
        self.routes = routes  # dict (method, path) -> (status, payload)
        self.calls = []

    def __call__(self, method, url, headers, body):
        path = url.split("https://graph.microsoft.com/v1.0")[-1]
        path = path.split("https://login.microsoftonline.com/")[-1]
        self.calls.append((method, path, body))
        if url.startswith("https://login.microsoftonline.com/"):
            return 200, {"access_token": "fake-token", "expires_in": 3600}
        # Strip query for routing, but keep it in the recorded call.
        route_key = (method, path.split("?")[0])
        if route_key in self.routes:
            return self.routes[route_key]
        return 404, {"error": {"code": "Request_ResourceNotFound",
                               "message": "not found"}}


def make_provider(routes, license_map=None):
    fake = FakeGraph(routes)
    graph = GraphClient("tenant", "client", "secret", request_fn=fake)
    provider = EntraProvider(
        "tenant", "client", "secret", "example.onmicrosoft.com",
        temp_password="TempPass123!", license_map=license_map or {},
        graph=graph)
    return provider, fake


def hire():
    return NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                   "engineer")


class TestEntraProvider(unittest.TestCase):
    def test_create_user_posts_correct_payload(self):
        routes = {
            ("POST", "/users"): (201, {"id": "u1"}),
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1", "displayName": "Ada Lovelace",
                      "department": "Engineering", "jobTitle": "engineer",
                      "accountEnabled": True, "assignedLicenses": []}),
            ("GET", "/users/u1/memberOf"): (200, {"value": []}),
        }
        provider, fake = make_provider(routes)
        provider.create_user(hire())
        method, path, body = fake.calls[1]
        self.assertEqual((method, path), ("POST", "/users"))
        import json
        payload = json.loads(body)
        self.assertEqual(payload["userPrincipalName"],
                         "ada.lovelace@example.onmicrosoft.com")
        self.assertEqual(payload["mailNickname"], "ada.lovelace")
        self.assertEqual(payload["usageLocation"], "US")
        self.assertEqual(payload["employeeType"], "engineer")
        self.assertNotIn("jobTitle", payload)
        self.assertNotEqual(payload["passwordProfile"]["password"],
                            "TempPass123!")
        self.assertTrue(payload["passwordProfile"]
                        ["forceChangePasswordNextSignIn"])

    def test_duplicate_create_maps_to_already_exists(self):
        routes = {("POST", "/users"): (
            409, {"error": {"code": "Request_ResourceAlreadyExists",
                            "message": "exists"}})}
        provider, _ = make_provider(routes)
        with self.assertRaises(AlreadyExists) as ctx:
            provider.create_user(hire())
        self.assertIn("already exists", str(ctx.exception))

    def test_get_user_returns_groups_and_licenses(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1", "displayName": "Ada Lovelace",
                      "department": "Engineering", "jobTitle": "engineer",
                      "accountEnabled": True,
                      "assignedLicenses": [{"skuId": "sku-e3"}]}),
            ("GET", "/users/u1/memberOf"): (
                200, {"value": [
                    {"@odata.type": "#microsoft.graph.group",
                     "displayName": "engineering"},
                    {"@odata.type": "#microsoft.graph.directoryRole",
                     "displayName": "not-a-group"}]}),
            ("GET", "/subscribedSkus"): (
                200, {"value": [{"skuId": "sku-e3",
                                 "skuPartNumber": "ENTERPRISEPACK"}]}),
        }
        provider, _ = make_provider(
            routes, license_map={"office-standard": "ENTERPRISEPACK"})
        user = provider.get_user("ada.lovelace")
        self.assertEqual(user["groups"], ["engineering"])
        self.assertEqual(user["licenses"], ["office-standard"])
        self.assertTrue(user["active"])

    def test_unknown_user_returns_none(self):
        provider, _ = make_provider({})
        self.assertIsNone(provider.get_user("ghost"))

    def test_group_add_resolves_display_name_once(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1"}),
            ("GET", "/groups"): (200, {"value": [{"id": "g1"}]}),
            ("POST", "/groups/g1/members/$ref"): (204, {}),
        }
        provider, fake = make_provider(routes)
        provider.add_to_group("ada.lovelace", "engineering")
        provider.add_to_group("ada.lovelace", "engineering")
        group_lookups = [c for c in fake.calls
                         if c[0] == "GET" and c[1].startswith("/groups")]
        self.assertEqual(len(group_lookups), 1)  # cached after first

    def test_unmapped_license_is_a_loud_error(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1"}),
        }
        provider, _ = make_provider(routes)
        with self.assertRaises(ValueError) as ctx:
            provider.assign_license("ada.lovelace", "office-standard")
        self.assertIn("no Graph skuPartNumber mapping", str(ctx.exception))

    def test_token_is_fetched_once_and_reused(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1"}),
        }
        provider, fake = make_provider(routes)
        provider._require_user_id("ada.lovelace")
        provider._require_user_id("ada.lovelace")
        # The token endpoint is hit once; the second call reuses cache.
        token_calls = [c for c in fake.calls if c[0] == "POST"
                       and "oauth2" in c[1]]
        self.assertEqual(len(token_calls), 1)

    def test_transient_graph_errors_raise_transient(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                503, {"error": {"code": "ServiceUnavailable",
                                "message": "try again"}}),
        }
        provider, _ = make_provider(routes)
        with self.assertRaises(TransientError):
            provider.get_user("ada.lovelace")

    def test_engine_run_works_against_entra(self):
        from iam_agent import OnboardingAgent
        routes = {
            ("POST", "/users"): (201, {"id": "u1"}),
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1", "displayName": "Ada Lovelace",
                      "department": "Engineering", "jobTitle": "engineer",
                      "accountEnabled": True, "assignedLicenses": []}),
            ("GET", "/users/u1/memberOf"): (200, {"value": []}),
            ("GET", "/groups"): (200, {"value": [{"id": "g1"}]}),
            ("POST", "/groups/g1/members/$ref"): (204, {}),
            ("POST", "/users/u1/assignLicense"): (200, {}),
            ("PATCH", "/users/u1"): (200, {}),
            ("GET", "/subscribedSkus"): (
                200, {"value": [{"skuId": "sku-e3",
                                 "skuPartNumber": "ENTERPRISEPACK"}]}),
        }
        provider, _ = make_provider(
            routes, license_map={"office-standard": "ENTERPRISEPACK"})
        agent = OnboardingAgent(provider, approver=lambda p, h: True)
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")

    def test_ambiguous_group_name_is_refused(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1"}),
            ("GET", "/groups"): (200, {"value": [{"id": "g1"}, {"id": "g2"}]}),
        }
        provider, _ = make_provider(routes)
        with self.assertRaises(ValueError) as ctx:
            provider.add_to_group("ada.lovelace", "engineering")
        self.assertIn("matched 2", str(ctx.exception))

    def test_inherited_group_is_separate_from_direct(self):
        routes = {
            ("GET", "/users/ada.lovelace@example.onmicrosoft.com"): (
                200, {"id": "u1", "displayName": "Ada Lovelace",
                      "department": "Engineering", "employeeType": "engineer",
                      "accountEnabled": True, "assignedLicenses": []}),
            ("GET", "/users/u1/memberOf"): (
                200, {"value": [
                    {"@odata.type": "#microsoft.graph.group",
                     "displayName": "engineering"}]}),
            ("GET", "/users/u1/transitiveMemberOf"): (
                200, {"value": [
                    {"@odata.type": "#microsoft.graph.group",
                     "displayName": "engineering"},
                    {"@odata.type": "#microsoft.graph.group",
                     "displayName": "all-staff"}]}),
        }
        provider, _ = make_provider(routes)
        user = provider.get_user("ada.lovelace")
        self.assertEqual(user["groups"], ["engineering"])
        self.assertEqual(user["inherited_groups"], ["all-staff"])


if __name__ == "__main__":
    unittest.main()

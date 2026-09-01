import json
import unittest

from mobile_demo.app import create_app


class MobileWebDemoTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("test-token", "agent:deployer")
        self.client = self.app.test_client()

    def auth_headers(self):
        return {"Authorization": "Bearer test-token"}

    def test_policy_endpoint_allows_valid_intent(self):
        response = self.client.post(
            "/api/decision",
            data=json.dumps({
                "principal": "agent:deployer",
                "action": "deploy",
                "resource": "service:api-server",
                "cost": 80,
            }),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("allow", payload["outcome"])
        self.assertTrue(payload["permit"])

    def test_policy_endpoint_rejects_bad_action(self):
        response = self.client.post(
            "/api/decision",
            data=json.dumps({
                "principal": "agent:deployer",
                "action": "execute",
                "resource": "repo:script.sh",
                "cost": 10,
            }),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("deny", payload["outcome"])
        self.assertEqual("action_not_allowed", payload["reason"])

    def test_policy_endpoint_rejects_malformed_cost(self):
        response = self.client.post(
            "/api/decision",
            data=json.dumps({
                "principal": "agent:deployer",
                "action": "read",
                "resource": "repo:docs",
                "cost": "not-a-number",
            }),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(400, response.status_code)
        payload = response.get_json()
        self.assertEqual("deny", payload["outcome"])
        self.assertEqual("invalid_cost", payload["reason"])

    def test_policy_endpoint_rejects_non_object_json(self):
        response = self.client.post(
            "/api/decision",
            data=json.dumps(["not", "an", "object"]),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(400, response.status_code)
        payload = response.get_json()
        self.assertEqual("deny", payload["outcome"])
        self.assertEqual("invalid_request", payload["reason"])

    def test_policy_endpoint_requires_authentication(self):
        response = self.client.post(
            "/api/decision",
            data=json.dumps({
                "principal": "agent:deployer",
                "action": "read",
                "resource": "repo:docs",
                "cost": 10,
            }),
            content_type="application/json",
        )
        self.assertEqual(401, response.status_code)
        self.assertEqual("authentication_required", response.get_json()["reason"])

    def test_policy_endpoint_rejects_principal_substitution(self):
        response = self.client.post(
            "/api/decision",
            data=json.dumps({
                "principal": "agent:attacker",
                "action": "read",
                "resource": "repo:docs",
                "cost": 10,
            }),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual("principal_not_allowed", response.get_json()["reason"])


if __name__ == "__main__":
    unittest.main()

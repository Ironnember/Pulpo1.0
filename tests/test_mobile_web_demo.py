import json
import os
import sys
import unittest

from mobile_demo.app import create_app, main


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

    def test_app_exposes_installable_pwa_assets(self):
        manifest = self.client.get("/manifest.webmanifest")
        service_worker = self.client.get("/sw.js")
        self.assertEqual(200, manifest.status_code)
        self.assertIn("Pulpo Mobile", manifest.get_data(as_text=True))
        self.assertEqual(200, service_worker.status_code)
        self.assertIn("CACHE_NAME", service_worker.get_data(as_text=True))

    def test_app_uses_bundled_static_root_when_frozen(self):
        original_meipass = getattr(sys, "_MEIPASS", None)
        try:
            sys._MEIPASS = os.path.dirname(os.path.dirname(__file__))
            app = create_app("test-token", "agent:deployer")
            self.assertEqual(
                os.path.join(sys._MEIPASS, "mobile_demo", "static"),
                app.static_folder,
            )
        finally:
            if original_meipass is None:
                del sys._MEIPASS
            else:
                sys._MEIPASS = original_meipass

    def test_local_install_exposes_mobile_command(self):
        self.assertTrue(callable(main))

    def test_policy_endpoint_rejects_expired_token(self):
        app = create_app("test-token", "agent:deployer", token_expires_at=1)
        response = app.test_client().post(
            "/api/decision",
            data=json.dumps({
                "principal": "agent:deployer",
                "action": "read",
                "resource": "repo:docs",
                "cost": 10,
            }),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(401, response.status_code)
        self.assertEqual("authentication_expired", response.get_json()["reason"])

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

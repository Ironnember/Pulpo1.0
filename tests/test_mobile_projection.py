import importlib.util
import json
import unittest

from pulpo.kernel import GovernanceKernel, Policy
from pulpo.mcp_boundary import PulpoMCPProjection
from pulpo.orchestrator import PulpoOrchestrator
from mobile_demo.app import create_app


FLASK_AVAILABLE = importlib.util.find_spec("flask") is not None


@unittest.skipUnless(FLASK_AVAILABLE, "install the 'web' optional dependency")
class MobileProjectionTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(Policy(allowed_actions=frozenset({"read"}), max_cost=10))
        self.projection = PulpoMCPProjection(PulpoOrchestrator(self.kernel))
        self.app = create_app(
            self.projection,
            auth_token="test-token",
            principal="agent:mobile",
        )
        self.client = self.app.test_client()

    @staticmethod
    def proposal(**overrides):
        payload = {
            "target_id": "mobile-target",
            "action": "read",
            "resource": "repo:docs",
            "cost": 0,
            "session_id": "mobile",
            "version": 1,
        }
        payload.update(overrides)
        return payload

    @staticmethod
    def auth_headers():
        return {"Authorization": "Bearer test-token"}

    def test_valid_proposal_locks_exact_target_without_permit(self):
        response = self.client.post(
            "/api/propose",
            data=json.dumps(self.proposal()),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("pulpo.mcp-proposal.v0", payload["schema"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertNotIn("permit", payload)
        target = self.kernel.get_locked_target("mobile-target")
        self.assertIsNotNone(target)
        self.assertEqual("agent:mobile", target.intent.principal)

    def test_client_cannot_supply_or_replace_principal(self):
        response = self.client.post(
            "/api/propose",
            data=json.dumps(self.proposal(principal="agent:attacker")),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("mobile_payload_invalid", response.get_json()["reason"])
        self.assertIsNone(self.kernel.get_locked_target("mobile-target"))

    def test_proposal_requires_authentication(self):
        response = self.client.post(
            "/api/propose",
            data=json.dumps(self.proposal()),
            content_type="application/json",
        )
        self.assertEqual(401, response.status_code)
        payload = response.get_json()
        self.assertEqual("authentication_required", payload["reason"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertIsNone(self.kernel.get_locked_target("mobile-target"))

    def test_malformed_cost_fails_closed(self):
        response = self.client.post(
            "/api/propose",
            data=json.dumps(self.proposal(cost=True)),
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("mcp_intent_invalid", response.get_json()["reason"])
        self.assertIsNone(self.kernel.get_locked_target("mobile-target"))

    def test_evidence_projection_is_read_only_and_has_no_permit(self):
        before = len(self.kernel.audit)
        response = self.client.get("/api/evidence", headers=self.auth_headers())
        after = len(self.kernel.audit)
        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(before, after)
        self.assertEqual("pulpo.mcp-evidence.v0", payload["schema"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertNotIn("permit", payload)

    def test_authority_and_execution_endpoints_do_not_exist(self):
        for path in ("/api/decision", "/api/approve", "/api/authorize", "/api/execute", "/api/consume"):
            with self.subTest(path=path):
                self.assertEqual(404, self.client.post(path).status_code)

    def test_pwa_assets_are_installable_but_api_is_not_cacheable(self):
        manifest = self.client.get("/manifest.webmanifest")
        worker = self.client.get("/sw.js")
        icon = self.client.get("/static/icon.svg")
        self.assertEqual(200, manifest.status_code)
        self.assertIn("Pulpo Mobile Projection", manifest.get_data(as_text=True))
        self.assertEqual(200, worker.status_code)
        worker_text = worker.get_data(as_text=True)
        self.assertIn("CACHE_NAME", worker_text)
        self.assertIn("startsWith('/api/')", worker_text)
        self.assertEqual(200, icon.status_code)

    def test_app_requires_existing_canonical_projection(self):
        with self.assertRaises(TypeError):
            create_app(object(), auth_token="test-token", principal="agent:mobile")


if __name__ == "__main__":
    unittest.main()

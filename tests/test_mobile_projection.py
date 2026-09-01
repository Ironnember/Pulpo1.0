import importlib.util
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
        self.app = create_app(self.projection, auth_token="test-token")
        self.client = self.app.test_client()

    @staticmethod
    def auth_headers():
        return {"Authorization": "Bearer test-token"}

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

    def test_evidence_requires_authentication_without_mutation(self):
        before = len(self.kernel.audit)
        response = self.client.get("/api/evidence")
        after = len(self.kernel.audit)
        self.assertEqual(401, response.status_code)
        payload = response.get_json()
        self.assertEqual("authentication_required", payload["reason"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertEqual(before, after)

    def test_distribution_surface_has_no_canonical_mutation_routes(self):
        before = len(self.kernel.audit)
        for path in (
            "/api/propose",
            "/api/decision",
            "/api/approve",
            "/api/authorize",
            "/api/execute",
            "/api/consume",
        ):
            with self.subTest(path=path):
                response = self.client.post(path, headers=self.auth_headers())
                self.assertEqual(404, response.status_code)
        self.assertEqual(before, len(self.kernel.audit))

    def test_repeated_read_access_does_not_append_canonical_audit(self):
        before = len(self.kernel.audit)
        for _ in range(3):
            self.assertEqual(200, self.client.get("/api/evidence", headers=self.auth_headers()).status_code)
        self.assertEqual(before, len(self.kernel.audit))

    def test_ui_exposes_evidence_only(self):
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        text = response.get_data(as_text=True)
        self.assertIn("Read-only evidence projection", text)
        self.assertIn("Read evidence", text)
        self.assertNotIn("Lock proposal", text)
        self.assertNotIn("/api/propose", text)
        self.assertNotIn("Principal:", text)

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
            create_app(object(), auth_token="test-token")

    def test_app_requires_nonempty_access_token(self):
        with self.assertRaises(ValueError):
            create_app(self.projection, auth_token="")


if __name__ == "__main__":
    unittest.main()

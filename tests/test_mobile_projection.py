import importlib.util
import unittest

import mobile_demo.app as mobile_app
from mobile_demo.app import FrozenEvidenceSource, create_app
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.mcp_boundary import PulpoMCPProjection
from pulpo.orchestrator import PulpoOrchestrator


FLASK_AVAILABLE = importlib.util.find_spec("flask") is not None


@unittest.skipUnless(FLASK_AVAILABLE, "install the 'web' optional dependency")
class MobileProjectionTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(Policy(allowed_actions=frozenset({"read"}), max_cost=10))
        self.projection = PulpoMCPProjection(PulpoOrchestrator(self.kernel))
        self.snapshot = self.projection.evidence_snapshot()
        self.source = FrozenEvidenceSource(self.snapshot)
        self.app = create_app(self.source, auth_token="test-token")
        self.client = self.app.test_client()

    @staticmethod
    def auth_headers():
        return {"Authorization": "Bearer test-token"}

    def test_distribution_module_imports_no_pulpo_capability_type(self):
        for name in ("GovernanceKernel", "PulpoOrchestrator", "PulpoMCPProjection"):
            self.assertNotIn(name, mobile_app.__dict__)

    def test_frozen_source_copies_primitives_and_retains_no_writer_reference(self):
        original = dict(self.snapshot)
        source = FrozenEvidenceSource(original)
        original["audit_records"] = 999

        self.assertEqual(self.snapshot["audit_records"], source.read_evidence()["audit_records"])
        for name in ("kernel", "orchestrator", "projection", "propose_intent", "lock_target"):
            self.assertFalse(hasattr(source, name), name)

    def test_app_rejects_write_capable_projection_dependency(self):
        with self.assertRaises(TypeError):
            create_app(self.projection, auth_token="test-token")

    def test_evidence_snapshot_is_explicitly_frozen_and_has_no_permit(self):
        before = len(self.kernel.audit)
        response = self.client.get("/api/evidence", headers=self.auth_headers())
        after = len(self.kernel.audit)

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(before, after)
        self.assertEqual("pulpo.mobile-evidence-snapshot.v0", payload["schema"])
        self.assertEqual("not_asserted", payload["freshness"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertNotIn("permit", payload)
        self.assertEqual("pulpo.mcp-evidence.v0", payload["source"]["schema"])
        self.assertEqual("none", payload["source"]["authority_effect"])
        self.assertNotIn("permit", payload["source"])

    def test_canonical_changes_do_not_create_hidden_live_or_write_path(self):
        frozen_records = self.source.read_evidence()["audit_records"]
        self.projection.propose_intent(
            "after-snapshot",
            "agent:test",
            "read",
            "repo:docs",
        )
        canonical_records = len(self.kernel.audit)
        self.assertGreater(canonical_records, frozen_records)

        response = self.client.get("/api/evidence", headers=self.auth_headers())
        payload = response.get_json()
        self.assertEqual("not_asserted", payload["freshness"])
        self.assertEqual(frozen_records, payload["source"]["audit_records"])
        self.assertEqual(canonical_records, len(self.kernel.audit))

    def test_evidence_requires_authentication_without_mutation(self):
        before = len(self.kernel.audit)
        response = self.client.get("/api/evidence")
        after = len(self.kernel.audit)

        self.assertEqual(401, response.status_code)
        payload = response.get_json()
        self.assertEqual("authentication_required", payload["reason"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertEqual(before, after)
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_distribution_route_map_has_no_canonical_mutation_paths_or_methods(self):
        rules = {rule.rule: set(rule.methods) for rule in self.app.url_map.iter_rules()}
        for path in (
            "/api/propose",
            "/api/decision",
            "/api/approve",
            "/api/authorize",
            "/api/execute",
            "/api/consume",
        ):
            self.assertNotIn(path, rules)

        self.assertIn("/api/evidence", rules)
        self.assertIn("GET", rules["/api/evidence"])
        self.assertTrue(rules["/api/evidence"].isdisjoint({"POST", "PUT", "PATCH", "DELETE"}))

    def test_repeated_read_access_does_not_append_canonical_audit(self):
        before = len(self.kernel.audit)
        for _ in range(3):
            self.assertEqual(200, self.client.get("/api/evidence", headers=self.auth_headers()).status_code)
        self.assertEqual(before, len(self.kernel.audit))

    def test_evidence_response_and_browser_fetch_are_no_store(self):
        response = self.client.get("/api/evidence", headers=self.auth_headers())
        self.assertEqual(200, response.status_code)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual("no-cache", response.headers["Pragma"])
        self.assertEqual("0", response.headers["Expires"])
        self.assertEqual("Authorization", response.headers["Vary"])

        index = self.client.get("/").get_data(as_text=True)
        self.assertIn("cache:'no-store'", index)
        self.assertIn("Freshness is not asserted", index)

    def test_pwa_assets_are_installable_but_api_is_not_service_worker_cacheable(self):
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

    def test_source_rejects_authority_or_invalid_evidence_payloads(self):
        with self.assertRaisesRegex(ValueError, "evidence_authority_boundary_invalid"):
            FrozenEvidenceSource({**self.snapshot, "permit": "forbidden"})
        with self.assertRaisesRegex(ValueError, "evidence_authority_boundary_invalid"):
            FrozenEvidenceSource({**self.snapshot, "authority_effect": "grant"})
        with self.assertRaisesRegex(ValueError, "evidence_schema_invalid"):
            FrozenEvidenceSource({**self.snapshot, "schema": "unknown"})

    def test_app_requires_nonempty_access_token(self):
        with self.assertRaises(ValueError):
            create_app(self.source, auth_token="")


if __name__ == "__main__":
    unittest.main()

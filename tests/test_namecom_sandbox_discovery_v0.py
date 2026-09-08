import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prove_namecom_sandbox_discovery_v0.py"
SPEC = importlib.util.spec_from_file_location("pulpo_namecom_sandbox_discovery_v0", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NameComSandboxDiscoveryV0Tests(unittest.TestCase):
    def test_fire_guard_blocks_before_credentials_or_provider_calls(self):
        with patch.dict(os.environ, {"PULPO_NAMECOM_FIRE": "1"}, clear=True):
            with self.assertRaisesRegex(MODULE.DiscoveryViolation, "fire_must_remain_disabled"):
                MODULE.main()

    def test_sandbox_token_is_required(self):
        env = {
            "PULPO_NAMECOM_FIRE": "0",
            "NAMECOM_SANDBOX_USERNAME": "pulpo-test",
            "GITHUB_SHA": "f141f54401a6875860cc1295559f5796133baf10",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(
                MODULE.DiscoveryViolation,
                "namecom_sandbox_token_unavailable",
            ):
                MODULE.main()

    def test_authenticated_discovery_is_read_only_sanitized_and_does_not_claim_separation(self):
        env = {
            "PULPO_NAMECOM_FIRE": "0",
            "NAMECOM_SANDBOX_USERNAME": "pulpo-test",
            "NAMECOM_SANDBOX_TOKEN": "sandbox-secret-value",
            "GITHUB_SHA": "f141f54401a6875860cc1295559f5796133baf10",
        }
        calls = []

        def fake_request(method, path, *, username, token, payload=None):
            calls.append((method, path, username, token, payload))
            if method == "GET" and path == "/core/v1/hello":
                return {"username": username}
            if method == "POST" and path == "/core/v1/domains:checkAvailability":
                self.assertIsInstance(payload, dict)
                names = payload["domainNames"]
                self.assertEqual("registration", payload["purchaseType"])
                return {
                    "results": [
                        {
                            "domainName": names[0],
                            "purchasable": True,
                            "premium": False,
                            "purchasePrice": 12.34,
                            "renewalPrice": 19.99,
                            "purchaseType": "registration",
                        },
                        {
                            "domainName": names[1],
                            "purchasable": True,
                            "premium": True,
                            "purchasePrice": 1.00,
                            "renewalPrice": 1.00,
                            "purchaseType": "registration",
                        },
                    ]
                }
            raise AssertionError(f"unexpected provider call: {method} {path}")

        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "evidence.json"
            output = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(
                MODULE, "_request_json", side_effect=fake_request
            ), patch.object(MODULE, "ARTIFACT_PATH", artifact), contextlib.redirect_stdout(output):
                self.assertEqual(0, MODULE.main())

            evidence = json.loads(artifact.read_text(encoding="utf-8"))
            stdout = output.getvalue()

        self.assertEqual(
            [
                ("GET", "/core/v1/hello"),
                ("POST", "/core/v1/domains:checkAvailability"),
            ],
            [(method, path) for method, path, *_ in calls],
        )
        self.assertFalse(evidence["fire_authorized"])
        self.assertFalse(evidence["provider_write_attempted"])
        self.assertEqual("sandbox", evidence["environment"])
        self.assertEqual("name.com", evidence["provider"])
        self.assertEqual(1234, evidence["selected"]["purchase_price_cents"])
        self.assertEqual(1999, evidence["selected"]["renewal_price_cents"])
        self.assertFalse(evidence["selected"]["premium"])
        self.assertEqual("registration", evidence["selected"]["purchase_type"])
        self.assertEqual(64, len(evidence["evidence_hash"]))
        self.assertTrue(evidence["credentials"]["sandbox_authenticated"])
        self.assertEqual("single_sandbox_token", evidence["credentials"]["credential_mode"])
        self.assertFalse(evidence["credentials"]["executor_observer_distinct"])
        self.assertFalse(evidence["credentials"]["distinct_credential_separation_claimed"])
        self.assertFalse(evidence["credentials"]["secret_material_recorded"])

        serialized = json.dumps(evidence, sort_keys=True) + stdout
        self.assertNotIn("sandbox-secret-value", serialized)


if __name__ == "__main__":
    unittest.main()

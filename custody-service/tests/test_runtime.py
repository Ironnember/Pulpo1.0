import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pulpo_custody_service.runtime import (
    RuntimeConfig,
    RuntimeConfigError,
    build_service,
)


class CustodyRuntimeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state_path = Path(directory.name) / "custody.sqlite3"
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.env = {
            "PULPO_CUSTODY_STATE_PATH": str(self.state_path),
            "PULPO_KERNEL_SECRET_HEX": "11" * 32,
            "PULPO_CUSTODY_SECRET_HEX": "22" * 32,
            "PULPO_AUTHORITY_PUBLIC_KEY_HEX": public.hex(),
            "PULPO_AUTHORITY_ID": "authority:external-human-v0",
            "PULPO_AUTHORITY_VERIFIER_ID": "verifier:ed25519:custody-v0",
            "PULPO_AUTHORITY_KEY_ID": "key:external-human:v0",
            "PULPO_AUTHORITY_DEPLOYMENT_ID": "deployment:custody-sandbox-v0",
            "PULPO_AUTHORITY_MAX_TTL_SECONDS": "300",
            "PULPO_PILOT_BUDGET_CENTS": "3000",
            "PULPO_OWNER_REF": "owner://iron-ember/namecom-sandbox",
            "NAMECOM_SANDBOX_USERNAME": "pulpo-test",
            "NAMECOM_SANDBOX_EXECUTOR_TOKEN": "executor-sandbox-token",
            "NAMECOM_SANDBOX_OBSERVER_TOKEN": "observer-sandbox-token",
        }

    def test_build_is_hard_pinned_to_sandbox_and_external_approval(self):
        config = RuntimeConfig.from_environ(self.env)
        service = build_service(config)

        self.assertEqual(
            "https://api.dev.name.com",
            service.registrar.client.config.base_url,
        )
        self.assertEqual(
            "https://api.dev.name.com",
            service.observer.client.config.base_url,
        )
        self.assertFalse(service.registrar.client.config.allow_production)
        self.assertFalse(service.observer.client.config.allow_production)

        kernel = service._kernel_factory()
        try:
            self.assertEqual(frozenset({"purchase_domain"}), kernel.policy.approval_actions)
            self.assertIsNotNone(kernel.policy.authority_trust)
            self.assertEqual("ed25519", kernel.policy.authority_trust.algorithm)
            self.assertFalse(hasattr(kernel._approval_verifier, "sign"))
        finally:
            kernel._state.close()

    def test_unrelated_environment_variable_cannot_select_production(self):
        env = {**self.env, "NAMECOM_ENVIRONMENT": "production", "ALLOW_PRODUCTION": "1"}
        service = build_service(RuntimeConfig.from_environ(env))
        self.assertEqual("https://api.dev.name.com", service.registrar.client.config.base_url)
        self.assertEqual("https://api.dev.name.com", service.observer.client.config.base_url)

    def test_budget_ttl_username_token_and_state_path_constraints_fail_closed(self):
        cases = [
            ({"PULPO_PILOT_BUDGET_CENTS": "3001"}, "budget exceeds"),
            ({"PULPO_AUTHORITY_MAX_TTL_SECONDS": "3601"}, "TTL exceeds"),
            ({"NAMECOM_SANDBOX_USERNAME": "pulpo"}, "must end in -test"),
            (
                {
                    "NAMECOM_SANDBOX_OBSERVER_TOKEN": self.env[
                        "NAMECOM_SANDBOX_EXECUTOR_TOKEN"
                    ]
                },
                "tokens must be distinct",
            ),
            ({"PULPO_CUSTODY_STATE_PATH": "relative.sqlite3"}, "must be absolute"),
        ]
        for changes, message in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(RuntimeConfigError, message):
                    RuntimeConfig.from_environ({**self.env, **changes})

    def test_missing_or_short_custody_secrets_fail_before_service_start(self):
        for name in ("PULPO_KERNEL_SECRET_HEX", "PULPO_CUSTODY_SECRET_HEX"):
            with self.subTest(name=name):
                env = dict(self.env)
                env[name] = "aa" * 16
                with self.assertRaisesRegex(RuntimeConfigError, "at least 32 bytes"):
                    RuntimeConfig.from_environ(env)


if __name__ == "__main__":
    unittest.main()

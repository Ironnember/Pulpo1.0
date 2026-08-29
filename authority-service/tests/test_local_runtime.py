from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from pulpo_authority_service.local_runtime import (
    DigestBearerWorkerAuthenticator,
    build_runtime,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class LocalAuthorityRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.private_key_path = self.root / "authority-private-key.hex"
        self.private_key_path.write_text(private_bytes.hex() + "\n", encoding="ascii")
        self.private_key_path.chmod(0o600)
        self.key_fingerprint = sha256(public_bytes).hexdigest()

        self.credentials_path = self.root / "credentials.json"
        self.credentials_path.write_text(
            json.dumps(
                {
                    "schema": "pulpo.local-authority-credentials.v0",
                    "credentials": [
                        {
                            "credential_id": "credential:primary",
                            "public_key_hex": "00",
                            "sign_count": 0,
                            "role": "primary",
                            "active": True,
                            "hardware_attested": True,
                            "backup_eligible": False,
                        },
                        {
                            "credential_id": "credential:recovery",
                            "public_key_hex": "01",
                            "sign_count": 0,
                            "role": "recovery",
                            "active": True,
                            "hardware_attested": True,
                            "backup_eligible": False,
                        },
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        self.tls_cert_path = self.root / "authority.crt"
        self.tls_key_path = self.root / "authority-tls.key"
        self.tls_cert_path.write_text("test-certificate\n", encoding="ascii")
        self.tls_key_path.write_text("test-key\n", encoding="ascii")

        self.worker_token = "worker-token-acceptance-v0"
        self.environment = {
            "PULPO_AUTHORITY_ORIGIN": "https://authority.local:8443",
            "PULPO_AUTHORITY_RP_ID": "authority.local",
            "PULPO_AUTHORITY_PORT": "8443",
            "PULPO_AUTHORITY_ID": "authority:local-acceptance",
            "PULPO_AUTHORITY_VERIFIER_ID": "verifier:local-ed25519",
            "PULPO_AUTHORITY_KEY_ID": "key:local-authority-v0",
            "PULPO_AUTHORITY_EXPECTED_KEY_FINGERPRINT": self.key_fingerprint,
            "PULPO_AUTHORITY_DEPLOYMENT_ID": "deployment:local-acceptance-v0",
            "PULPO_AUTHORITY_MAX_TTL_SECONDS": "300",
            "PULPO_AUTHORITY_PRIVATE_KEY_PATH": str(self.private_key_path),
            "PULPO_AUTHORITY_CREDENTIALS_PATH": str(self.credentials_path),
            "PULPO_AUTHORITY_STATE_PATH": str(self.root / "state" / "authority.sqlite3"),
            "PULPO_AUTHORITY_EVIDENCE_DIR": str(self.root / "evidence"),
            "PULPO_AUTHORITY_WORKER_TOKEN_SHA256": sha256(self.worker_token.encode()).hexdigest(),
            "PULPO_AUTHORITY_TLS_CERT_PATH": str(self.tls_cert_path),
            "PULPO_AUTHORITY_TLS_KEY_PATH": str(self.tls_key_path),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def _request(self):
        intent = {
            "principal": "agent:hostile-worker",
            "action": "request",
            "resource": "domain:example.test",
            "cost": 0,
            "session_id": "session:local-boundary",
        }
        return {
            **intent,
            "intent_hash": sha256(_canonical(intent)).hexdigest(),
            "policy_hash": "a" * 64,
            "deployment_id": self.environment["PULPO_AUTHORITY_DEPLOYMENT_ID"],
            "requested_ttl_ns": 1_000_000_000,
            "schema": "pulpo.authority-request.v1",
        }

    def test_runtime_exposes_authenticated_worker_request_poll_only(self):
        runtime = build_runtime(self.environment)
        client = TestClient(runtime.app)

        self.assertEqual(
            {"status": "ok", "authority_effect": "none"},
            client.get("/health").json(),
        )
        self.assertEqual(401, client.post("/v1/approval-requests", json=self._request()).status_code)
        self.assertEqual(
            401,
            client.post(
                "/v1/approval-requests",
                json=self._request(),
                headers={"Authorization": "Bearer wrong-token"},
            ).status_code,
        )
        created = client.post(
            "/v1/approval-requests",
            json=self._request(),
            headers={"Authorization": f"Bearer {self.worker_token}"},
        )
        self.assertEqual(200, created.status_code)
        request_id = created.json()["request_id"]
        self.assertTrue(created.json()["approval_url"].startswith("https://authority.local:8443/human/approval/"))
        pending = client.get(
            f"/v1/approval-requests/{request_id}",
            headers={"Authorization": f"Bearer {self.worker_token}"},
        )
        self.assertEqual({"status": "pending"}, pending.json())

        paths = {route.path for route in client.app.routes}
        self.assertFalse(any(term in path for path in paths for term in ("sign", "enroll", "rotate", "recover", "revoke")))
        self.assertNotIn("/v1/approve", paths)

    def test_worker_authenticator_retains_only_digest_not_raw_token(self):
        digest = sha256(self.worker_token.encode()).hexdigest()
        authenticator = DigestBearerWorkerAuthenticator(digest)
        self.assertEqual({"expected_token_sha256": digest}, vars(authenticator))
        self.assertNotIn(self.worker_token, repr(vars(authenticator)))

    def test_inline_authority_secrets_are_rejected(self):
        for name, value in (
            ("PULPO_AUTHORITY_PRIVATE_KEY_HEX", "11" * 32),
            ("PULPO_AUTHORITY_WORKER_TOKEN", self.worker_token),
            ("PULPO_AUTHORITY_CREDENTIAL_JSON", "{}"),
        ):
            with self.subTest(name=name):
                environment = dict(self.environment)
                environment[name] = value
                with self.assertRaisesRegex(ValueError, "inline authority secrets are prohibited"):
                    build_runtime(environment)

    def test_signer_key_substitution_and_weak_permissions_fail_closed(self):
        environment = dict(self.environment)
        environment["PULPO_AUTHORITY_EXPECTED_KEY_FINGERPRINT"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "pinned public fingerprint"):
            build_runtime(environment)

        self.private_key_path.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "group/world writable"):
            build_runtime(self.environment)

    def test_runtime_requires_active_hardware_bound_primary_credential(self):
        value = json.loads(self.credentials_path.read_text(encoding="utf-8"))
        value["credentials"][0]["backup_eligible"] = True
        self.credentials_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "active hardware-bound primary"):
            build_runtime(self.environment)

    def test_origin_port_and_local_ttl_are_bounded(self):
        environment = dict(self.environment)
        environment["PULPO_AUTHORITY_ORIGIN"] = "https://authority.local:9443"
        with self.assertRaisesRegex(ValueError, "must be HTTPS on"):
            build_runtime(environment)

        environment = dict(self.environment)
        environment["PULPO_AUTHORITY_MAX_TTL_SECONDS"] = "3601"
        with self.assertRaisesRegex(ValueError, "outside the allowed range"):
            build_runtime(environment)


if __name__ == "__main__":
    unittest.main()

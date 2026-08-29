from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pulpo_authority_service.hardware_enrollment_runtime import validate_runtime_environment


class HardwareEnrollmentRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cert = self.root / "tls.crt"
        self.key = self.root / "tls.key"
        self.cert.write_text("cert\n")
        self.key.write_text("key\n")
        self.environment = {
            "PULPO_ENROLLMENT_ORIGIN": "https://authority.pulpo.ai:8443",
            "PULPO_ENROLLMENT_RP_ID": "authority.pulpo.ai",
            "PULPO_ENROLLMENT_CANDIDATE_PATH": str(self.root / "candidate.json"),
            "PULPO_ENROLLMENT_TTL_SECONDS": "300",
            "PULPO_ENROLLMENT_ROLE": "primary",
            "PULPO_ENROLLMENT_BOOTSTRAP_TOKEN_SHA256": "a" * 64,
            "PULPO_ENROLLMENT_TLS_CERT_PATH": str(self.cert),
            "PULPO_ENROLLMENT_TLS_KEY_PATH": str(self.key),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_runtime_is_loopback_only(self):
        host, port, cert, key = validate_runtime_environment(self.environment)
        self.assertEqual("127.0.0.1", host)
        self.assertEqual(8443, port)
        self.assertEqual(self.cert, cert)
        self.assertEqual(self.key, key)

        for host in ("0.0.0.0", "192.0.2.1", "authority.pulpo.ai"):
            environment = dict(self.environment)
            environment["PULPO_ENROLLMENT_BIND_HOST"] = host
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "loopback"):
                validate_runtime_environment(environment)

    def test_runtime_refuses_signer_custody_and_provider_secrets(self):
        forbidden = {
            "PULPO_ENROLLMENT_BOOTSTRAP_TOKEN": "raw-token",
            "PULPO_AUTHORITY_PRIVATE_KEY_PATH": "/secret/authority.key",
            "PULPO_AUTHORITY_PRIVATE_KEY_HEX": "11" * 32,
            "PULPO_KERNEL_SECRET_HEX": "22" * 32,
            "PULPO_CUSTODY_SECRET_HEX": "33" * 32,
            "NAMECOM_SANDBOX_EXECUTOR_TOKEN": "executor-secret",
            "NAMECOM_SANDBOX_OBSERVER_TOKEN": "observer-secret",
        }
        for name, value in forbidden.items():
            environment = dict(self.environment)
            environment[name] = value
            with self.subTest(name=name), self.assertRaisesRegex(
                RuntimeError,
                "refuses authority/execution secret material",
            ):
                validate_runtime_environment(environment)

    def test_tls_files_must_exist_and_origin_must_be_https(self):
        environment = dict(self.environment)
        environment["PULPO_ENROLLMENT_TLS_CERT_PATH"] = str(self.root / "missing.crt")
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            validate_runtime_environment(environment)

        environment = dict(self.environment)
        environment["PULPO_ENROLLMENT_ORIGIN"] = "http://authority.pulpo.ai:8443"
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            validate_runtime_environment(environment)


if __name__ == "__main__":
    unittest.main()

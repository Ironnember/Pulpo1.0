from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from webauthn.helpers.structs import (
    AttestationFormat,
    AuthenticatorAttachment,
    CredentialDeviceType,
)

from pulpo_authority_service.hardware_enrollment import (
    DigestBootstrapAuthenticator,
    EnrollmentConfig,
    HardwareEnrollmentService,
    create_enrollment_app,
)


NOW = 1_000_000_000_000


class FakeVerifier:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


def verified_registration(**changes):
    value = {
        "credential_id": b"credential-id-v0",
        "credential_public_key": b"public-cose-key-v0",
        "sign_count": 1,
        "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
        "fmt": AttestationFormat.PACKED,
        "user_verified": True,
        "attestation_object": b"verified-attestation-object",
        "credential_device_type": CredentialDeviceType.SINGLE_DEVICE,
        "credential_backed_up": False,
    }
    value.update(changes)
    return SimpleNamespace(**value)


class HardwareEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.json"
        self.clock = [NOW]
        self.random_values = iter((b"c" * 32, b"u" * 32))
        self.verifier = FakeVerifier(verified_registration())
        self.service = HardwareEnrollmentService(
            EnrollmentConfig(
                "authority.pulpo.ai",
                "https://authority.pulpo.ai",
                self.candidate,
                session_ttl_seconds=300,
                role="primary",
            ),
            registration_verifier=self.verifier,
            clock=lambda: self.clock[0],
            random_bytes=lambda _: next(self.random_values),
            random_token=lambda _: "session-token",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _begin(self):
        value = self.service.begin()
        self.assertEqual("none", value["authority_effect"])
        return value

    def _credential(self):
        return {
            "id": "credential-id-v0",
            "rawId": "credential-id-v0",
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": "AA",
                "attestationObject": "AA",
                "transports": ["usb"],
            },
        }

    def test_options_require_cross_platform_resident_verified_security_key(self):
        value = self._begin()
        public_key = value["public_key"]
        selection = public_key["authenticatorSelection"]
        self.assertEqual("authority.pulpo.ai", public_key["rp"]["id"])
        self.assertEqual("cross-platform", selection["authenticatorAttachment"])
        self.assertEqual("required", selection["residentKey"])
        self.assertTrue(selection["requireResidentKey"])
        self.assertEqual("required", selection["userVerification"])
        self.assertEqual("direct", public_key["attestation"])
        self.assertEqual(["security-key"], public_key["hints"])
        self.assertEqual(300_000, public_key["timeout"])

    def test_success_creates_public_candidate_but_no_active_authority_state(self):
        options = self._begin()
        parsed = SimpleNamespace(authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM)
        with patch(
            "pulpo_authority_service.hardware_enrollment.parse_registration_credential_json",
            return_value=parsed,
        ):
            result = self.service.complete(options["session_id"], self._credential())

        self.assertEqual("candidate_created", result["status"])
        self.assertEqual("none_until_explicit_admission", result["authority_effect"])
        self.assertTrue(self.candidate.is_file())
        self.assertEqual(0o600, stat.S_IMODE(self.candidate.stat().st_mode))
        candidate = json.loads(self.candidate.read_text())
        self.assertEqual("pulpo.webauthn-credential-candidate.v0", candidate["schema"])
        self.assertEqual("local_acceptance_candidate_only", candidate["admission_class"])
        self.assertEqual("none_until_explicit_admission", candidate["authority_effect"])
        self.assertEqual("primary", candidate["runtime_record"]["role"])
        self.assertTrue(candidate["runtime_record"]["hardware_attested"])
        self.assertFalse(candidate["runtime_record"]["backup_eligible"])
        self.assertNotIn("private", self.candidate.read_text().lower())
        self.assertFalse((self.root / "authority.sqlite3").exists())
        self.assertEqual(1, len(self.verifier.calls))
        call = self.verifier.calls[0]
        self.assertEqual(b"c" * 32, call["expected_challenge"])
        self.assertEqual("authority.pulpo.ai", call["expected_rp_id"])
        self.assertEqual("https://authority.pulpo.ai", call["expected_origin"])
        self.assertTrue(call["require_user_presence"])
        self.assertTrue(call["require_user_verification"])

    def test_synced_passkey_backup_and_none_attestation_fail_closed(self):
        cases = (
            (
                verified_registration(credential_device_type=CredentialDeviceType.MULTI_DEVICE),
                "multi-device",
            ),
            (verified_registration(credential_backed_up=True), "backed-up"),
            (verified_registration(fmt=AttestationFormat.NONE), "attestation"),
            (verified_registration(user_verified=False), "verification"),
        )
        for verified, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory) / "candidate.json"
                random_values = iter((b"c" * 32, b"u" * 32))
                verifier = FakeVerifier(verified)
                service = HardwareEnrollmentService(
                    EnrollmentConfig(
                        "authority.pulpo.ai",
                        "https://authority.pulpo.ai",
                        candidate,
                    ),
                    registration_verifier=verifier,
                    clock=lambda: NOW,
                    random_bytes=lambda _: next(random_values),
                    random_token=lambda _: "case",
                )
                options = service.begin()
                parsed = SimpleNamespace(
                    authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
                )
                with patch(
                    "pulpo_authority_service.hardware_enrollment.parse_registration_credential_json",
                    return_value=parsed,
                ), self.assertRaisesRegex(PermissionError, message):
                    service.complete(options["session_id"], self._credential())
                self.assertFalse(candidate.exists())

    def test_platform_authenticator_is_rejected_before_verification(self):
        options = self._begin()
        credential = self._credential()
        credential["authenticatorAttachment"] = "platform"
        with self.assertRaisesRegex(PermissionError, "cross-platform"):
            self.service.complete(options["session_id"], credential)
        self.assertEqual([], self.verifier.calls)
        self.assertFalse(self.candidate.exists())

    def test_expired_session_and_replay_cannot_create_candidate(self):
        options = self._begin()
        self.clock[0] = NOW + 300 * 1_000_000_000
        with self.assertRaisesRegex(PermissionError, "expired"):
            self.service.complete(options["session_id"], self._credential())
        self.assertFalse(self.candidate.exists())
        with self.assertRaisesRegex(PermissionError, "unknown"):
            self.service.complete(options["session_id"], self._credential())

    def test_existing_candidate_is_never_overwritten(self):
        self.candidate.write_text("existing\n")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.service.begin()
        self.assertEqual("existing\n", self.candidate.read_text())

    def test_candidate_hash_binds_public_material(self):
        options = self._begin()
        parsed = SimpleNamespace(authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM)
        with patch(
            "pulpo_authority_service.hardware_enrollment.parse_registration_credential_json",
            return_value=parsed,
        ):
            result = self.service.complete(options["session_id"], self._credential())
        payload = json.loads(self.candidate.read_text())
        stored_hash = payload.pop("candidate_hash")
        payload.pop("runtime_record")
        expected = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(expected, stored_hash)
        self.assertEqual(stored_hash, result["candidate_hash"])


class HardwareEnrollmentApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        random_values = iter((b"c" * 32, b"u" * 32))
        self.service = HardwareEnrollmentService(
            EnrollmentConfig(
                "authority.pulpo.ai",
                "https://authority.pulpo.ai",
                root / "candidate.json",
            ),
            registration_verifier=FakeVerifier(verified_registration()),
            clock=lambda: NOW,
            random_bytes=lambda _: next(random_values),
            random_token=lambda _: "api",
        )
        self.token = "bootstrap-token-v0"
        authenticator = DigestBootstrapAuthenticator(sha256(self.token.encode()).hexdigest())
        self.client = TestClient(create_enrollment_app(self.service, authenticator))

    def tearDown(self):
        self.temporary.cleanup()

    def test_bootstrap_token_is_candidate_access_not_authority(self):
        self.assertEqual(
            {"status": "ok", "authority_effect": "none"},
            self.client.get("/health").json(),
        )
        self.assertEqual(401, self.client.post("/v1/enrollment/options", json={}).status_code)
        self.assertEqual(
            401,
            self.client.post(
                "/v1/enrollment/options",
                json={},
                headers={"Authorization": "Bearer wrong"},
            ).status_code,
        )
        created = self.client.post(
            "/v1/enrollment/options",
            json={},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(200, created.status_code)
        self.assertEqual("none", created.json()["authority_effect"])

        paths = {route.path for route in self.client.app.routes}
        for forbidden in ("approve", "sign", "permit", "execute", "policy", "revoke", "rotate"):
            self.assertFalse(any(forbidden in path for path in paths), (forbidden, paths))

    def test_bootstrap_page_keeps_token_in_fragment_memory_only(self):
        page = self.client.get("/bootstrap")
        script = self.client.get("/bootstrap.js")
        self.assertEqual(200, page.status_code)
        self.assertEqual("no-store", page.headers["cache-control"])
        self.assertIn("candidate only", page.text)
        self.assertNotIn(self.token, page.text)
        self.assertIn("navigator.credentials.create", script.text)
        self.assertIn("location.hash", script.text)
        self.assertIn("history.replaceState", script.text)
        self.assertIn("Authorization", script.text)
        self.assertNotIn(self.token, script.text)


if __name__ == "__main__":
    unittest.main()

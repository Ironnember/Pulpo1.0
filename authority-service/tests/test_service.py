from __future__ import annotations

from dataclasses import asdict, replace
from hashlib import sha256
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pulpo import (
    ApprovalEnvelope as PulpoApprovalEnvelope,
    AuthorityTrust as PulpoAuthorityTrust,
    Ed25519ApprovalVerifier,
    GovernanceKernel,
    Intent,
    Policy,
)
from pulpo_authority_service import (
    ApprovalRequest,
    AuthorityConfig,
    AuthorityService,
    AuthorityTrust as ServiceAuthorityTrust,
    CeremonyResult,
    CredentialRecord,
    InMemoryEvidenceSink,
    InMemoryState,
)


NOW = 1_000_000


class FakeWebAuthnVerifier:
    def __init__(self, result=None):
        self.calls = []
        self.result = result

    def verify(self, assertion, **expected):
        self.calls.append((assertion, expected))
        return self.result or CeremonyResult(
            credential_id=expected["credential"].credential_id,
            user_present=True,
            user_verified=True,
            backup_eligible=False,
            backed_up=False,
            new_sign_count=expected["credential"].sign_count + 1,
        )


class Ed25519TestSigner:
    algorithm = "ed25519"

    def __init__(self, private_key, verifier):
        self.private_key = private_key
        self.authority_id = verifier.authority_id
        self.verifier_id = verifier.verifier_id
        self.key_id = verifier.key_id
        self.key_fingerprint = verifier.key_fingerprint

    def sign(self, payload):
        return self.private_key.sign(payload).hex()


class FailingEvidenceSink:
    def append(self, bundle):
        raise RuntimeError("append unavailable")


class AuthorityServiceTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization

        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.approval_verifier = Ed25519ApprovalVerifier(
            authority_id="authority:founder",
            verifier_id="verifier:ed25519:production",
            key_id="key:authority-service:v1",
            public_key=public,
        )
        self.trust = PulpoAuthorityTrust(
            authority_id=self.approval_verifier.authority_id,
            verifier_id=self.approval_verifier.verifier_id,
            key_id=self.approval_verifier.key_id,
            algorithm=self.approval_verifier.algorithm,
            key_fingerprint=self.approval_verifier.key_fingerprint,
            deployment_id="deployment:production",
            max_approval_ttl_ns=10_000,
        )
        self.policy = Policy(
            frozenset({"push"}),
            100,
            frozenset({"push"}),
            authority_trust=self.trust,
        )
        self.kernel = GovernanceKernel(
            self.policy,
            approval_verifier=self.approval_verifier,
            clock=lambda: NOW,
        )
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, "session:1")
        self.primary = CredentialRecord("credential:primary", b"public-cose-key", 4, "primary", True, True, False)
        self.recovery = CredentialRecord("credential:recovery", b"recovery-cose-key", 0, "recovery", True, True, False)
        self.state = InMemoryState((self.primary, self.recovery))
        self.evidence = InMemoryEvidenceSink()
        self.webauthn = FakeWebAuthnVerifier()
        self.service_trust = ServiceAuthorityTrust(**asdict(self.trust))
        tokens = iter(("request-token", "approval-token", "nonce-token"))
        self.service = AuthorityService(
            AuthorityConfig(self.service_trust, "example.com", "https://authority.example.com"),
            self.state,
            self.webauthn,
            Ed25519TestSigner(self.private_key, self.approval_verifier),
            self.evidence,
            clock=lambda: NOW,
            random_token=lambda _: next(tokens),
        )
        self.request = ApprovalRequest(
            principal=self.intent.principal,
            action=self.intent.action,
            resource=self.intent.resource,
            cost=self.intent.cost,
            session_id=self.intent.session_id,
            intent_hash=self.kernel.intent_hash(self.intent),
            policy_hash=self.kernel.policy_hash,
            deployment_id=self.trust.deployment_id,
            requested_ttl_ns=1_000,
        )

    def test_one_exact_verified_ceremony_produces_one_kernel_usable_envelope(self):
        request_id, url = self.service.request_approval(self.request)
        displayed = self.service.display(request_id)
        challenge = self.service.challenge(request_id)
        envelope = self.service.approve(request_id, self.primary.credential_id, "raw-assertion-json")

        self.assertEqual("https://authority.example.com/human/approval/request:request-token", url)
        self.assertEqual(self.intent.resource, displayed["resource"])
        self.assertEqual(challenge, self.webauthn.calls[0][1]["expected_challenge"])
        self.assertEqual("https://authority.example.com", self.webauthn.calls[0][1]["expected_origin"])
        self.assertEqual("example.com", self.webauthn.calls[0][1]["expected_rp_id"])
        self.assertEqual(1, self.state.sequence)
        self.assertEqual(1, len(self.evidence.bundles))
        self.assertEqual("approved", self.service.poll(request_id)["status"])
        decision = self.kernel.evaluate_with_approval(
            self.intent,
            PulpoApprovalEnvelope(**asdict(envelope)),
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        with self.assertRaisesRegex(RuntimeError, "not pending"):
            self.service.approve(request_id, self.primary.credential_id, "second-assertion")

    def test_challenge_binds_request_payload_expiry_and_service_nonce(self):
        request_id, _ = self.service.request_approval(self.request)
        record = self.state.requests[request_id]
        expected = sha256(
            json.dumps(
                {
                    "schema": "pulpo.webauthn-challenge.v1",
                    "purpose": "approve-exact-pulpo-envelope",
                    "request_id": request_id,
                    "signing_payload_hash": record.unsigned_envelope.signing_payload_hash,
                    "expires_at_ns": record.unsigned_envelope.expires_at_ns,
                    "service_nonce": record.unsigned_envelope.nonce,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).digest()
        self.assertEqual(expected, record.challenge)

    def test_worker_cannot_lie_about_displayed_intent_or_deployment(self):
        with self.assertRaisesRegex(ValueError, "intent hash"):
            self.service.request_approval(replace(self.request, resource="repo:attacker"))
        with self.assertRaisesRegex(ValueError, "deployment"):
            self.service.request_approval(replace(self.request, deployment_id="deployment:attacker"))
        with self.assertRaisesRegex(ValueError, "TTL"):
            self.service.request_approval(replace(self.request, requested_ttl_ns=10_001))

    def test_recovery_and_backup_eligible_credentials_cannot_approve(self):
        request_id, _ = self.service.request_approval(self.request)
        with self.assertRaisesRegex(PermissionError, "recovery"):
            self.service.approve(request_id, self.recovery.credential_id, "assertion")

        self.state.credentials[self.primary.credential_id] = replace(self.primary, backup_eligible=True)
        with self.assertRaisesRegex(PermissionError, "hardware policy"):
            self.service.approve(request_id, self.primary.credential_id, "assertion")

    def test_missing_uv_backup_state_and_counter_rollback_fail_closed(self):
        request_id, _ = self.service.request_approval(self.request)
        cases = (
            (CeremonyResult(self.primary.credential_id, True, False, False, False, 5), "verification"),
            (CeremonyResult(self.primary.credential_id, True, True, True, True, 5), "backup"),
            (CeremonyResult(self.primary.credential_id, True, True, False, False, 3), "rollback"),
        )
        for result, message in cases:
            with self.subTest(message=message):
                self.service.verifier = FakeWebAuthnVerifier(result)
                with self.assertRaisesRegex(PermissionError, message):
                    self.service.approve(request_id, self.primary.credential_id, "assertion")
                self.assertEqual("pending", self.service.poll(request_id)["status"])

    def test_evidence_failure_releases_no_envelope_and_recovers_without_second_assertion(self):
        request_id, _ = self.service.request_approval(self.request)
        self.service.evidence = FailingEvidenceSink()
        with self.assertRaisesRegex(RuntimeError, "authority evidence unavailable"):
            self.service.approve(request_id, self.primary.credential_id, "first-assertion")

        record = self.state.requests[request_id]
        self.assertEqual("evidence_pending", record.status)
        self.assertEqual(1, self.state.sequence)
        self.assertIsNotNone(record.envelope)
        self.assertIsNotNone(record.evidence_bundle)
        self.assertIsNone(record.evidence_hash)
        self.assertEqual(1, len(self.webauthn.calls))

        self.service.evidence = self.evidence
        approved = self.service.poll(request_id)
        self.assertEqual("approved", approved["status"])
        self.assertIn("envelope", approved)
        self.assertEqual(1, self.state.sequence)
        self.assertEqual(1, len(self.evidence.bundles))
        self.assertEqual(1, len(self.webauthn.calls))
        self.assertIsNone(self.state.requests[request_id].evidence_bundle)

    def test_origin_and_rp_must_be_exact_https_boundary(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            AuthorityConfig(self.service_trust, "example.com", "http://authority.example.com")
        with self.assertRaisesRegex(ValueError, "rp_id"):
            AuthorityConfig(self.service_trust, "example.com", "https://attacker.test")
        for invalid in (
            "https://user@authority.example.com",
            "https://authority.example.com?query=value",
            "https://authority.example.com#fragment",
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "HTTPS"):
                AuthorityConfig(self.service_trust, "example.com", invalid)

    def test_service_rejects_a_signer_outside_pinned_trust(self):
        signer = Ed25519TestSigner(self.private_key, self.approval_verifier)
        signer.key_id = "key:attacker"
        with self.assertRaisesRegex(ValueError, "pinned authority trust"):
            AuthorityService(
                AuthorityConfig(self.service_trust, "example.com", "https://authority.example.com"),
                self.state,
                self.webauthn,
                signer,
                self.evidence,
            )

    def test_service_owned_time_rollback_fails_closed(self):
        clock = [NOW]
        tokens = iter(("request-clock", "approval-clock", "nonce-clock"))
        service = AuthorityService(
            AuthorityConfig(self.service_trust, "example.com", "https://authority.example.com"),
            InMemoryState((self.primary, self.recovery)),
            self.webauthn,
            Ed25519TestSigner(self.private_key, self.approval_verifier),
            self.evidence,
            clock=lambda: clock[0],
            random_token=lambda _: next(tokens),
        )
        request_id, _ = service.request_approval(self.request)
        clock[0] = NOW - 1
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            service.poll(request_id)
        self.assertEqual("pending", service.state.requests[request_id].status)


if __name__ == "__main__":
    unittest.main()

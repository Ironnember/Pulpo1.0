"""Optional asymmetric verifier proof; private keys exist only as test fixtures."""

from __future__ import annotations

from dataclasses import replace
import importlib.util
import unittest

from pulpo import (
    ApprovalEnvelope,
    AuthorityTrust,
    AuthorityTrustError,
    Ed25519ApprovalVerifier,
    GovernanceKernel,
    Intent,
    Policy,
)


CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None
NOW = 1_000_000


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "install pulpo[authority]")
class Ed25519AuthorityTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private_key = Ed25519PrivateKey.generate()
        public_key = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.verifier = Ed25519ApprovalVerifier(
            authority_id="authority:test-human",
            verifier_id="verifier:ed25519:test",
            key_id="key:test-human:v1",
            public_key=public_key,
        )
        self.trust = AuthorityTrust(
            authority_id=self.verifier.authority_id,
            verifier_id=self.verifier.verifier_id,
            key_id=self.verifier.key_id,
            algorithm=self.verifier.algorithm,
            key_fingerprint=self.verifier.key_fingerprint,
            deployment_id="deployment:test-ed25519",
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
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, "session:1")

    def envelope(self):
        unsigned = ApprovalEnvelope(
            approval_id="approval:ed25519:1",
            authority_id=self.trust.authority_id,
            verifier_id=self.trust.verifier_id,
            key_id=self.trust.key_id,
            deployment_id=self.trust.deployment_id,
            trust_hash=self.trust.trust_hash,
            session_id=self.intent.session_id,
            principal=self.intent.principal,
            intent_hash=self.kernel.intent_hash(self.intent),
            policy_hash=self.kernel.policy_hash,
            nonce="nonce:ed25519:1",
            issued_at_ns=NOW,
            expires_at_ns=NOW + 1_000,
            signature="",
        )
        return replace(unsigned, signature=self._private_key.sign(unsigned.signing_bytes()).hex())

    def test_pinned_ed25519_public_key_verifies_exact_envelope_once(self):
        envelope = self.envelope()
        decision = self.kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.kernel.consume(decision.permit, self.intent))
        self.assertFalse(self.kernel.consume(decision.permit, self.intent))
        self.assertFalse(hasattr(self.verifier, "sign"))

    def test_signature_and_payload_substitution_fail_closed(self):
        envelope = self.envelope()
        invalid = replace(envelope, signature="00" * 64)
        self.assertEqual(
            "approval_signature_invalid",
            self.kernel.evaluate_with_approval(self.intent, invalid).reason,
        )
        substituted = replace(self.intent, resource="repo:attacker")
        self.assertEqual(
            "approval_intent_mismatch",
            self.kernel.evaluate_with_approval(substituted, envelope).reason,
        )

    def test_same_authority_with_substituted_public_key_fails_bootstrap(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        attacker_public_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        attacker = Ed25519ApprovalVerifier(
            authority_id=self.trust.authority_id,
            verifier_id=self.trust.verifier_id,
            key_id=self.trust.key_id,
            public_key=attacker_public_key,
        )
        with self.assertRaises(AuthorityTrustError):
            GovernanceKernel(
                self.policy,
                approval_verifier=attacker,
                clock=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest
from dataclasses import replace

from pulpo import (
    CeremonyProof,
    CeremonyTrust,
    CeremonyTrustError,
    CeremonyVerification,
    GovernanceKernel,
    Intent,
    Policy,
    expected_ceremony_challenge,
)
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
CREDENTIAL_ID = "credential:primary"
CREDENTIAL_SET_HASH = hashlib.sha256(CREDENTIAL_ID.encode()).hexdigest()


class FakeIndependentCeremonyVerifier:
    verifier_id = "ceremony-verifier:test-v0"
    rp_id = "example.com"
    origin = "https://authority.example.com"
    credential_set_hash = CREDENTIAL_SET_HASH

    def __init__(self, *, credential_id=CREDENTIAL_ID):
        self.credential_id = credential_id
        self.calls = []

    def verify(self, proof, *, expected_challenge):
        self.calls.append((proof, expected_challenge))
        if proof.assertion != expected_challenge.hex():
            raise ValueError("challenge mismatch")
        return CeremonyVerification(
            credential_id=self.credential_id,
            user_present=True,
            user_verified=True,
            backup_eligible=False,
            backed_up=False,
            new_sign_count=5,
        )


class IndependentCeremonyApprovalTests(unittest.TestCase):
    def setUp(self):
        self.approval_verifier = HmacTestVerifier()
        self.ceremony_trust = CeremonyTrust(
            verifier_id=FakeIndependentCeremonyVerifier.verifier_id,
            rp_id=FakeIndependentCeremonyVerifier.rp_id,
            origin=FakeIndependentCeremonyVerifier.origin,
            credential_set_hash=CREDENTIAL_SET_HASH,
        )
        self.policy = Policy(
            frozenset({"push"}),
            0,
            frozenset({"push"}),
            authority_trust=trust_for(self.approval_verifier),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=self.ceremony_trust,
        )
        self.ceremony_verifier = FakeIndependentCeremonyVerifier()
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"independent-ceremony-proof",
            approval_verifier=self.approval_verifier,
            ceremony_verifier=self.ceremony_verifier,
            clock=lambda: NOW,
        )
        self.intent = Intent(
            "agent:publisher",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/main",
            0,
            "ceremony-proof-session",
        )

    def envelope(self, **changes):
        return signed_envelope(
            self.kernel,
            self.intent,
            self.approval_verifier,
            now_ns=NOW,
            **changes,
        )

    def proof_for(self, envelope, *, request_id="request:1", credential_id=CREDENTIAL_ID):
        return CeremonyProof(
            request_id=request_id,
            credential_id=credential_id,
            assertion=expected_ceremony_challenge(envelope, request_id).hex(),
        )

    def test_valid_signature_without_ceremony_proof_is_denied(self):
        decision = self.kernel.evaluate_with_approval(self.intent, self.envelope())
        self.assertEqual(
            ("deny", "approval_ceremony_proof_missing"),
            (decision.outcome, decision.reason),
        )

    def test_valid_ceremony_proof_without_valid_signature_is_denied(self):
        envelope = self.envelope()
        proof = self.proof_for(envelope)
        invalid = replace(envelope, signature="invalid")

        decision = self.kernel.evaluate_with_approval(self.intent, invalid, proof)

        self.assertEqual(
            ("deny", "approval_signature_invalid"),
            (decision.outcome, decision.reason),
        )
        self.assertEqual([], self.ceremony_verifier.calls)

    def test_proof_for_one_exact_envelope_cannot_authorize_another(self):
        first = self.envelope()
        proof = self.proof_for(first)
        second = self.envelope(approval_id="approval-2", nonce="nonce-2")

        decision = self.kernel.evaluate_with_approval(self.intent, second, proof)

        self.assertEqual(
            ("deny", "approval_ceremony_verification_failed"),
            (decision.outcome, decision.reason),
        )

    def test_valid_signature_and_valid_independent_proof_allow_one_permit(self):
        envelope = self.envelope()
        proof = self.proof_for(envelope)

        decision = self.kernel.evaluate_with_approval(self.intent, envelope, proof)

        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        verified = next(
            record["payload"]
            for record in self.kernel.audit
            if record["event"] == "approval_verified"
        )
        self.assertEqual(self.ceremony_trust.trust_hash, verified["ceremony_trust_hash"])
        self.assertEqual(proof.proof_hash, verified["ceremony_proof_hash"])
        self.assertNotIn("assertion", verified)

    def test_ceremony_credential_mismatch_fails_closed(self):
        envelope = self.envelope()
        proof = self.proof_for(envelope, credential_id="credential:other")

        decision = self.kernel.evaluate_with_approval(self.intent, envelope, proof)

        self.assertEqual(
            ("deny", "approval_ceremony_credential_mismatch"),
            (decision.outcome, decision.reason),
        )

    def test_untrusted_ceremony_verifier_is_rejected_at_bootstrap(self):
        verifier = FakeIndependentCeremonyVerifier()
        verifier.credential_set_hash = "f" * 64
        with self.assertRaises(CeremonyTrustError):
            GovernanceKernel(
                self.policy,
                approval_verifier=self.approval_verifier,
                ceremony_verifier=verifier,
                clock=lambda: NOW,
            )

    def test_ceremony_requirement_is_explicit_policy_and_legacy_path_stays_legacy(self):
        legacy_policy = Policy(
            frozenset({"push"}),
            0,
            frozenset({"push"}),
            authority_trust=trust_for(self.approval_verifier),
        )
        legacy_kernel = GovernanceKernel(
            legacy_policy,
            approval_verifier=self.approval_verifier,
            clock=lambda: NOW,
        )
        legacy_intent = replace(self.intent, session_id="legacy-session")
        envelope = signed_envelope(
            legacy_kernel,
            legacy_intent,
            self.approval_verifier,
            now_ns=NOW,
        )

        self.assertEqual(
            "allow",
            legacy_kernel.evaluate_with_approval(legacy_intent, envelope).outcome,
        )

    def test_ceremony_actions_cannot_exist_outside_approval_actions(self):
        with self.assertRaisesRegex(ValueError, "subset"):
            Policy(
                frozenset({"push"}),
                0,
                frozenset(),
                ceremony_actions=frozenset({"push"}),
                ceremony_trust=self.ceremony_trust,
            )


if __name__ == "__main__":
    unittest.main()

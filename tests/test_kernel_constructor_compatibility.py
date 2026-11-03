"""Synthetic constructor ABI regression for the held ceremony candidate."""
import unittest

from pulpo import (
    CeremonyProof,
    CeremonyTrust,
    CeremonyTrustError,
    GovernanceKernel,
    InMemoryKernelState,
    Intent,
    Policy,
    expected_ceremony_challenge,
)
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_independent_ceremony_approval import FakeIndependentCeremonyVerifier


NOW = 1_000_000


class KernelConstructorCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.signer = HmacTestVerifier()
        self.intent = Intent("agent:test", "push", "resource:test", 0, "session:test")
        self.clock = lambda: NOW
        self.state = InMemoryKernelState()

    def legacy_policy(self):
        return Policy(
            frozenset({"push"}), 0, frozenset({"push"}),
            authority_trust=trust_for(self.signer),
        )

    def ceremony_policy(self):
        verifier = FakeIndependentCeremonyVerifier()
        return (
            Policy(
                frozenset({"push"}), 0, frozenset({"push"}),
                authority_trust=trust_for(self.signer),
                ceremony_actions=frozenset({"push"}),
                ceremony_trust=CeremonyTrust(
                    verifier.verifier_id, verifier.rp_id,
                    verifier.origin, verifier.credential_set_hash,
                ),
            ),
            verifier,
        )

    def test_existing_five_arg_positional_abi_and_legacy_approval(self):
        kernel = GovernanceKernel(
            self.legacy_policy(), b"test-secret", self.signer,
            self.clock, self.state,
        )
        self.assertIs(kernel._clock, self.clock)
        self.assertIs(kernel._state, self.state)
        self.assertIs(kernel._approval_verifier, self.signer)
        self.assertIsNone(kernel._ceremony_verifier)
        self.assertIsNone(kernel._ceremony_evidence_reader)
        envelope = signed_envelope(kernel, self.intent, self.signer, now_ns=NOW)
        self.assertEqual(
            "allow", kernel.evaluate_with_approval(self.intent, envelope).outcome
        )

    def test_ceremony_policy_positional_without_verifier_denies(self):
        policy, verifier = self.ceremony_policy()
        kernel = GovernanceKernel(
            policy, b"test-secret", self.signer, self.clock, self.state
        )
        envelope = signed_envelope(kernel, self.intent, self.signer, now_ns=NOW)
        request_id = "request:missing-verifier"
        proof = CeremonyProof(
            request_id, "credential:primary",
            expected_ceremony_challenge(envelope, request_id).hex(),
        )
        decision = kernel.evaluate_with_approval(self.intent, envelope, proof)
        self.assertEqual(
            ("deny", "approval_ceremony_verifier_unavailable"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(any(row["event"] == "approval_verified" for row in kernel.audit))

    def test_keyword_ceremony_verifier_preserves_pinning_and_clock(self):
        policy, verifier = self.ceremony_policy()
        kernel = GovernanceKernel(
            policy, b"test-secret", self.signer,
            clock=self.clock, state=self.state, ceremony_verifier=verifier,
        )
        self.assertIs(kernel._clock, self.clock)
        self.assertIs(kernel._state, self.state)
        self.assertIs(kernel._ceremony_verifier, verifier)
        wrong_verifier = FakeIndependentCeremonyVerifier()
        wrong_verifier.verifier_id = "untrusted:verifier"
        with self.assertRaises(CeremonyTrustError):
            GovernanceKernel(
                policy, b"test-secret", self.signer,
                clock=self.clock, state=InMemoryKernelState(),
                ceremony_verifier=wrong_verifier,
            )


if __name__ == "__main__":
    unittest.main()

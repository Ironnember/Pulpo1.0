import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.targets import evaluate_locked_target_with_approval
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


class TargetAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000_000_000_000
        self.verifier = HmacTestVerifier()
        self.kernel = GovernanceKernel(
            Policy(
                frozenset({"push"}),
                100,
                approval_actions=frozenset({"push"}),
                authority_trust=trust_for(self.verifier),
            ),
            secret=b"target-authority-secret",
            approval_verifier=self.verifier,
            clock=lambda: self.now,
        )
        self.intent = Intent(
            "agent:builder",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/main",
            0,
            "voice-session",
        )
        self.target = self.kernel.lock_target("T-AUTH-001", self.intent)

    def test_exact_locked_target_can_use_existing_approval_path(self):
        envelope = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=self.now,
        )

        resolution, decision = evaluate_locked_target_with_approval(
            self.kernel,
            self.target.target_id,
            self.target.target_hash,
            envelope,
        )

        self.assertEqual("match", resolution.outcome)
        self.assertIsNotNone(decision)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.kernel.consume(decision.permit, self.intent))
        self.assertFalse(self.kernel.consume(decision.permit, self.intent))

    def test_target_hash_mismatch_stops_before_approval_is_consumed(self):
        envelope = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=self.now,
        )

        mismatch, denied = evaluate_locked_target_with_approval(
            self.kernel,
            self.target.target_id,
            "0" * 64,
            envelope,
        )
        exact, allowed = evaluate_locked_target_with_approval(
            self.kernel,
            self.target.target_id,
            self.target.target_hash,
            envelope,
        )

        self.assertEqual(("deny", "target_hash_mismatch"), (mismatch.outcome, mismatch.reason))
        self.assertIsNone(denied)
        self.assertEqual("match", exact.outcome)
        self.assertEqual("allow", allowed.outcome)

    def test_approval_for_different_intent_cannot_authorize_locked_target(self):
        other_intent = Intent(
            "agent:builder",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/release",
            0,
            "voice-session",
        )
        envelope = signed_envelope(
            self.kernel,
            other_intent,
            self.verifier,
            now_ns=self.now,
        )

        resolution, decision = evaluate_locked_target_with_approval(
            self.kernel,
            self.target.target_id,
            self.target.target_hash,
            envelope,
        )

        self.assertEqual("match", resolution.outcome)
        self.assertEqual(("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)

    def test_verified_approval_replay_remains_denied_with_canonical_reason(self):
        envelope = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=self.now,
        )

        _, first = evaluate_locked_target_with_approval(
            self.kernel,
            self.target.target_id,
            self.target.target_hash,
            envelope,
        )
        _, second = evaluate_locked_target_with_approval(
            self.kernel,
            self.target.target_id,
            self.target.target_hash,
            envelope,
        )

        self.assertEqual("allow", first.outcome)
        self.assertEqual(("deny", "approval_id_replayed"), (second.outcome, second.reason))


if __name__ == "__main__":
    unittest.main()

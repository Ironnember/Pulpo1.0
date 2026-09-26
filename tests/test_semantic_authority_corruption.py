import unittest

from pulpo import GovernanceKernel, Intent, Policy
from tests.authority_support import HmacTestVerifier, trust_for


class SemanticAuthorityCorruptionTests(unittest.TestCase):
    """Executable proof that inferred meaning cannot repair missing authority."""

    def setUp(self):
        verifier = HmacTestVerifier()
        self.kernel = GovernanceKernel(
            Policy(
                frozenset({"push"}),
                0,
                frozenset({"push"}),
                authority_trust=trust_for(verifier),
            ),
            secret=b"semantic-authority-corruption-proof",
        )
        self.reconstructed = Intent(
            "agent",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/main",
            0,
            "semantic-corruption-session",
        )

    def test_high_confidence_reconstruction_is_only_a_locked_proposal(self):
        confidence = 1.0
        target = self.kernel.lock_target("semantic-reconstruction", self.reconstructed)

        self.assertEqual(1.0, confidence)
        self.assertEqual(self.reconstructed, target.intent)
        self.assertEqual("target_locked", self.kernel.audit[-1]["event"])
        self.assertEqual("none", self.kernel.audit[-1]["payload"]["authority_effect"])
        self.assertFalse(any(record["event"] == "decision" for record in self.kernel.audit))

    def test_resolving_exact_reconstruction_does_not_inherit_authority(self):
        target = self.kernel.lock_target("semantic-reconstruction", self.reconstructed)

        resolution, decision = self.kernel.evaluate_locked_target(
            target.target_id,
            target.target_hash,
        )

        self.assertEqual(("match", "target_exact_match"), (resolution.outcome, resolution.reason))
        self.assertIsNotNone(decision)
        self.assertEqual(("require_approval", "approval_required"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)

    def test_alternate_plausible_reconstruction_cannot_reuse_exact_target(self):
        target = self.kernel.lock_target("semantic-reconstruction", self.reconstructed)
        alternate = Intent(
            "agent",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/release",
            0,
            "semantic-corruption-session",
        )
        alternate_target = self.kernel.lock_target("semantic-alternate", alternate)

        resolution, decision = self.kernel.evaluate_locked_target(
            target.target_id,
            alternate_target.target_hash,
        )

        self.assertEqual(("deny", "target_hash_mismatch"), (resolution.outcome, resolution.reason))
        self.assertIsNone(decision)

    def test_repeated_reconstruction_never_upgrades_authority(self):
        target = self.kernel.lock_target("semantic-reconstruction", self.reconstructed)

        for _confidence in (0.51, 0.90, 0.99, 1.0):
            resolution, decision = self.kernel.evaluate_locked_target(
                target.target_id,
                target.target_hash,
            )
            self.assertEqual("match", resolution.outcome)
            self.assertEqual("require_approval", decision.outcome)
            self.assertIsNone(decision.permit)

        self.assertFalse(any(record["event"] == "permit_issued" for record in self.kernel.audit))


if __name__ == "__main__":
    unittest.main()

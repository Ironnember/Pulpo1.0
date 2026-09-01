import unittest

from pulpo import GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import PulpoMCPProjection


class GovernedEffectBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=b"governed-effect-boundary",
            clock=lambda: 3_000_000,
        )
        self.projection = PulpoMCPProjection(PulpoOrchestrator(self.kernel))

    def test_no_permit_does_not_mean_no_governed_effect(self):
        """A canonical target lock mutates state even though no permit exists."""

        intent = Intent("agent:planner", "read", "repo:README.md", 0, "session-1")
        before = len(self.kernel.audit)
        target = self.kernel.lock_target("target-1", intent)

        self.assertEqual(before + 1, len(self.kernel.audit))
        record = self.kernel.audit[-1]
        self.assertEqual("target_locked", record["event"])
        self.assertEqual(target.target_hash, record["payload"]["target_hash"])
        self.assertEqual("none", record["payload"]["authority_effect"])
        self.assertNotIn("permit", record["payload"])
        self.assertIsNotNone(self.kernel.get_locked_target("target-1"))

    def test_non_authoritative_projection_cannot_receive_canonical_write_capability(self):
        """Ephemeral proposal transport must leave the canonical chain unchanged."""

        before = list(self.kernel.audit)
        proposal = self.projection.propose_intent(
            "target-1",
            "agent:planner",
            "read",
            "repo:README.md",
            0,
            "session-1",
        )

        self.assertEqual(before, self.kernel.audit)
        self.assertFalse(proposal["canonical_state_mutation"])
        self.assertEqual("none", proposal["governed_effect"])
        self.assertEqual("none", proposal["authority_effect"])
        self.assertNotIn("target_hash", proposal)
        self.assertIsNone(self.kernel.get_locked_target("target-1"))


if __name__ == "__main__":
    unittest.main()

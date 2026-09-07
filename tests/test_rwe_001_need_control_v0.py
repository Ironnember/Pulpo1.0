"""Incident-shaped evidence-of-need -> evidence-of-control tests.

These tests do not claim Pulpo prevented any historical incident. They translate
publicly documented failure mechanisms into local falsifiable checks against the
current canonical software boundary.

RWE-01 is shaped by the class of development-agent failures where a task gains
an unintended path to production mutation.

RWE-07 is shaped by NIST's observation that probabilistic agent-hijacking risk
can increase materially under repeated attempts. The property tested here is
stronger and narrower: repeated hostile requests must not accumulate authority.
"""

import unittest

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import PulpoMCPProjection, freeze_mcp_snapshot


class EvidenceOfNeedToControlV0(unittest.TestCase):
    def _kernel(self) -> GovernanceKernel:
        grant = AgentGrant(
            "agent:builder",
            frozenset({"write"}),
            ("dev:",),
            0,
        )
        return GovernanceKernel(
            Policy(
                frozenset({"write"}),
                0,
                agent_grants=(grant,),
            ),
            secret=b"pulpo-rwe-001-v0",
            clock=lambda: 31_000_000,
        )

    @staticmethod
    def _attempt_write(kernel: GovernanceKernel, intent: Intent, writes: list[str]) -> None:
        """Model one narrow executor that acts only after exact permit consumption."""

        decision = kernel.evaluate(intent)
        if decision.permit is None:
            return
        if kernel.consume(decision.permit, intent):
            writes.append(intent.resource)

    def test_rwe01_development_authority_cannot_become_production_mutation(self):
        kernel = self._kernel()
        projection = PulpoMCPProjection(
            freeze_mcp_snapshot(PulpoOrchestrator(kernel))
        )

        development_writes: list[str] = []
        production_writes: list[str] = []

        development = Intent(
            "agent:builder",
            "write",
            "dev:database:customers",
            0,
            "rwe01-dev",
        )
        self._attempt_write(kernel, development, development_writes)
        self.assertEqual(["dev:database:customers"], development_writes)

        for attempt in range(100):
            session_id = f"rwe01-prod-{attempt}"
            proposal = projection.propose_intent(
                f"rwe01-target-{attempt}",
                "agent:builder",
                "write",
                "prod:database:customers",
                0,
                session_id,
            )
            self.assertEqual("none", proposal["authority_effect"])
            self.assertEqual("none", proposal["governed_effect"])
            self.assertFalse(proposal["canonical_state_mutation"])
            self.assertNotIn("permit", proposal)

            production = Intent(
                "agent:builder",
                "write",
                "prod:database:customers",
                0,
                session_id,
            )
            decision = kernel.evaluate(production)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("agent_resource_not_allowed", decision.reason)
            self.assertIsNone(decision.permit)
            self._attempt_write(kernel, production, production_writes)

        self.assertEqual([], production_writes)
        self.assertTrue(kernel.verify_audit())

    def test_rwe07_repeated_hijacking_does_not_accumulate_authority(self):
        kernel = self._kernel()
        production_writes: list[str] = []

        for attempt in range(100):
            intent = Intent(
                "agent:builder",
                "write",
                "prod:database:customers",
                0,
                f"rwe07-{attempt}",
            )
            decision = kernel.evaluate(intent)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("agent_resource_not_allowed", decision.reason)
            self.assertIsNone(decision.permit)
            self._attempt_write(kernel, intent, production_writes)

        self.assertEqual([], production_writes)
        self.assertTrue(kernel.verify_audit())

        # Repeated denials do not widen authority and do not break the one
        # originally permitted namespace.
        allowed = Intent(
            "agent:builder",
            "write",
            "dev:database:customers",
            0,
            "rwe07-control",
        )
        decision = kernel.evaluate(allowed)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertTrue(kernel.consume(decision.permit, allowed))
        self.assertFalse(kernel.consume(decision.permit, allowed))


if __name__ == "__main__":
    unittest.main()

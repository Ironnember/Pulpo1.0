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
    def _execute_if_permitted(
        kernel: GovernanceKernel,
        intent: Intent,
        permit: str | None,
        modeled_writes: list[str],
    ) -> None:
        """Model one narrow executor that acts only after exact permit consumption."""

        if permit is None:
            return
        if kernel.consume(permit, intent):
            modeled_writes.append(intent.resource)

    @staticmethod
    def _decision_events_for_hashes(kernel: GovernanceKernel, intent_hashes: set[str]):
        return [
            record
            for record in kernel.audit
            if record.get("event") == "decision"
            and record.get("payload", {}).get("intent_hash") in intent_hashes
        ]

    def test_rwe01_development_authority_cannot_become_production_mutation(self):
        kernel = self._kernel()
        policy_hash_before = kernel.policy_hash
        grants_before = kernel.policy.agent_grants
        projection = PulpoMCPProjection(
            freeze_mcp_snapshot(PulpoOrchestrator(kernel))
        )

        modeled_development_writes: list[str] = []
        modeled_production_writes: list[str] = []

        development = Intent(
            "agent:builder",
            "write",
            "dev:database:customers",
            0,
            "rwe01-dev",
        )
        development_decision = kernel.evaluate(development)
        self.assertEqual("allow", development_decision.outcome)
        self.assertIsNotNone(development_decision.permit)
        self._execute_if_permitted(
            kernel,
            development,
            development_decision.permit,
            modeled_development_writes,
        )
        self.assertEqual(["dev:database:customers"], modeled_development_writes)

        production_hashes: set[str] = set()
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
            production_hashes.add(kernel.intent_hash(production))
            decision = kernel.evaluate(production)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("agent_resource_not_allowed", decision.reason)
            self.assertIsNone(decision.permit)
            self._execute_if_permitted(
                kernel,
                production,
                decision.permit,
                modeled_production_writes,
            )

        # Exactly the 100 production-scoped requests were denied; none received
        # or consumed a permit. The executor list is a local model, not proof of
        # an external provider's state.
        production_decisions = self._decision_events_for_hashes(kernel, production_hashes)
        self.assertEqual(100, len(production_decisions))
        self.assertTrue(
            all(record["payload"]["outcome"] == "deny" for record in production_decisions)
        )
        production_consumptions = [
            record
            for record in kernel.audit
            if record.get("event") == "permit_consumed"
            and record.get("payload", {}).get("intent_hash") in production_hashes
        ]
        self.assertEqual([], production_consumptions)
        self.assertEqual([], modeled_production_writes)

        # Repetition did not widen the policy or the agent grant.
        self.assertEqual(policy_hash_before, kernel.policy_hash)
        self.assertEqual(grants_before, kernel.policy.agent_grants)
        self.assertTrue(kernel.verify_audit())

    def test_rwe07_repeated_hijacking_does_not_accumulate_authority(self):
        kernel = self._kernel()
        policy_hash_before = kernel.policy_hash
        grants_before = kernel.policy.agent_grants
        modeled_production_writes: list[str] = []
        production_hashes: set[str] = set()

        for attempt in range(100):
            intent = Intent(
                "agent:builder",
                "write",
                "prod:database:customers",
                0,
                f"rwe07-{attempt}",
            )
            production_hashes.add(kernel.intent_hash(intent))
            decision = kernel.evaluate(intent)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("agent_resource_not_allowed", decision.reason)
            self.assertIsNone(decision.permit)
            self._execute_if_permitted(
                kernel,
                intent,
                decision.permit,
                modeled_production_writes,
            )

        production_decisions = self._decision_events_for_hashes(kernel, production_hashes)
        self.assertEqual(100, len(production_decisions))
        self.assertTrue(
            all(record["payload"]["outcome"] == "deny" for record in production_decisions)
        )
        self.assertEqual([], modeled_production_writes)
        self.assertEqual(policy_hash_before, kernel.policy_hash)
        self.assertEqual(grants_before, kernel.policy.agent_grants)
        self.assertTrue(kernel.verify_audit())

        # Repeated denials do not widen authority and do not break the one
        # originally permitted namespace. The valid permit remains exact and
        # one-use.
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
        assert decision.permit is not None
        self.assertTrue(kernel.consume(decision.permit, allowed))
        self.assertFalse(kernel.consume(decision.permit, allowed))


if __name__ == "__main__":
    unittest.main()

import unittest

from pulpo.decision_evidence import AgentInteraction, DecisionBoundary, evidence_projection


class DecisionEvidenceTests(unittest.TestCase):
    def boundary(self):
        return DecisionBoundary(
            boundary_id="boundary:purchase",
            task_id="task:1",
            principal="agent:commerce",
            proposed_action="purchase_domain",
            resource="commerce:domain:example.com",
            consequence_class="economic_external",
            required_evidence=("quote", "approval", "delivery"),
            approval_class="human_external",
        )

    def interaction(self, boundary):
        return AgentInteraction(
            interaction_id="interaction:1",
            task_id=boundary.task_id,
            source_principal="agent:planner",
            target_principal="agent:commerce",
            relation="proposes_to",
            payload_hash="a" * 64,
            boundary_hash=boundary.boundary_hash,
        )

    def test_boundary_hash_is_deterministic(self):
        first = self.boundary()
        second = self.boundary()
        self.assertEqual(first.boundary_hash, second.boundary_hash)

    def test_projection_binds_interaction_to_boundary(self):
        boundary = self.boundary()
        projection = evidence_projection(boundary, (self.interaction(boundary),))
        self.assertEqual(projection["authority_effect"], "none")
        self.assertEqual(projection["decision_boundary"]["boundary_hash"], boundary.boundary_hash)
        self.assertEqual(len(projection["agent_interactions"]), 1)

    def test_interaction_cannot_grant_authority(self):
        boundary = self.boundary()
        with self.assertRaises(ValueError):
            AgentInteraction(
                interaction_id="interaction:bad",
                task_id=boundary.task_id,
                source_principal="agent:planner",
                target_principal="agent:builder",
                relation="delegates_to",
                payload_hash="b" * 64,
                boundary_hash=boundary.boundary_hash,
                authority_effect="grant",
            )

    def test_self_interaction_is_rejected(self):
        boundary = self.boundary()
        with self.assertRaises(ValueError):
            AgentInteraction(
                interaction_id="interaction:self",
                task_id=boundary.task_id,
                source_principal="agent:planner",
                target_principal="agent:planner",
                relation="proposes_to",
                payload_hash="c" * 64,
                boundary_hash=boundary.boundary_hash,
            )

    def test_cross_task_interaction_is_rejected(self):
        boundary = self.boundary()
        interaction = AgentInteraction(
            interaction_id="interaction:other-task",
            task_id="task:2",
            source_principal="agent:planner",
            target_principal="agent:commerce",
            relation="proposes_to",
            payload_hash="d" * 64,
            boundary_hash=boundary.boundary_hash,
        )
        with self.assertRaises(ValueError):
            evidence_projection(boundary, (interaction,))

    def test_substituted_boundary_is_rejected(self):
        boundary = self.boundary()
        interaction = self.interaction(boundary)
        other = DecisionBoundary(
            boundary_id="boundary:other",
            task_id="task:1",
            principal="agent:commerce",
            proposed_action="purchase_domain",
            resource="commerce:domain:other.com",
            consequence_class="economic_external",
            required_evidence=("quote", "approval", "delivery"),
            approval_class="human_external",
        )
        with self.assertRaises(ValueError):
            evidence_projection(other, (interaction,))

    def test_boundary_requires_evidence(self):
        with self.assertRaises(ValueError):
            DecisionBoundary(
                boundary_id="boundary:empty",
                task_id="task:1",
                principal="agent:commerce",
                proposed_action="purchase_domain",
                resource="commerce:domain:example.com",
                consequence_class="economic_external",
                required_evidence=(),
            )


if __name__ == "__main__":
    unittest.main()

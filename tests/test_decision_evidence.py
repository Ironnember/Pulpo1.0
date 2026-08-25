import unittest

from pulpo.decision_evidence import (
    AgentInteraction,
    DecisionBoundary,
    attach_to_proof_bundle,
    evidence_projection,
)


class DecisionEvidenceTests(unittest.TestCase):
    def boundary(self, resource="commerce:domain:example.com"):
        return DecisionBoundary(
            boundary_id="boundary:purchase",
            task_id="task:1",
            principal="agent:commerce",
            proposed_action="purchase_domain",
            resource=resource,
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

    def proof_bundle(self):
        from pulpo.decision_evidence import _digest

        order = {
            "principal": "agent:commerce",
            "domain": "example.com",
            "purchase_price_cents": 2000,
        }
        payload = {
            "schema": "pulpo.commerce.proof.v1",
            "request": {"request_id": "request-1"},
            "quote": {"quote_id": "quote-1"},
            "assessment": {"outcome": "allow"},
            "order": order,
            "outcome": None,
            "audit_valid": True,
            "audit_tip": "f" * 64,
        }
        return {**payload, "bundle_hash": _digest(payload)}, order

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

    def test_attachment_is_hash_covered_and_preserves_audit_tip(self):
        from pulpo.decision_evidence import _digest

        bundle, order = self.proof_bundle()
        resource = f"commerce:domain:{_digest(order)}"
        boundary = self.boundary(resource)
        attached = attach_to_proof_bundle(bundle, boundary, (self.interaction(boundary),))
        self.assertEqual(bundle["audit_tip"], attached["audit_tip"])
        self.assertEqual("pulpo.decision-evidence.v1", attached["decision_evidence"]["schema"])
        self.assertNotEqual(bundle["bundle_hash"], attached["bundle_hash"])
        payload = {key: value for key, value in attached.items() if key != "bundle_hash"}
        self.assertEqual(_digest(payload), attached["bundle_hash"])

    def test_attachment_rejects_tampered_bundle(self):
        bundle, order = self.proof_bundle()
        bundle["audit_tip"] = "0" * 64
        from pulpo.decision_evidence import _digest
        boundary = self.boundary(f"commerce:domain:{_digest(order)}")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            attach_to_proof_bundle(bundle, boundary)

    def test_attachment_rejects_substituted_order_boundary(self):
        bundle, _ = self.proof_bundle()
        boundary = self.boundary("commerce:domain:" + "0" * 64)
        with self.assertRaisesRegex(ValueError, "exact order"):
            attach_to_proof_bundle(bundle, boundary)

    def test_attachment_rejects_authority_substitution(self):
        from pulpo.decision_evidence import _digest
        bundle, order = self.proof_bundle()
        boundary = DecisionBoundary(
            boundary_id="boundary:purchase",
            task_id="task:1",
            principal="agent:planner",
            proposed_action="purchase_domain",
            resource=f"commerce:domain:{_digest(order)}",
            consequence_class="economic_external",
            required_evidence=("quote", "approval", "delivery"),
        )
        with self.assertRaisesRegex(ValueError, "principal"):
            attach_to_proof_bundle(bundle, boundary)


if __name__ == "__main__":
    unittest.main()

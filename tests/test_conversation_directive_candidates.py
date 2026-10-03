import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.conversation_directives import (
    ConversationDirectiveCandidate,
    ConversationDirectiveCandidateError,
    digest_conversation_source,
)
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 10_000_000
OPERATOR = "operator:retail-manager"
PRINCIPAL = "agent:archie"
RESOURCE = "tenant:mintpath-test:store:148:fixture:beverage-a3:"


class ConversationDirectiveCandidateTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.trust = trust_for(self.verifier)
        self.parent = Directive(
            directive_id="retail-manager-delegation",
            version=1,
            issuer_authority_id=self.trust.authority_id,
            principal=PRINCIPAL,
            allowed_actions=frozenset({"publish_planogram", "read_planogram"}),
            resource_prefixes=("tenant:mintpath-test:store:148:",),
            max_cost=50,
            issued_at_ns=NOW - 1_000,
            expires_at_ns=NOW + 10_000,
        )

    def candidate(self, **overrides):
        values = dict(
            candidate_id="planogram-chat-001",
            source_digest=digest_conversation_source(
                "For today, Archie may publish Store 148 beverage planograms, max 20 cost units."
            ),
            interpreter_id="semantic-projection:test",
            interpreter_version="1",
            proposed_issuer_authority_id=self.trust.authority_id,
            principal=PRINCIPAL,
            allowed_actions=frozenset({"publish_planogram"}),
            resource_prefixes=(RESOURCE,),
            max_cost=20,
            issued_at_ns=NOW,
            expires_at_ns=NOW + 5_000,
            identity_context_hash="a" * 64,
        )
        values.update(overrides)
        return ConversationDirectiveCandidate(**values)

    def governed(self):
        policy = Policy(
            frozenset({
                "publish_planogram",
                "activate_directive",
                "revoke_directive",
            }),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=self.trust,
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"conversation-directive-candidate-proof",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        return kernel, DirectiveAuthorityController(kernel)

    def envelope(self, kernel, controller, directive, *, operation=None, approval_id, nonce):
        selected_operation = operation or controller.ACTIVATE
        authority_intent = controller.authority_intent(
            selected_operation,
            directive,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            authority_intent,
            self.verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def activate_parent(self, kernel, controller):
        envelope = self.envelope(
            kernel,
            controller,
            self.parent,
            approval_id="activate-parent",
            nonce="activate-parent-nonce",
        )
        decision = controller.activate(
            self.parent,
            envelope,
            operator_principal=OPERATOR,
        )
        self.assertEqual("allow", decision.outcome)

    def test_candidate_is_explicitly_non_authoritative(self):
        candidate = self.candidate()

        self.assertEqual("conversation", candidate.source_type)
        self.assertEqual("none", candidate.authority_effect)
        self.assertEqual("none", candidate.governed_effect)
        self.assertFalse(candidate.canonical_state_mutation)
        self.assertTrue(candidate.admissible)

    def test_exact_source_and_identity_provenance_change_candidate_identity(self):
        first = self.candidate()
        second = self.candidate(
            source_digest=digest_conversation_source(
                "For today, Archie may publish Store 148 beverage planograms, max 19 cost units."
            )
        )
        third = self.candidate(identity_context_hash="b" * 64)

        self.assertNotEqual(first.candidate_hash, second.candidate_hash)
        self.assertNotEqual(first.candidate_hash, third.candidate_hash)
        self.assertNotEqual(first.derived_directive_id, second.derived_directive_id)
        self.assertNotEqual(first.derived_directive_id, third.derived_directive_id)

    def test_ambiguous_conversation_cannot_materialize(self):
        candidate = self.candidate(unresolved_references=("target_store", "planogram_version"))

        self.assertFalse(candidate.admissible)
        with self.assertRaisesRegex(
            ConversationDirectiveCandidateError,
            "candidate_ambiguity_unresolved",
        ):
            candidate.materialize_narrowed_directive(self.parent)

    def test_candidate_cannot_broaden_parent_action(self):
        candidate = self.candidate(allowed_actions=frozenset({"publish_planogram", "delete_store"}))

        with self.assertRaisesRegex(
            ConversationDirectiveCandidateError,
            "directive_parent_action_broadened",
        ):
            candidate.materialize_narrowed_directive(self.parent)

    def test_candidate_cannot_broaden_parent_resource(self):
        candidate = self.candidate(
            resource_prefixes=("tenant:mintpath-test:store:149:",),
        )

        with self.assertRaisesRegex(
            ConversationDirectiveCandidateError,
            "directive_parent_resource_broadened",
        ):
            candidate.materialize_narrowed_directive(self.parent)

    def test_candidate_cannot_broaden_parent_budget_or_time(self):
        with self.assertRaisesRegex(
            ConversationDirectiveCandidateError,
            "directive_parent_budget_broadened",
        ):
            self.candidate(max_cost=51).materialize_narrowed_directive(self.parent)

        with self.assertRaisesRegex(
            ConversationDirectiveCandidateError,
            "directive_parent_time_broadened",
        ):
            self.candidate(expires_at_ns=self.parent.expires_at_ns + 1).materialize_narrowed_directive(
                self.parent
            )

    def test_identity_context_provenance_cannot_override_delegation_ceiling(self):
        candidate = self.candidate(
            identity_context_hash="f" * 64,
            resource_prefixes=("tenant:mintpath-test:",),
            max_cost=999,
        )

        with self.assertRaises(ConversationDirectiveCandidateError):
            candidate.materialize_narrowed_directive(self.parent)

    def test_exact_candidate_materializes_only_as_parent_bound_child(self):
        candidate = self.candidate()
        child = candidate.materialize_narrowed_directive(self.parent)

        self.assertEqual(self.parent.directive_hash, child.parent_directive_hash)
        self.assertEqual(candidate.derived_directive_id, child.directive_id)
        self.assertEqual(candidate.allowed_actions, child.allowed_actions)
        self.assertEqual(candidate.resource_prefixes, child.resource_prefixes)
        self.assertEqual(candidate.max_cost, child.max_cost)
        self.assertEqual(candidate.proposed_issuer_authority_id, child.issuer_authority_id)
        self.assertIsNone(child.derivation_failure(self.parent))

    def test_materialized_candidate_is_not_authority_until_existing_controller_activates_it(self):
        kernel, controller = self.governed()
        self.activate_parent(kernel, controller)

        candidate = self.candidate()
        child = candidate.materialize_narrowed_directive(self.parent)
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent(
            PRINCIPAL,
            "publish_planogram",
            f"{RESOURCE}version:18",
            12,
            "planogram-proof-001",
        )

        before = projection.evaluate(intent, child)
        self.assertEqual("deny", before.outcome)
        self.assertIsNone(before.permit)

        child_envelope = self.envelope(
            kernel,
            controller,
            child,
            approval_id="activate-child",
            nonce="activate-child-nonce",
        )
        activated = controller.activate(
            child,
            child_envelope,
            operator_principal=OPERATOR,
            parent_directive=self.parent,
        )
        self.assertEqual("allow", activated.outcome)

        after = projection.evaluate(intent, child)
        self.assertEqual("allow", after.outcome)
        self.assertIsNotNone(after.permit)
        self.assertTrue(kernel.consume(after.permit, intent))
        self.assertFalse(kernel.consume(after.permit, intent))

    def test_revoked_parent_still_blocks_conversation_derived_child(self):
        kernel, controller = self.governed()
        self.activate_parent(kernel, controller)
        candidate = self.candidate()
        child = candidate.materialize_narrowed_directive(self.parent)

        revoke_envelope = self.envelope(
            kernel,
            controller,
            self.parent,
            operation=controller.REVOKE,
            approval_id="revoke-parent",
            nonce="revoke-parent-nonce",
        )
        revoked = controller.revoke(
            self.parent,
            revoke_envelope,
            operator_principal=OPERATOR,
        )
        self.assertEqual("allow", revoked.outcome)

        child_envelope = self.envelope(
            kernel,
            controller,
            child,
            approval_id="activate-child-after-revoke",
            nonce="activate-child-after-revoke-nonce",
        )
        decision = controller.activate(
            child,
            child_envelope,
            operator_principal=OPERATOR,
            parent_directive=self.parent,
        )
        self.assertEqual("deny", decision.outcome)


if __name__ == "__main__":
    unittest.main()

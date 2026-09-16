import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.execution_context import (
    ExecutionContext,
    bind_resource_to_execution_context,
    consume_context_bound_permit,
    required_execution_context_hash,
    verify_execution_context,
)


NOW = 8_000_000
SESSION = "execution-context-proof-1"
PRINCIPAL = "agent:assistant"
ACTION = "read_connector"


class ExecutionContextBindingTests(unittest.TestCase):
    """Prove that requested routing context cannot substitute for observed context."""

    def setUp(self):
        self.kernel = GovernanceKernel(
            Policy(frozenset({ACTION}), 0),
            secret=b"execution-context-proof-secret",
            clock=lambda: NOW,
        )
        self.requested = ExecutionContext(
            "slack",
            "workspace:requested",
            principal="human:owner",
            connection="chatgpt-slack",
        )
        self.other_workspace = ExecutionContext(
            "slack",
            "workspace:other",
            principal="human:owner",
            connection="chatgpt-slack",
        )
        self.intent = Intent(
            PRINCIPAL,
            ACTION,
            bind_resource_to_execution_context("channel:history", self.requested),
            0,
            SESSION,
        )

    def _permit(self):
        decision = self.kernel.evaluate(self.intent)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit

    def test_exact_observed_context_consumes_one_use_permit(self):
        permit = self._permit()

        check, consumed = consume_context_bound_permit(
            self.kernel,
            permit,
            self.intent,
            self.requested,
        )

        self.assertEqual(("match", "execution_context_exact_match"), (check.outcome, check.reason))
        self.assertTrue(consumed)
        self.assertFalse(self.kernel.consume(permit, self.intent))

    def test_wrong_authority_scope_denies_before_permit_consumption(self):
        permit = self._permit()

        check, consumed = consume_context_bound_permit(
            self.kernel,
            permit,
            self.intent,
            self.other_workspace,
        )

        self.assertEqual(("deny", "execution_context_mismatch"), (check.outcome, check.reason))
        self.assertFalse(consumed)

        exact_check, exact_consumed = consume_context_bound_permit(
            self.kernel,
            permit,
            self.intent,
            self.requested,
        )
        self.assertEqual("match", exact_check.outcome)
        self.assertTrue(exact_consumed)

    def test_same_owner_and_connection_do_not_expand_workspace_authority(self):
        self.assertEqual(self.requested.principal, self.other_workspace.principal)
        self.assertEqual(self.requested.connection, self.other_workspace.connection)
        self.assertNotEqual(self.requested.context_hash, self.other_workspace.context_hash)

        check = verify_execution_context(self.intent, self.other_workspace)
        self.assertEqual(("deny", "execution_context_mismatch"), (check.outcome, check.reason))

    def test_missing_observation_fails_closed_without_spending_permit(self):
        permit = self._permit()

        check, consumed = consume_context_bound_permit(self.kernel, permit, self.intent, None)

        self.assertEqual(
            ("deny", "execution_context_observation_missing", False),
            (check.outcome, check.reason, consumed),
        )
        _, exact_consumed = consume_context_bound_permit(
            self.kernel,
            permit,
            self.intent,
            self.requested,
        )
        self.assertTrue(exact_consumed)

    def test_surface_substitution_fails_closed(self):
        wrong_surface = ExecutionContext(
            "github",
            self.requested.authority_scope,
            principal=self.requested.principal,
            connection=self.requested.connection,
        )
        check = verify_execution_context(self.intent, wrong_surface)
        self.assertEqual(("deny", "execution_context_mismatch"), (check.outcome, check.reason))

    def test_unbound_resource_is_not_accepted_by_context_gate(self):
        unbound = Intent(PRINCIPAL, ACTION, "channel:history", 0, SESSION)
        decision = self.kernel.evaluate(unbound)
        self.assertEqual("allow", decision.outcome)

        check, consumed = consume_context_bound_permit(
            self.kernel,
            decision.permit,
            unbound,
            self.requested,
        )
        self.assertEqual(
            ("deny", "execution_context_binding_missing", False),
            (check.outcome, check.reason, consumed),
        )

    def test_context_retargeting_changes_intent_and_invalidates_existing_permit(self):
        permit = self._permit()
        substituted = Intent(
            PRINCIPAL,
            ACTION,
            bind_resource_to_execution_context("channel:history", self.other_workspace),
            0,
            SESSION,
        )

        self.assertNotEqual(self.kernel.intent_hash(self.intent), self.kernel.intent_hash(substituted))
        self.assertFalse(self.kernel.consume(permit, substituted))

    def test_bound_resource_carries_exact_context_hash(self):
        self.assertEqual(
            self.requested.context_hash,
            required_execution_context_hash(self.intent.resource),
        )


if __name__ == "__main__":
    unittest.main()

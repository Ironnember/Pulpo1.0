import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directive_memory_surface import (
    DirectiveMemoryReadSnapshot,
    DirectiveMemorySkillProjection,
    freeze_directive_memory_snapshot,
)
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"


def directive(**overrides):
    values = dict(
        directive_id="deploy-prod",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


class DirectiveMemorySkillBoundaryTests(unittest.TestCase):
    def governed(self, state=None):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"directive-memory-surface-proof",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation,
            d,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def activate(self, state, d):
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self.approve(
            kernel,
            verifier,
            controller.ACTIVATE,
            d,
            "activate-surface-1",
            "activate-surface-nonce-1",
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def test_surface_accepts_only_exact_capability_free_snapshot(self):
        kernel, _ = self.governed(InMemoryKernelState())
        d = directive()
        snapshot = freeze_directive_memory_snapshot(kernel, d)
        self.assertIs(type(snapshot), DirectiveMemoryReadSnapshot)
        with self.assertRaises(TypeError):
            DirectiveMemorySkillProjection(kernel)
        with self.assertRaises(TypeError):
            DirectiveMemorySkillProjection(d)

        surface = DirectiveMemorySkillProjection(snapshot)
        for forbidden in (
            "kernel",
            "state",
            "_state",
            "controller",
            "authority_client",
            "approval_verifier",
            "executor",
            "clock",
            "ledger",
        ):
            self.assertFalse(hasattr(surface, forbidden), forbidden)
        self.assertEqual(("_snapshot",), DirectiveMemorySkillProjection.__slots__)
        self.assertIs(type(surface._snapshot), DirectiveMemoryReadSnapshot)

    def test_chat_style_inspection_and_proposal_do_not_mutate_canonical_state(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _, _ = self.activate(state, d)
        audit_before = list(state.audit)
        snapshot = freeze_directive_memory_snapshot(kernel, d)
        surface = DirectiveMemorySkillProjection(snapshot)

        inspected = surface.inspect()
        proposed = surface.propose_intent(action="write", resource="repo:file", cost=3)

        self.assertEqual(audit_before, state.audit)
        self.assertEqual("active", state.directive_status(d.directive_id, d.version, d.directive_hash))
        self.assertEqual("not_asserted", inspected["authority"])
        self.assertFalse(inspected["canonical_state_mutation"])
        self.assertEqual("none", inspected["governed_effect"])
        self.assertTrue(proposed["frozen_scope_match"])
        self.assertEqual("frozen_scope_match_only", proposed["frozen_scope_reason"])
        self.assertTrue(proposed["requires_canonical_revalidation"])
        self.assertEqual("not_asserted", proposed["authority"])
        self.assertFalse(proposed["canonical_state_mutation"])

    def test_unactivated_directive_cannot_be_promoted_by_skill_projection(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _ = self.governed(state)
        audit_before = list(state.audit)
        surface = DirectiveMemorySkillProjection(freeze_directive_memory_snapshot(kernel, d))

        proposal = surface.propose_intent(action="write", resource="repo:file", cost=1)

        self.assertFalse(proposal["frozen_scope_match"])
        self.assertEqual("directive_not_authorized", proposal["frozen_scope_reason"])
        self.assertEqual("not_asserted", proposal["authority"])
        self.assertEqual(audit_before, state.audit)
        self.assertEqual("directive_not_authorized", state.directive_status(d.directive_id, d.version, d.directive_hash))

    def test_broadening_request_is_only_a_failed_frozen_scope_proposal(self):
        state = InMemoryKernelState()
        d = directive(max_cost=5)
        kernel, _, _ = self.activate(state, d)
        audit_before = list(state.audit)
        surface = DirectiveMemorySkillProjection(freeze_directive_memory_snapshot(kernel, d))

        proposal = surface.propose_intent(action="write", resource="repo:file", cost=50)

        self.assertFalse(proposal["frozen_scope_match"])
        self.assertEqual("directive_budget_exceeded", proposal["frozen_scope_reason"])
        self.assertTrue(proposal["requires_canonical_revalidation"])
        self.assertEqual("none", proposal["authority_effect"])
        self.assertEqual("none", proposal["governed_effect"])
        self.assertEqual(audit_before, state.audit)

    def test_skill_surface_exposes_no_activation_revocation_or_execution_methods(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _, _ = self.activate(state, d)
        surface = DirectiveMemorySkillProjection(freeze_directive_memory_snapshot(kernel, d))

        for forbidden in (
            "activate",
            "revoke",
            "evaluate",
            "evaluate_with_approval",
            "consume",
            "mint_permit",
            "execute",
            "write",
            "commit",
        ):
            self.assertFalse(hasattr(surface, forbidden), forbidden)

    def test_stale_pre_revocation_snapshot_cannot_override_live_canonical_revocation(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name)
            d = directive()
            kernel, verifier, controller = self.activate(state, d)
            surface = DirectiveMemorySkillProjection(freeze_directive_memory_snapshot(kernel, d))

            stale_before_revoke = surface.propose_intent(
                action="write",
                resource="repo:file",
                cost=1,
            )
            self.assertTrue(stale_before_revoke["frozen_scope_match"])
            self.assertEqual("not_asserted", stale_before_revoke["authority"])

            revoke_envelope = self.approve(
                kernel,
                verifier,
                controller.REVOKE,
                d,
                "revoke-surface-1",
                "revoke-surface-nonce-1",
            )
            revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
            self.assertEqual("allow", revoke.outcome)
            state.close()

            restarted = SQLiteKernelState(handle.name)
            restarted_kernel, _ = self.governed(restarted)
            live = GovernedDirectiveProjection(restarted_kernel).evaluate(
                Intent("agent:builder", "write", "repo:file", 1),
                d,
            )
            stale_after_restart = surface.propose_intent(
                action="write",
                resource="repo:file",
                cost=1,
            )

            self.assertEqual(("deny", "directive_revoked"), (live.outcome, live.reason))
            self.assertTrue(stale_after_restart["frozen_scope_match"])
            self.assertEqual("frozen", stale_after_restart["freshness"])
            self.assertEqual("not_asserted", stale_after_restart["authority"])
            self.assertTrue(stale_after_restart["requires_canonical_revalidation"])
            self.assertTrue(restarted_kernel.verify_audit())
            restarted.close()


if __name__ == "__main__":
    unittest.main()

from dataclasses import replace
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
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


class DirectiveProofTests(unittest.TestCase):
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
            secret=b"proof",
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
        envelope = self.approve(kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1")
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def test_directive_components_reject_parallel_state_and_clock_injection(self):
        state = InMemoryKernelState()
        kernel, _ = self.governed(state)
        with self.assertRaises(TypeError):
            DirectiveAuthorityController(kernel, InMemoryKernelState(), lambda: NOW)
        with self.assertRaises(TypeError):
            GovernedDirectiveProjection(kernel, InMemoryKernelState(), lambda: NOW)

    def test_chat_or_retrieval_cannot_create_authority(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _ = self.governed(state)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 1), d)
        self.assertEqual(("deny", "directive_not_authorized"), (decision.outcome, decision.reason))

    def test_activation_requires_verified_external_authority(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        intent = controller.authority_intent(controller.ACTIVATE, d, operator_principal=OPERATOR)
        valid = signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id="activate-1",
            nonce="activate-nonce-1",
        )
        envelope = replace(valid, signature="00" * 32)
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual(("deny", "approval_signature_invalid"), (decision.outcome, decision.reason))
        self.assertEqual("directive_not_authorized", state.directive_status(d.directive_id, d.version, d.directive_hash))

    def test_approval_is_bound_to_exact_directive_digest(self):
        state = InMemoryKernelState()
        original = directive(max_cost=1)
        broadened = directive(max_cost=99)
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self.approve(kernel, verifier, controller.ACTIVATE, original, "activate-1", "activate-nonce-1")
        decision = controller.activate(broadened, envelope, operator_principal=OPERATOR)
        self.assertEqual(("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason))
        self.assertEqual("directive_not_authorized", state.directive_status(broadened.directive_id, broadened.version, broadened.directive_hash))

    def test_authorized_directive_constrains_but_does_not_replace_kernel(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _, _ = self.activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        allowed = projection.evaluate(Intent("agent:builder", "write", "repo:file", 5), d)
        denied = projection.evaluate(Intent("agent:builder", "write", "repo:file", 6), d)
        self.assertEqual("allow", allowed.outcome)
        self.assertEqual("directive_budget_exceeded", denied.reason)

    def test_model_summary_or_retrieval_score_cannot_raise_authority(self):
        state = InMemoryKernelState()
        d = directive(max_cost=1)
        kernel, _, _ = self.activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 2), d)
        self.assertEqual("directive_budget_exceeded", decision.reason)

    def test_untrusted_issuer_is_denied_even_with_valid_approval(self):
        state = InMemoryKernelState()
        d = directive(issuer_authority_id="authority:other")
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self.approve(kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1")
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("directive_issuer_untrusted", decision.reason)

    def test_revocation_requires_new_authority_and_survives_restart(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name)
            d = directive()
            kernel, verifier, controller = self.activate(state, d)
            activation = next(record for record in state.audit if record["event"] == "directive_activated")
            self.assertEqual(d.directive_hash, activation["payload"]["authority_evidence"]["directive_hash"])
            self.assertEqual("authority:test-owner", activation["payload"]["authority_evidence"]["authority_id"])

            revoke_envelope = self.approve(
                kernel,
                verifier,
                controller.REVOKE,
                d,
                "revoke-1",
                "revoke-nonce-1",
            )
            revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
            self.assertEqual("allow", revoke.outcome)
            state.close()

            restarted = SQLiteKernelState(handle.name)
            restarted_kernel, _ = self.governed(restarted)
            projection = GovernedDirectiveProjection(restarted_kernel)
            decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 1), d)
            self.assertEqual("directive_revoked", decision.reason)
            self.assertTrue(restarted_kernel.verify_audit())
            restarted.close()

    def test_delegated_scope_cannot_be_broadened_by_substitution(self):
        state = InMemoryKernelState()
        original = directive()
        kernel, _, _ = self.activate(state, original)
        broadened = directive(resource_prefixes=("repo:", "shell:"), max_cost=50)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(Intent("agent:builder", "write", "shell:root", 1), broadened)
        self.assertEqual("directive_version_mismatch", decision.reason)

    def test_active_directive_bound_permit_consumes_once_with_identity_evidence(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _, _ = self.activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:file", 1)
        decision = projection.evaluate(intent, d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        self.assertTrue(kernel.consume(decision.permit, intent))
        self.assertFalse(kernel.consume(decision.permit, intent))
        consumed = [record for record in state.audit if record["event"] == "permit_consumed"][-1]
        self.assertEqual(d.directive_id, consumed["payload"]["directive_id"])
        self.assertEqual(d.version, consumed["payload"]["directive_version"])
        self.assertEqual(d.directive_hash, consumed["payload"]["directive_hash"])
        self.assertEqual("active", consumed["payload"]["directive_status"])

    def test_revoked_directive_invalidates_previously_issued_permit(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, verifier, controller = self.activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:file", 1)
        decision = projection.evaluate(intent, d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revoke_envelope = self.approve(
            kernel,
            verifier,
            controller.REVOKE,
            d,
            "revoke-1",
            "revoke-nonce-1",
        )
        revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", revoke.outcome)

        self.assertFalse(kernel.consume(decision.permit, intent))
        rejected = [record for record in state.audit if record["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])
        self.assertEqual(d.directive_hash, rejected["payload"]["directive_hash"])

    def test_preissued_permit_stays_invalid_after_revocation_and_restart(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name)
            d = directive()
            kernel, verifier, controller = self.activate(state, d)
            projection = GovernedDirectiveProjection(kernel)
            intent = Intent("agent:builder", "write", "repo:file", 1)
            decision = projection.evaluate(intent, d)
            self.assertEqual("allow", decision.outcome)
            self.assertIsNotNone(decision.permit)

            revoke_envelope = self.approve(
                kernel,
                verifier,
                controller.REVOKE,
                d,
                "revoke-1",
                "revoke-nonce-1",
            )
            revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
            self.assertEqual("allow", revoke.outcome)
            state.close()

            restarted = SQLiteKernelState(handle.name)
            restarted_kernel, _ = self.governed(restarted)
            self.assertFalse(restarted_kernel.consume(decision.permit, intent))
            rejected = [record for record in restarted.audit if record["event"] == "permit_rejected"][-1]
            self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])
            self.assertEqual(d.directive_id, rejected["payload"]["directive_id"])
            self.assertEqual(d.version, rejected["payload"]["directive_version"])
            self.assertEqual(d.directive_hash, rejected["payload"]["directive_hash"])
            self.assertTrue(restarted_kernel.verify_audit())
            restarted.close()


if __name__ == "__main__":
    unittest.main()

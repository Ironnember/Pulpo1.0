from dataclasses import replace
import inspect
import tempfile
import unittest
from pathlib import Path

from pulpo.commerce import (
    CommerceViolation,
    DomainPurchaseRequest,
    DomainQuote,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_reconcile import (
    GovernedDomainOutcomeMemoryProjection,
    IndependentDomainObservation,
    IndependentDomainReconciler,
)
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 23_000_000
CUSTODY_SECRET = b"issue-153-custody"
KERNEL_SECRET = b"issue-153-kernel"
OPERATOR = "operator:owner"


class Issue153ConsequenceReconciliationV0(unittest.TestCase):
    """Closure-grade local proof for Issue #153 under the software boundary."""

    def _path(self) -> Path:
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        return path

    @staticmethod
    def _safe_close(state: SQLiteKernelState) -> None:
        try:
            state.close()
        except Exception:
            pass

    @staticmethod
    def _commerce_verifier() -> HmacTestVerifier:
        return HmacTestVerifier(secret=b"issue-153-commerce-authority")

    def _commerce_policy(self, verifier: HmacTestVerifier) -> Policy:
        return Policy(
            frozenset({"purchase_domain", "activate_directive", "revoke_directive"}),
            3_000,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )

    def _activate_directive(
        self,
        kernel: GovernanceKernel,
        verifier: HmacTestVerifier,
        directive: Directive,
        *,
        approval_id: str,
        nonce: str,
    ) -> DirectiveAuthorityController:
        controller = DirectiveAuthorityController(kernel)
        authority_intent = controller.authority_intent(
            controller.ACTIVATE,
            directive,
            operator_principal=OPERATOR,
        )
        envelope = signed_envelope(
            kernel,
            authority_intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )
        decision = controller.activate(
            directive,
            envelope,
            operator_principal=OPERATOR,
        )
        self.assertEqual("allow", decision.outcome)
        return controller

    def _stack(self, path: Path):
        custody = SQLiteGovernanceCustody(
            path,
            signing_secret=CUSTODY_SECRET,
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(path)
        state = SQLiteKernelState(path)
        verifier = self._commerce_verifier()
        kernel = GovernanceKernel(
            self._commerce_policy(verifier),
            secret=KERNEL_SECRET,
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        directive = Directive(
            directive_id="issue-153-commerce-directive",
            version=1,
            issuer_authority_id=verifier.authority_id,
            principal="agent:commerce",
            allowed_actions=frozenset({"purchase_domain"}),
            resource_prefixes=("commerce:domain:",),
            max_cost=3_000,
            issued_at_ns=NOW - 100,
            expires_at_ns=NOW + 100_000,
        )
        self._activate_directive(
            kernel,
            verifier,
            directive,
            approval_id="issue-153-commerce-activate",
            nonce="issue-153-commerce-activate-nonce",
        )

        request = DomainPurchaseRequest(
            request_id="issue-153-request-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-issue153.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="issue-153-quote-v0",
            domain="pulpo-issue153.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref="credential://issue-153/executor",
            now_ns=NOW,
        )
        self.assertEqual("allow", assessment.outcome)
        self.assertIsNotNone(assessment.order)
        order = assessment.order
        assert order is not None

        intent = purchase_intent(order)
        target = kernel.lock_target("issue-153-target-v0", intent)
        decision = GovernedDirectiveProjection(kernel).evaluate(intent, directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        coordinator = GovernedDomainAttemptCoordinator(kernel, custody, budget)
        reservation = coordinator.reserve(order)
        governed = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
            reservation_id=reservation.reservation_id,
        )

        consumed = [record for record in kernel.audit if record["event"] == "permit_consumed"][-1]
        self.assertEqual(directive.directive_hash, consumed["payload"]["directive_hash"])
        self.assertEqual("active", consumed["payload"]["directive_status"])

        head = custody.snapshot()
        custody.claim_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            executor_id="executor:issue-153",
        )
        provider_request_id = f"issue153:{governed.attempt_id}"
        head = custody.snapshot()
        custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=provider_request_id,
        )
        head = custody.snapshot()
        custody.require_reconciliation(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
        )
        return (
            state,
            kernel,
            custody,
            budget,
            governed,
            order,
            provider_request_id,
            verifier,
        )

    @staticmethod
    def _observation(provider_request_id: str, **changes) -> IndependentDomainObservation:
        values = {
            "observation_id": "issue-153-observation-v0",
            "provider_request_id": provider_request_id,
            "provider_request_status": "succeeded",
            "domain": "pulpo-issue153.example",
            "registrar": "name.com",
            "owner_ref": "owner://iron-ember",
            "registered": True,
            "payment_id": "issue-153-payment-v0",
            "charged_cents": 2_000,
            "receipt_hash": "a" * 64,
            "privacy_enabled": True,
            "dns_state": "registered",
        }
        values.update(changes)
        return IndependentDomainObservation(**values)

    @staticmethod
    def _directive_kernel(now_box, *, directive_id: str, max_cost: int = 2):
        verifier = HmacTestVerifier(secret=b"issue-153-freshness-authority")
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            policy,
            secret=b"issue-153-freshness-kernel",
            approval_verifier=verifier,
            clock=lambda: now_box[0],
            state=state,
        )
        directive = Directive(
            directive_id=directive_id,
            version=1,
            issuer_authority_id=verifier.authority_id,
            principal="agent:builder",
            allowed_actions=frozenset({"write"}),
            resource_prefixes=("repo:",),
            max_cost=max_cost,
            issued_at_ns=NOW - 100,
            expires_at_ns=NOW + 500,
        )
        return kernel, verifier, state, directive

    def test_01_valid_directive_exact_permit_and_observation_reconcile_verified_success(self):
        path = self._path()
        state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
        self.addCleanup(self._safe_close, state)
        observation = self._observation(provider_request_id)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153",
        ).reconcile(governed, order, observation)

        self.assertEqual(("success", "external_consequence_verified"), (result.outcome, result.reason))
        self.assertEqual(SQLiteGovernanceCustody.RECONCILED_SUCCESS, custody.attempt(governed.attempt_id).state)
        self.assertEqual(2_000, budget.spent_cents)
        self.assertEqual(0, budget.reserved_cents)

        memory_projection = GovernedDomainOutcomeMemoryProjection(kernel, custody)
        memory = memory_projection.record(governed, order, observation, result)
        self.assertEqual("SUCCESS_VERIFIED", memory.classification)
        self.assertTrue(memory.reusable)
        self.assertEqual("none", memory.authority_effect)
        self.assertEqual("canonical_outcome_memory", memory.governed_effect)

        duplicate = memory_projection.record(governed, order, observation, result)
        self.assertEqual(memory, duplicate)
        events = [record for record in kernel.audit if record["event"] == memory_projection.EVENT]
        self.assertEqual(1, len(events))

    def test_02_executor_success_plus_substituted_observation_is_mismatch_and_nonreusable_memory(self):
        path = self._path()
        state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
        self.addCleanup(self._safe_close, state)
        observation = self._observation(provider_request_id, domain="substituted.example")
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-mismatch",
        ).reconcile(governed, order, observation)

        self.assertEqual(("failure", "observed_domain_mismatch"), (result.outcome, result.reason))
        memory = GovernedDomainOutcomeMemoryProjection(kernel, custody).record(
            governed,
            order,
            observation,
            result,
        )
        self.assertEqual("RECONCILIATION_MISMATCH", memory.classification)
        self.assertFalse(memory.reusable)
        self.assertEqual(0, budget.spent_cents)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_03_executor_success_plus_incomplete_evidence_is_unknown_and_nonreusable_memory(self):
        path = self._path()
        state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
        self.addCleanup(self._safe_close, state)
        observation = self._observation(provider_request_id, owner_ref=None)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-unknown",
        ).reconcile(governed, order, observation)

        self.assertEqual(("unresolved", "success_observation_incomplete"), (result.outcome, result.reason))
        memory = GovernedDomainOutcomeMemoryProjection(kernel, custody).record(
            governed,
            order,
            observation,
            result,
        )
        self.assertEqual("EVIDENCE_FAILURE", memory.classification)
        self.assertFalse(memory.reusable)
        self.assertEqual(SQLiteGovernanceCustody.UNRESOLVED, custody.attempt(governed.attempt_id).state)

    def test_04_mismatch_and_unknown_state_and_memory_survive_restart_without_retry_authority(self):
        cases = (
            (
                "mismatch",
                {"domain": "substituted.example"},
                "failure",
                SQLiteGovernanceCustody.RECONCILED_FAILURE,
                "RECONCILIATION_MISMATCH",
            ),
            (
                "unknown",
                {"owner_ref": None},
                "unresolved",
                SQLiteGovernanceCustody.UNRESOLVED,
                "EVIDENCE_FAILURE",
            ),
        )
        for name, changes, expected_outcome, expected_state, expected_classification in cases:
            with self.subTest(name=name):
                path = self._path()
                state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
                observation = self._observation(provider_request_id, **changes)
                result = IndependentDomainReconciler(
                    custody,
                    budget,
                    observer_id=f"observer:issue-153:{name}",
                ).reconcile(governed, order, observation)
                memory = GovernedDomainOutcomeMemoryProjection(kernel, custody).record(
                    governed,
                    order,
                    observation,
                    result,
                )
                self.assertEqual(expected_classification, memory.classification)
                state.close()

                restarted_custody = SQLiteGovernanceCustody(
                    path,
                    signing_secret=CUSTODY_SECRET,
                    clock=lambda: NOW,
                )
                restarted_verifier = self._commerce_verifier()
                restarted_state = SQLiteKernelState(path)
                restarted_kernel = GovernanceKernel(
                    self._commerce_policy(restarted_verifier),
                    secret=KERNEL_SECRET,
                    approval_verifier=restarted_verifier,
                    clock=lambda: NOW,
                    state=restarted_state,
                )
                attempt = restarted_custody.attempt(governed.attempt_id)
                self.assertIsNotNone(attempt)
                self.assertEqual(expected_state, attempt.state)
                self.assertEqual(expected_outcome, attempt.reconciliation_outcome)

                remembered = GovernedDomainOutcomeMemoryProjection(
                    restarted_kernel,
                    restarted_custody,
                ).latest(governed.attempt_id)
                self.assertIsNotNone(remembered)
                self.assertEqual(expected_classification, remembered.classification)
                self.assertFalse(remembered.reusable)

                head = restarted_custody.snapshot()
                with self.assertRaises(CustodyViolation):
                    restarted_custody.claim_attempt(
                        expected_epoch=head.epoch,
                        expected_state_root=head.state_root,
                        attempt_id=governed.attempt_id,
                        executor_id="executor:retry-must-deny",
                    )
                with self.assertRaises(CommerceViolation):
                    SQLiteBudgetAccount(path).require_active(
                        governed.reservation_id,
                        order,
                        now_ns=NOW,
                    )
                self.assertTrue(restarted_kernel.verify_audit())
                restarted_state.close()

    def test_05_replay_substitution_expiry_revocation_and_widening_do_not_create_fresh_authority(self):
        basic = GovernanceKernel(
            Policy(frozenset({"write"}), 10),
            secret=b"issue-153-basic",
            clock=lambda: NOW,
            state=InMemoryKernelState(),
        )
        exact = Intent("agent:builder", "write", "repo:exact", 1)
        first = basic.evaluate(exact)
        self.assertEqual("allow", first.outcome)
        self.assertIsNotNone(first.permit)
        self.assertTrue(basic.consume(first.permit, exact))
        self.assertFalse(basic.consume(first.permit, exact))

        substituted = basic.evaluate(exact)
        self.assertIsNotNone(substituted.permit)
        self.assertFalse(
            basic.consume(
                substituted.permit,
                Intent("agent:builder", "write", "repo:substituted", 1),
            )
        )

        expiry_time = [NOW]
        expiry_kernel, expiry_verifier, _, expiry_directive = self._directive_kernel(
            expiry_time,
            directive_id="issue-153-expiry",
        )
        self._activate_directive(
            expiry_kernel,
            expiry_verifier,
            expiry_directive,
            approval_id="issue-153-expiry-activate",
            nonce="issue-153-expiry-activate-nonce",
        )
        expiry_projection = GovernedDirectiveProjection(expiry_kernel)
        expiry_intent = Intent("agent:builder", "write", "repo:exact", 1)
        expiry_decision = expiry_projection.evaluate(expiry_intent, expiry_directive)
        self.assertEqual("allow", expiry_decision.outcome)
        self.assertIsNotNone(expiry_decision.permit)
        expiry_time[0] = expiry_directive.expires_at_ns
        self.assertFalse(expiry_kernel.consume(expiry_decision.permit, expiry_intent))

        revoke_time = [NOW]
        revoke_kernel, revoke_verifier, _, revoke_directive = self._directive_kernel(
            revoke_time,
            directive_id="issue-153-revoke",
        )
        controller = self._activate_directive(
            revoke_kernel,
            revoke_verifier,
            revoke_directive,
            approval_id="issue-153-revoke-activate",
            nonce="issue-153-revoke-activate-nonce",
        )
        revoke_projection = GovernedDirectiveProjection(revoke_kernel)
        revoke_intent = Intent("agent:builder", "write", "repo:exact", 1)
        revoke_decision = revoke_projection.evaluate(revoke_intent, revoke_directive)
        self.assertEqual("allow", revoke_decision.outcome)
        self.assertIsNotNone(revoke_decision.permit)
        revoke_authority_intent = controller.authority_intent(
            controller.REVOKE,
            revoke_directive,
            operator_principal=OPERATOR,
        )
        revoke_envelope = signed_envelope(
            revoke_kernel,
            revoke_authority_intent,
            revoke_verifier,
            now_ns=NOW - 5,
            approval_id="issue-153-revoke-approval",
            nonce="issue-153-revoke-nonce",
        )
        self.assertEqual(
            "allow",
            controller.revoke(
                revoke_directive,
                revoke_envelope,
                operator_principal=OPERATOR,
            ).outcome,
        )
        self.assertFalse(revoke_kernel.consume(revoke_decision.permit, revoke_intent))

        widen_time = [NOW]
        widen_kernel, widen_verifier, _, parent = self._directive_kernel(
            widen_time,
            directive_id="issue-153-parent",
            max_cost=2,
        )
        widen_controller = self._activate_directive(
            widen_kernel,
            widen_verifier,
            parent,
            approval_id="issue-153-parent-activate",
            nonce="issue-153-parent-activate-nonce",
        )
        child = Directive(
            directive_id="issue-153-child",
            version=1,
            issuer_authority_id=parent.issuer_authority_id,
            principal=parent.principal,
            allowed_actions=parent.allowed_actions,
            resource_prefixes=parent.resource_prefixes,
            max_cost=3,
            issued_at_ns=parent.issued_at_ns,
            expires_at_ns=parent.expires_at_ns,
            parent_directive_hash=parent.directive_hash,
        )
        child_authority_intent = widen_controller.authority_intent(
            widen_controller.ACTIVATE,
            child,
            operator_principal=OPERATOR,
        )
        child_envelope = signed_envelope(
            widen_kernel,
            child_authority_intent,
            widen_verifier,
            now_ns=NOW - 5,
            approval_id="issue-153-child-activate",
            nonce="issue-153-child-activate-nonce",
        )
        widened = widen_controller.activate(
            child,
            child_envelope,
            operator_principal=OPERATOR,
            parent_directive=parent,
        )
        self.assertEqual(("deny", "directive_parent_budget_broadened"), (widened.outcome, widened.reason))

    def test_06_chat_retrieval_and_prior_success_are_not_authority_inputs(self):
        now_box = [NOW]
        kernel, verifier, _, directive = self._directive_kernel(
            now_box,
            directive_id="issue-153-memory-nonauthority",
            max_cost=1,
        )
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:exact", 1)
        self.assertEqual(
            ("intent", "directive"),
            tuple(inspect.signature(projection.evaluate).parameters),
        )
        before_activation = projection.evaluate(intent, directive)
        self.assertEqual(("deny", "directive_not_authorized"), (before_activation.outcome, before_activation.reason))

        self._activate_directive(
            kernel,
            verifier,
            directive,
            approval_id="issue-153-memory-activate",
            nonce="issue-153-memory-activate-nonce",
        )
        over_scope = projection.evaluate(
            Intent("agent:builder", "write", "repo:exact", 2),
            directive,
        )
        self.assertEqual(("deny", "directive_budget_exceeded"), (over_scope.outcome, over_scope.reason))

    def test_07_outcome_memory_rejects_result_substitution_and_conflicting_replacement(self):
        path = self._path()
        state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
        self.addCleanup(self._safe_close, state)
        observation = self._observation(provider_request_id)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-substitution",
        ).reconcile(governed, order, observation)
        projection = GovernedDomainOutcomeMemoryProjection(kernel, custody)
        memory = projection.record(governed, order, observation, result)
        self.assertEqual("SUCCESS_VERIFIED", memory.classification)

        substituted_result = replace(result, reason="executor_claimed_success")
        with self.assertRaisesRegex(CustodyViolation, "outcome_memory_reconciliation_result_mismatch"):
            projection.record(governed, order, observation, substituted_result)

        conflicting_observation = replace(observation, observation_id="issue-153-conflicting-observation")
        with self.assertRaisesRegex(CustodyViolation, "outcome_memory_persisted_reconciliation_mismatch"):
            projection.record(governed, order, conflicting_observation, result)

    def test_08_independently_observed_provider_failure_is_failure_class_memory_not_success(self):
        path = self._path()
        state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
        self.addCleanup(self._safe_close, state)
        observation = self._observation(
            provider_request_id,
            provider_request_status="failed",
            registered=False,
            payment_id=None,
            charged_cents=0,
            receipt_hash=None,
            privacy_enabled=None,
            dns_state=None,
        )
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-provider-failure",
        ).reconcile(governed, order, observation)
        self.assertEqual(("failure", "provider_failure_independently_observed"), (result.outcome, result.reason))
        memory = GovernedDomainOutcomeMemoryProjection(kernel, custody).record(
            governed,
            order,
            observation,
            result,
        )
        self.assertEqual("RECONCILIATION_FAILURE", memory.classification)
        self.assertFalse(memory.reusable)

    def test_09_successful_outcome_memory_cannot_authorize_an_otherwise_denied_intent(self):
        path = self._path()
        state, kernel, custody, budget, governed, order, provider_request_id, _ = self._stack(path)
        self.addCleanup(self._safe_close, state)
        observation = self._observation(provider_request_id)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-memory-authority",
        ).reconcile(governed, order, observation)
        memory = GovernedDomainOutcomeMemoryProjection(kernel, custody).record(
            governed,
            order,
            observation,
            result,
        )
        self.assertTrue(memory.reusable)

        denied = kernel.evaluate(
            Intent(
                principal="agent:commerce",
                action="deploy",
                resource="infra:production",
                cost=0,
            )
        )
        self.assertEqual(("deny", "action_not_allowed"), (denied.outcome, denied.reason))
        self.assertIsNone(denied.permit)


if __name__ == "__main__":
    unittest.main()

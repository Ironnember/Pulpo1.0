import inspect
import tempfile
import unittest
from pathlib import Path

import pulpo
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
from pulpo.custody_reconcile import IndependentDomainObservation, IndependentDomainReconciler
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 23_000_000
CUSTODY_SECRET = b"issue-153-custody"
KERNEL_SECRET = b"issue-153-kernel"
OPERATOR = "operator:owner"


class Issue153ConsequenceReconciliationV0(unittest.TestCase):
    """Compose current canonical seams into the Issue #153 hostile matrix.

    This test file intentionally adds no production component. The final test is
    a deliberate red sentinel if current canonical code has no legitimate
    reconciliation-to-successful-outcome-memory gate. That gap must be exposed,
    not filled by a test-only memory object.
    """

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

    def _stack(self, path: Path):
        custody = SQLiteGovernanceCustody(
            path,
            signing_secret=CUSTODY_SECRET,
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(path)
        state = SQLiteKernelState(path)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=KERNEL_SECRET,
            clock=lambda: NOW,
            state=state,
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
        order = assess_quote(
            request,
            quote,
            credential_ref="credential://issue-153/executor",
            now_ns=NOW,
        ).order
        self.assertIsNotNone(order)
        intent = purchase_intent(order)
        target = kernel.lock_target("issue-153-target-v0", intent)
        decision = kernel.evaluate(intent)
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
        return state, kernel, custody, budget, governed, order, provider_request_id

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
    def _directive(now_box, *, directive_id: str = "issue-153-directive", max_cost: int = 2):
        verifier = HmacTestVerifier(secret=b"issue-153-test-authority")
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            policy,
            secret=b"issue-153-directive-kernel",
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

    def _activate(self, kernel, verifier, directive, *, approval_id: str, nonce: str):
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
        decision = controller.activate(directive, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return controller

    def test_01_exact_independent_observation_is_verified_success(self):
        path = self._path()
        state, _, custody, budget, governed, order, provider_request_id = self._stack(path)
        self.addCleanup(self._safe_close, state)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153",
        ).reconcile(governed, order, self._observation(provider_request_id))

        self.assertEqual(("success", "external_consequence_verified"), (result.outcome, result.reason))
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILED_SUCCESS,
            custody.attempt(governed.attempt_id).state,
        )
        self.assertEqual(2_000, budget.spent_cents)
        self.assertEqual(0, budget.reserved_cents)

    def test_02_executor_success_plus_substituted_observation_is_mismatch_failure(self):
        path = self._path()
        state, _, custody, budget, governed, order, provider_request_id = self._stack(path)
        self.addCleanup(self._safe_close, state)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153",
        ).reconcile(
            governed,
            order,
            self._observation(provider_request_id, domain="substituted.example"),
        )

        self.assertEqual(("failure", "observed_domain_mismatch"), (result.outcome, result.reason))
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILED_FAILURE,
            custody.attempt(governed.attempt_id).state,
        )
        self.assertEqual(0, budget.spent_cents)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_03_executor_success_plus_incomplete_evidence_remains_unknown(self):
        path = self._path()
        state, _, custody, budget, governed, order, provider_request_id = self._stack(path)
        self.addCleanup(self._safe_close, state)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153",
        ).reconcile(
            governed,
            order,
            self._observation(provider_request_id, owner_ref=None),
        )

        self.assertEqual(("unresolved", "success_observation_incomplete"), (result.outcome, result.reason))
        self.assertEqual(SQLiteGovernanceCustody.UNRESOLVED, custody.attempt(governed.attempt_id).state)
        self.assertEqual(0, budget.spent_cents)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_04_mismatch_and_unknown_survive_restart_without_retry_authority(self):
        cases = (
            ("mismatch", {"domain": "substituted.example"}, "failure", SQLiteGovernanceCustody.RECONCILED_FAILURE),
            ("unknown", {"owner_ref": None}, "unresolved", SQLiteGovernanceCustody.UNRESOLVED),
        )
        for name, changes, expected_outcome, expected_state in cases:
            with self.subTest(name=name):
                path = self._path()
                state, _, custody, budget, governed, order, provider_request_id = self._stack(path)
                result = IndependentDomainReconciler(
                    custody,
                    budget,
                    observer_id=f"observer:issue-153:{name}",
                ).reconcile(governed, order, self._observation(provider_request_id, **changes))
                self.assertEqual(expected_outcome, result.outcome)
                state.close()

                restarted_custody = SQLiteGovernanceCustody(
                    path,
                    signing_secret=CUSTODY_SECRET,
                    clock=lambda: NOW,
                )
                restarted_budget = SQLiteBudgetAccount(path)
                attempt = restarted_custody.attempt(governed.attempt_id)
                self.assertIsNotNone(attempt)
                self.assertEqual(expected_state, attempt.state)
                self.assertEqual(expected_outcome, attempt.reconciliation_outcome)
                self.assertEqual(2_000, restarted_budget.reserved_cents)

                head = restarted_custody.snapshot()
                with self.assertRaises(CustodyViolation):
                    restarted_custody.claim_attempt(
                        expected_epoch=head.epoch,
                        expected_state_root=head.state_root,
                        attempt_id=governed.attempt_id,
                        executor_id="executor:retry-must-deny",
                    )
                with self.assertRaises(CommerceViolation):
                    restarted_budget.require_active(
                        governed.reservation_id,
                        order,
                        now_ns=NOW,
                    )

                restarted_state = SQLiteKernelState(path)
                restarted_kernel = GovernanceKernel(
                    Policy(frozenset({"purchase_domain"}), 3_000),
                    secret=KERNEL_SECRET,
                    clock=lambda: NOW,
                    state=restarted_state,
                )
                self.assertTrue(restarted_kernel.verify_audit())
                restarted_state.close()

    def test_05_replay_substitution_expiry_and_revocation_do_not_create_fresh_authority(self):
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
        expiry_kernel, expiry_verifier, _, expiry_directive = self._directive(
            expiry_time,
            directive_id="issue-153-expiry",
        )
        self._activate(
            expiry_kernel,
            expiry_verifier,
            expiry_directive,
            approval_id="issue-153-activate-expiry",
            nonce="issue-153-activate-expiry-nonce",
        )
        expiry_projection = GovernedDirectiveProjection(expiry_kernel)
        expiry_intent = Intent("agent:builder", "write", "repo:exact", 1)
        expiry_decision = expiry_projection.evaluate(expiry_intent, expiry_directive)
        self.assertEqual("allow", expiry_decision.outcome)
        self.assertIsNotNone(expiry_decision.permit)
        expiry_time[0] = expiry_directive.expires_at_ns
        self.assertFalse(expiry_kernel.consume(expiry_decision.permit, expiry_intent))

        revoke_time = [NOW]
        revoke_kernel, revoke_verifier, _, revoke_directive = self._directive(
            revoke_time,
            directive_id="issue-153-revoke",
        )
        controller = self._activate(
            revoke_kernel,
            revoke_verifier,
            revoke_directive,
            approval_id="issue-153-activate-revoke",
            nonce="issue-153-activate-revoke-nonce",
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

    def test_06_chat_retrieval_and_prior_success_are_not_authority_inputs(self):
        now_box = [NOW]
        kernel, verifier, _, directive = self._directive(
            now_box,
            directive_id="issue-153-memory-nonauthority",
            max_cost=1,
        )
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:exact", 1)

        # The projection has no chat, retrieval-score, prior-success, or model
        # summary input that can be converted into authority.
        self.assertEqual(
            ("intent", "directive"),
            tuple(inspect.signature(projection.evaluate).parameters),
        )
        before_activation = projection.evaluate(intent, directive)
        self.assertEqual(("deny", "directive_not_authorized"), (before_activation.outcome, before_activation.reason))

        self._activate(
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

    def test_07_successful_outcome_memory_requires_a_canonical_reconciliation_gate(self):
        # Canonical Pulpo currently exposes file-artifact target completion, but
        # that is not a consequence outcome-memory admission gate. The canonical
        # Outcome Learning Protocol requires successful reusable completion paths
        # to follow reconciliation-supported success. Do not manufacture a test
        # double or infer that missing seam from custody state.
        self.assertTrue(hasattr(pulpo, "GovernedTargetReconciliation"))
        self.assertFalse(hasattr(pulpo, "OutcomeMemory"))
        self.fail(
            "issue_153_gap: current canonical runtime has no explicit governed "
            "consequence-reconciliation -> successful outcome-memory/reusable-path "
            "admission seam; keep this proof red/held until that exact gap is "
            "implemented through the existing governance/evidence path"
        )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_reconcile import IndependentDomainObservation, IndependentDomainReconciler
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState


NOW = 17_000_000


class LaterEvidenceReconciliationTests(unittest.TestCase):
    def test_unresolved_consequence_can_later_resolve_without_reopening_execution(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))

        custody = SQLiteGovernanceCustody(
            path,
            signing_secret=b"later-evidence-custody",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(path)
        state = SQLiteKernelState(path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"later-evidence-kernel",
            clock=lambda: NOW,
            state=state,
        )
        request = DomainPurchaseRequest(
            request_id="later-evidence-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-later-evidence.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="later-evidence-quote-v0",
            domain="pulpo-later-evidence.example",
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
            credential_ref="credential://name-com/custody",
            now_ns=NOW,
        ).order
        self.assertIsNotNone(order)
        intent = purchase_intent(order)
        target = kernel.lock_target("later-evidence-target", intent)
        decision = kernel.evaluate(intent)
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
            executor_id="executor:domain-v0",
        )
        head = custody.snapshot()
        provider_request_id = f"domain:{governed.attempt_id}:preflight:{'b' * 64}"
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

        reconciler = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:later-evidence",
        )
        unresolved = IndependentDomainObservation(
            observation_id="obs:initial",
            provider_request_id=provider_request_id,
            provider_request_status="unknown",
            domain=None,
            registrar=None,
            owner_ref=None,
            registered=None,
            payment_id=None,
            charged_cents=None,
            receipt_hash=None,
            privacy_enabled=None,
            dns_state=None,
            auto_renew_enabled=None,
        )
        first = reconciler.reconcile(governed, order, unresolved)
        self.assertEqual("unresolved", first.outcome)
        self.assertEqual(SQLiteGovernanceCustody.UNRESOLVED, custody.attempt(governed.attempt_id).state)
        self.assertEqual(2_000, budget.reserved_cents)

        later = IndependentDomainObservation(
            observation_id="obs:later",
            provider_request_id=provider_request_id,
            provider_request_status="succeeded",
            domain=order.domain,
            registrar="name.com",
            owner_ref=order.owner_ref,
            registered=True,
            payment_id="namecom-order:987",
            charged_cents=2_000,
            receipt_hash="c" * 64,
            privacy_enabled=True,
            dns_state="registered",
            auto_renew_enabled=order.auto_renew_enabled,
        )
        second = reconciler.reconcile(governed, order, later)
        self.assertEqual("success", second.outcome)
        self.assertEqual(SQLiteGovernanceCustody.RECONCILED_SUCCESS, custody.attempt(governed.attempt_id).state)
        self.assertEqual(2_000, budget.spent_cents)
        self.assertEqual(0, budget.reserved_cents)

        # Later evidence resolves truth only. It does not recreate an execution
        # path from the already-transmitted attempt.
        self.assertNotIn(
            custody.attempt(governed.attempt_id).state,
            {SQLiteGovernanceCustody.ATTEMPT_AUTHORIZED, SQLiteGovernanceCustody.ATTEMPT_CLAIMED},
        )


if __name__ == "__main__":
    unittest.main()

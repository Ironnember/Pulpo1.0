import tempfile
import unittest
from pathlib import Path

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_executor import ExternalConsequenceUnknown, TrustedDomainExecutor
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState


NOW = 11_000_000


class FakeCustodyRegistrar:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.calls = 0
        self.idempotency_keys = []

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        self.calls += 1
        self.idempotency_keys.append(idempotency_key)
        if self.fail:
            raise RuntimeError("simulated lost provider response")
        return RegistrarResult(
            payment_id="payment-v0",
            charged_cents=min(order.purchase_price_cents, max_charge_cents),
            receipt_hash="a" * 64,
            registration_id="registration-v0",
            domain=order.domain,
            registrar=order.registrar,
        )


class CustodyExecutorTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def order(self, domain="pulpo-hostile-executor.example"):
        request = DomainPurchaseRequest(
            request_id=f"executor-request-v0:{domain}",
            principal="agent:commerce",
            acceptable_domains=(domain,),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id=f"executor-quote:{domain}",
            domain=domain,
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
            credential_ref="credential://name-com/hostile-worker-v0",
            now_ns=NOW,
        )
        self.assertIsNotNone(assessment.order)
        return assessment.order

    def governed_attempt(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"trusted-executor-custody",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(self.path)
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"trusted-executor-kernel",
            clock=lambda: NOW,
            state=state,
        )
        order = self.order()
        intent = purchase_intent(order)
        target = kernel.lock_target("trusted-executor-v0", intent)
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody, budget)
        reservation = coordinator.reserve(order)
        governed = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
            reservation_id=reservation.reservation_id,
        )
        return custody, budget, governed, order

    def test_provider_success_is_only_a_claim_and_still_requires_reconciliation(self):
        custody, budget, governed, order = self.governed_attempt()
        adapter = FakeCustodyRegistrar()
        claim = TrustedDomainExecutor(custody, executor_id="executor:domain-v0").execute(
            governed, order, adapter
        )
        self.assertEqual(1, adapter.calls)
        self.assertEqual([governed.attempt_id], adapter.idempotency_keys)
        self.assertTrue(claim.reconciliation_required)
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            custody.attempt(governed.attempt_id).state,
        )
        self.assertIsNone(custody.attempt(governed.attempt_id).reconciliation_outcome)
        self.assertEqual(1_000, budget.available_cents)

    def test_lost_provider_response_is_unknown_and_cannot_retry_or_release_budget(self):
        custody, budget, governed, order = self.governed_attempt()
        adapter = FakeCustodyRegistrar(fail=True)
        executor = TrustedDomainExecutor(custody, executor_id="executor:domain-v0")
        with self.assertRaisesRegex(ExternalConsequenceUnknown, governed.attempt_id):
            executor.execute(governed, order, adapter)
        self.assertEqual(1, adapter.calls)
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            custody.attempt(governed.attempt_id).state,
        )
        self.assertEqual(1_000, budget.available_cents)
        with self.assertRaisesRegex(CustodyViolation, "attempt_not_executable"):
            executor.execute(governed, order, adapter)
        self.assertEqual(1, adapter.calls)

    def test_crash_before_transmission_can_resume_same_executor_identity_only(self):
        custody, _, governed, order = self.governed_attempt()
        head = custody.snapshot()
        custody.claim_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            executor_id="executor:domain-v0",
        )
        wrong = FakeCustodyRegistrar()
        with self.assertRaisesRegex(CustodyViolation, "attempt_not_executable"):
            TrustedDomainExecutor(custody, executor_id="executor:other").execute(governed, order, wrong)
        self.assertEqual(0, wrong.calls)
        adapter = FakeCustodyRegistrar()
        TrustedDomainExecutor(custody, executor_id="executor:domain-v0").execute(governed, order, adapter)
        self.assertEqual(1, adapter.calls)
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            custody.attempt(governed.attempt_id).state,
        )

    def test_crash_after_transmission_release_never_releases_second_network_right(self):
        custody, _, governed, order = self.governed_attempt()
        head = custody.snapshot()
        custody.claim_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            executor_id="executor:domain-v0",
        )
        head = custody.snapshot()
        custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=f"domain:{governed.attempt_id}",
        )
        adapter = FakeCustodyRegistrar()
        with self.assertRaisesRegex(CustodyViolation, "attempt_not_executable"):
            TrustedDomainExecutor(custody, executor_id="executor:domain-v0").execute(governed, order, adapter)
        self.assertEqual(0, adapter.calls)
        self.assertEqual(
            SQLiteGovernanceCustody.REQUEST_TRANSMITTED,
            custody.attempt(governed.attempt_id).state,
        )
        head = custody.snapshot()
        custody.require_reconciliation(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
        )
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            custody.attempt(governed.attempt_id).state,
        )

    def test_substituted_order_never_reaches_credential_adapter(self):
        custody, _, governed, _ = self.governed_attempt()
        substituted = self.order("pulpo-executor-substitute.example")
        adapter = FakeCustodyRegistrar()
        with self.assertRaisesRegex(CustodyViolation, "executor_order_mismatch"):
            TrustedDomainExecutor(custody, executor_id="executor:domain-v0").execute(
                governed, substituted, adapter
            )
        self.assertEqual(0, adapter.calls)
        self.assertEqual(
            SQLiteGovernanceCustody.ATTEMPT_AUTHORIZED,
            custody.attempt(governed.attempt_id).state,
        )


if __name__ == "__main__":
    unittest.main()

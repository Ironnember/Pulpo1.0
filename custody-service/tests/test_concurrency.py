import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    SQLiteBudgetAccount,
    assess_quote,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState

from pulpo_custody_service.core import DomainCustodyService, ServiceRejected


NOW = 41_000_000


class UnusedRegistrar:
    def preflight(self, order):
        return "a" * 64

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        return RegistrarResult(
            payment_id="unused",
            charged_cents=order.purchase_price_cents,
            receipt_hash="b" * 64,
            registration_id="unused",
            domain=order.domain,
            registrar=order.registrar,
        )


class UnusedObserver:
    def observe(self, governed, order):
        raise AssertionError("observer should not run in authorization race proof")


class CustodyServiceConcurrencyTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def order(self):
        request = DomainPurchaseRequest(
            request_id="service-race-v0",
            principal="agent:hostile-worker",
            acceptable_domains=("pulpo-race.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="service-race-quote-v0",
            domain="pulpo-race.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        result = assess_quote(
            request,
            quote,
            credential_ref="credential://service/namecom",
            now_ns=NOW,
        )
        self.assertIsNotNone(result.order)
        return result.order

    def service(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"service-race-custody",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(self.path)
        policy = Policy(frozenset({"purchase_domain"}), 3_000)

        def kernel_factory():
            state = SQLiteKernelState(self.path)
            try:
                return GovernanceKernel(
                    policy,
                    secret=b"service-race-kernel",
                    clock=lambda: NOW,
                    state=state,
                )
            except Exception:
                state.close()
                raise

        service = DomainCustodyService(
            kernel_factory=kernel_factory,
            custody=custody,
            budget=budget,
            registrar=UnusedRegistrar(),
            observer=UnusedObserver(),
            observer_id="observer:service-race-v0",
            executor_id="executor:service-race-v0",
        )
        return service, custody, budget

    def test_two_callers_same_exact_order_create_one_authoritative_attempt(self):
        service, custody, budget = self.service()
        order = self.order()

        def authorize_once():
            try:
                return "ok", service.authorize(order)
            except ServiceRejected as exc:
                return "rejected", str(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: authorize_once(), range(2)))

        successes = [value for status, value in results if status == "ok"]
        rejections = [value for status, value in results if status == "rejected"]
        self.assertEqual(1, len(successes), results)
        self.assertEqual(1, len(rejections), results)

        handle = successes[0]
        attempt = custody.attempt(handle.attempt_id)
        self.assertIsNotNone(attempt)
        self.assertEqual(custody.ATTEMPT_AUTHORIZED, attempt.state)
        self.assertEqual(order.order_hash, attempt.object_hash)
        self.assertEqual(1, custody.snapshot().epoch)
        self.assertEqual(order.purchase_price_cents, budget.reserved_cents)
        self.assertEqual(1_000, budget.available_cents)

        with self.assertRaises(ServiceRejected):
            service.authorize(order)
        self.assertEqual(1, custody.snapshot().epoch)
        self.assertEqual(order.purchase_price_cents, budget.reserved_cents)


if __name__ == "__main__":
    unittest.main()

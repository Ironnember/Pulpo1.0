import json
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
from pulpo.custody_reconcile import IndependentDomainReconciler
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.namecom_core import NameComCoreClient, NameComCoreConfig, NameComResponse
from pulpo.namecom_observer import NameComCoreObserver
from pulpo.state import SQLiteKernelState


NOW = 25_000_000


class SequenceTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError("unexpected provider observation request")
        return self.responses.pop(0)


def response(payload, status=200):
    return NameComResponse(
        status=status,
        headers={},
        body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )


def registration_order(domain, *, order_id=321, status="success", total_capture=20.0):
    return {
        "id": order_id,
        "status": status,
        "totalCapture": total_capture,
        "orderItems": [
            {
                "id": order_id * 10,
                "type": "registration",
                "name": domain,
                "status": status,
                "price": total_capture,
                "quantity": 1,
                "duration": 1,
                "interval": "year",
                "isRefundable": False,
            }
        ],
    }


class NameComObserverTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def stack(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"namecom-observer-custody",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(self.path)
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"namecom-observer-kernel",
            clock=lambda: NOW,
            state=state,
        )
        request = DomainPurchaseRequest(
            request_id="observer-request-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-observer.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="observer-quote-v0",
            domain="pulpo-observer.example",
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
            credential_ref="credential://name-com/executor",
            now_ns=NOW,
        ).order
        self.assertIsNotNone(order)
        intent = purchase_intent(order)
        target = kernel.lock_target("observer-domain-v0", intent)
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
            executor_id="executor:namecom-v0",
        )
        head = custody.snapshot()
        custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=f"domain:{governed.attempt_id}",
        )
        head = custody.snapshot()
        custody.require_reconciliation(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
        )
        return custody, budget, governed, order

    def observer(self, custody, responses):
        transport = SequenceTransport(responses)
        client = NameComCoreClient(
            NameComCoreConfig("pulpo-observer-test", "observer-token"),
            transport=transport,
        )
        return (
            NameComCoreObserver(
                custody,
                client,
                owner_ref="owner://iron-ember",
                observation_id_prefix="observer-test",
            ),
            transport,
        )

    def test_exact_order_and_get_domain_readback_can_drive_verified_reconciliation(self):
        custody, budget, governed, order = self.stack()
        provider_order = registration_order(order.domain)
        observer, transport = self.observer(
            custody,
            [
                response({"totalCount": 1, "orders": [provider_order]}),
                response(
                    {
                        "domainName": order.domain,
                        "autorenewEnabled": False,
                        "locked": True,
                        "privacyEnabled": True,
                        "contacts": {},
                        "nameservers": ["ns1.name.com", "ns2.name.com"],
                        "locks": ["clientTransferProhibited"],
                        "renewalPrice": 24.0,
                    }
                ),
            ],
        )
        observation = observer.observe(governed, order)

        self.assertEqual("succeeded", observation.provider_request_status)
        self.assertTrue(observation.registered)
        self.assertEqual("namecom-order:321", observation.payment_id)
        self.assertEqual(2_000, observation.charged_cents)
        self.assertEqual("owner://iron-ember", observation.owner_ref)
        self.assertTrue(observation.privacy_enabled)
        self.assertEqual("registered", observation.dns_state)
        self.assertEqual(2, len(transport.calls))

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("success", result.outcome)
        self.assertEqual(2_000, budget.spent_cents)
        self.assertEqual(0, budget.reserved_cents)

    def test_success_order_without_domain_readback_stays_unknown(self):
        custody, budget, governed, order = self.stack()
        observer, _ = self.observer(
            custody,
            [
                response({"totalCount": 1, "orders": [registration_order(order.domain)]}),
                response({"message": "not found"}, status=404),
            ],
        )
        observation = observer.observe(governed, order)
        self.assertEqual("unknown", observation.provider_request_status)
        self.assertFalse(observation.registered)

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("unresolved", result.outcome)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_ambiguous_multiple_registration_orders_never_guess_attribution(self):
        custody, budget, governed, order = self.stack()
        observer, _ = self.observer(
            custody,
            [
                response(
                    {
                        "totalCount": 2,
                        "orders": [
                            registration_order(order.domain, order_id=321),
                            registration_order(order.domain, order_id=322),
                        ],
                    }
                ),
                response(
                    {
                        "domainName": order.domain,
                        "autorenewEnabled": False,
                        "locked": True,
                        "privacyEnabled": True,
                        "contacts": {},
                        "nameservers": [],
                        "locks": [],
                        "renewalPrice": 24.0,
                    }
                ),
            ],
        )
        observation = observer.observe(governed, order)
        self.assertEqual("unknown", observation.provider_request_status)
        self.assertIsNone(observation.payment_id)
        self.assertIsNone(observation.charged_cents)

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("unresolved", result.outcome)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_failed_registration_order_with_no_domain_readback_is_known_failure(self):
        custody, budget, governed, order = self.stack()
        observer, _ = self.observer(
            custody,
            [
                response(
                    {
                        "totalCount": 1,
                        "orders": [registration_order(order.domain, status="failed", total_capture=0.0)],
                    }
                ),
                response({"message": "not found"}, status=404),
            ],
        )
        observation = observer.observe(governed, order)
        self.assertEqual("failed", observation.provider_request_status)
        self.assertFalse(observation.registered)
        self.assertEqual(0, observation.charged_cents)

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("failure", result.outcome)
        # V0 deliberately does not reopen budget on failure until an explicit
        # no-charge release transition is separately governed.
        self.assertEqual(2_000, budget.reserved_cents)

    def test_non_registration_order_for_same_domain_is_ignored(self):
        custody, budget, governed, order = self.stack()
        unrelated = registration_order(order.domain)
        unrelated["orderItems"][0]["type"] = "renewal"
        observer, _ = self.observer(
            custody,
            [
                response({"totalCount": 1, "orders": [unrelated]}),
                response({"message": "not found"}, status=404),
            ],
        )
        observation = observer.observe(governed, order)
        self.assertEqual("unknown", observation.provider_request_status)
        self.assertIsNone(observation.payment_id)

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("unresolved", result.outcome)


if __name__ == "__main__":
    unittest.main()

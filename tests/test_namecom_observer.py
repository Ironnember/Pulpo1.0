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
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
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

    def stack(self, *, provider_reference="namecom-order:321"):
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
        local_request_id = f"domain:{governed.attempt_id}:preflight:{'b' * 64}"
        custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=local_request_id,
        )
        head = custody.snapshot()
        if provider_reference is None:
            custody.require_reconciliation(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                attempt_id=governed.attempt_id,
            )
        else:
            custody._transition_attempt(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                attempt_id=governed.attempt_id,
                required_states=frozenset({custody.REQUEST_TRANSMITTED}),
                next_state=custody.RECONCILIATION_REQUIRED,
                payload={
                    "reason": "external_consequence_not_yet_verified",
                    "provider_request_id": provider_reference,
                    "provider_identity_source": "provider_response",
                },
                updates={"provider_request_id": provider_reference},
            )
        return custody, budget, governed, order, local_request_id

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

    @staticmethod
    def domain_record(domain):
        return {
            "domainName": domain,
            "autorenewEnabled": False,
            "locked": True,
            "privacyEnabled": True,
            "contacts": {},
            "nameservers": ["ns1.name.com", "ns2.name.com"],
            "locks": ["clientTransferProhibited"],
            "renewalPrice": 24.0,
        }

    def test_exact_provider_order_id_and_domain_readback_drive_verified_reconciliation(self):
        custody, budget, governed, order, _ = self.stack()
        provider_order = registration_order(order.domain, order_id=321)
        observer, transport = self.observer(
            custody,
            [response(provider_order), response(self.domain_record(order.domain))],
        )
        observation = observer.observe(governed, order)

        self.assertEqual("namecom-order:321", observation.provider_request_id)
        self.assertEqual("succeeded", observation.provider_request_status)
        self.assertTrue(observation.registered)
        self.assertEqual("namecom-order:321", observation.payment_id)
        self.assertEqual(2_000, observation.charged_cents)
        self.assertEqual("owner://iron-ember", observation.owner_ref)
        self.assertTrue(observation.privacy_enabled)
        self.assertFalse(observation.auto_renew_enabled)
        self.assertEqual("registered", observation.dns_state)
        self.assertEqual(
            [
                "https://api.dev.name.com/core/v1/orders/321",
                f"https://api.dev.name.com/core/v1/domains/{order.domain}",
            ],
            [call[1] for call in transport.calls],
        )

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("success", result.outcome)
        self.assertEqual(2_000, budget.spent_cents)
        self.assertEqual(0, budget.reserved_cents)

    def test_missing_provider_native_reference_stays_unknown_without_provider_lookup(self):
        custody, budget, governed, order, local_request_id = self.stack(
            provider_reference=None
        )
        observer, transport = self.observer(custody, [])
        observation = observer.observe(governed, order)

        self.assertEqual(local_request_id, observation.provider_request_id)
        self.assertEqual("unknown", observation.provider_request_status)
        self.assertIsNone(observation.payment_id)
        self.assertEqual([], transport.calls)

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("unresolved", result.outcome)
        self.assertEqual("provider_status_unknown", result.reason)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_provider_order_id_mismatch_cannot_manufacture_success(self):
        custody, _, governed, order, _ = self.stack(provider_reference="namecom-order:322")
        observer, transport = self.observer(
            custody,
            [response(registration_order(order.domain, order_id=321))],
        )
        with self.assertRaisesRegex(
            CustodyViolation,
            "namecom_observer_provider_order_id_mismatch",
        ):
            observer.observe(governed, order)
        self.assertEqual(1, len(transport.calls))

    def test_provider_order_object_mismatch_cannot_manufacture_success(self):
        custody, _, governed, order, _ = self.stack()
        wrong = registration_order("wrong.example", order_id=321)
        observer, transport = self.observer(custody, [response(wrong)])
        with self.assertRaisesRegex(
            CustodyViolation,
            "namecom_observer_provider_order_object_mismatch",
        ):
            observer.observe(governed, order)
        self.assertEqual(1, len(transport.calls))

    def test_provider_order_type_mismatch_cannot_manufacture_success(self):
        custody, _, governed, order, _ = self.stack()
        wrong = registration_order(order.domain, order_id=321)
        wrong["orderItems"][0]["type"] = "renewal"
        observer, transport = self.observer(custody, [response(wrong)])
        with self.assertRaisesRegex(
            CustodyViolation,
            "namecom_observer_provider_order_object_mismatch",
        ):
            observer.observe(governed, order)
        self.assertEqual(1, len(transport.calls))

    def test_exact_provider_order_not_found_stays_unresolved(self):
        custody, budget, governed, order, _ = self.stack()
        observer, transport = self.observer(
            custody,
            [response({"message": "not found"}, status=404)],
        )
        observation = observer.observe(governed, order)
        self.assertEqual("not_found", observation.provider_request_status)
        self.assertFalse(observation.registered is True)
        self.assertEqual(1, len(transport.calls))

        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:namecom-core-readback",
        ).reconcile(governed, order, observation)
        self.assertEqual("unresolved", result.outcome)
        self.assertEqual("provider_request_not_found", result.reason)
        self.assertEqual(2_000, budget.reserved_cents)

    def test_success_order_without_domain_readback_stays_unknown(self):
        custody, budget, governed, order, _ = self.stack()
        observer, _ = self.observer(
            custody,
            [
                response(registration_order(order.domain, order_id=321)),
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

    def test_failed_exact_order_with_no_domain_readback_is_known_failure(self):
        custody, budget, governed, order, _ = self.stack()
        observer, _ = self.observer(
            custody,
            [
                response(
                    registration_order(
                        order.domain,
                        order_id=321,
                        status="failed",
                        total_capture=0.0,
                    )
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
        self.assertEqual(2_000, budget.reserved_cents)


if __name__ == "__main__":
    unittest.main()

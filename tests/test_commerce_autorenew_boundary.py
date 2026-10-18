from __future__ import annotations

from dataclasses import replace
import unittest

from pulpo.commerce import (
    BudgetAccount,
    CommerceOutcome,
    CommerceViolation,
    DeliveryEvidence,
    DomainCommerceExecutor,
    DomainPurchaseOrder,
    DomainPurchaseRequest,
    DomainQuote,
    PaymentEvidence,
    VerificationEvidence,
    accept_delivery,
    assess_quote,
    purchase_intent,
)
from pulpo.custody_reconcile import IndependentDomainObservation
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.namecom_core import NameComCoreRegistrarAdapter, NameComViolation


NOW = 41_000_000


class NeverCalledRegistrar:
    def __init__(self) -> None:
        self.calls = 0

    def purchase(self, order, *, max_charge_cents):
        del order, max_charge_cents
        self.calls += 1
        raise AssertionError("substituted renewal state must not reach provider")


class CommerceAutoRenewGovernedEffectTests(unittest.TestCase):
    def request(self, *, auto_renew_enabled=False) -> DomainPurchaseRequest:
        return DomainPurchaseRequest(
            request_id="autorenew-boundary-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-autorenew.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
            auto_renew_enabled=auto_renew_enabled,
        )

    def quote(self) -> DomainQuote:
        return DomainQuote(
            quote_id="autorenew-quote-v0",
            domain="pulpo-autorenew.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )

    def order(self, *, auto_renew_enabled=False) -> DomainPurchaseOrder:
        assessment = assess_quote(
            self.request(auto_renew_enabled=auto_renew_enabled),
            self.quote(),
            credential_ref="credential://name-com/autorenew-v0",
            now_ns=NOW,
        )
        self.assertIsNotNone(assessment.order)
        return assessment.order

    def test_request_order_and_observer_schemas_bind_auto_renew_state(self) -> None:
        for schema in (
            DomainPurchaseRequest,
            DomainPurchaseOrder,
            VerificationEvidence,
            IndependentDomainObservation,
        ):
            with self.subTest(schema=schema.__name__):
                self.assertIn("auto_renew_enabled", schema.__dataclass_fields__)

    def test_pilot_defaults_auto_renew_off_and_rejects_truthy_non_boolean(self) -> None:
        self.assertFalse(self.request().auto_renew_enabled)
        with self.assertRaisesRegex(CommerceViolation, "auto_renew_enabled must be boolean"):
            self.request(auto_renew_enabled="false")  # type: ignore[arg-type]

    def test_auto_renew_changes_request_order_hash_and_permit_binding(self) -> None:
        off_request = self.request(auto_renew_enabled=False)
        on_request = self.request(auto_renew_enabled=True)
        off_order = self.order(auto_renew_enabled=False)
        on_order = self.order(auto_renew_enabled=True)

        self.assertNotEqual(off_request.request_hash, on_request.request_hash)
        self.assertNotEqual(off_order.order_hash, on_order.order_hash)
        self.assertFalse(off_order.auto_renew_enabled)
        self.assertTrue(on_order.auto_renew_enabled)

        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"autorenew-permit-boundary",
            clock=lambda: NOW,
        )
        permit = kernel.evaluate(purchase_intent(off_order)).permit
        budget = BudgetAccount()
        reservation = budget.reserve(on_order, now_ns=NOW)
        registrar = NeverCalledRegistrar()

        with self.assertRaisesRegex(CommerceViolation, "permit_rejected"):
            DomainCommerceExecutor().execute(
                kernel,
                on_order,
                permit,
                registrar,
                budget,
                reservation.reservation_id,
                now_ns=NOW,
            )
        self.assertEqual(0, registrar.calls)

    def test_acceptance_requires_observed_exact_auto_renew_state(self) -> None:
        order = self.order(auto_renew_enabled=False)
        outcome = CommerceOutcome(
            order_hash=order.order_hash,
            authorized=True,
            payment=PaymentEvidence("payment:auto-renew", 2_000, "a" * 64),
            delivery=DeliveryEvidence("registration:auto-renew", order.domain, order.registrar),
        )
        base = VerificationEvidence(
            order.domain,
            order.registrar,
            order.owner_ref,
            1,
            True,
            "registered",
        )

        with self.assertRaisesRegex(CommerceViolation, "auto_renew_not_verified"):
            accept_delivery(order, outcome, base)
        with self.assertRaisesRegex(CommerceViolation, "auto_renew_mismatch"):
            accept_delivery(order, outcome, replace(base, auto_renew_enabled=True))

        accept_delivery(order, outcome, replace(base, auto_renew_enabled=False))
        self.assertTrue(outcome.accepted)

    def test_namecom_core_rejects_unhonorable_auto_renew_before_provider_call(self) -> None:
        order = self.order(auto_renew_enabled=True)
        adapter = NameComCoreRegistrarAdapter(object())  # type: ignore[arg-type]

        with self.assertRaisesRegex(NameComViolation, "namecom_autorenew_not_supported"):
            adapter.preflight(order)
        with self.assertRaisesRegex(NameComViolation, "namecom_autorenew_not_supported"):
            adapter.purchase(
                order,
                max_charge_cents=order.purchase_price_cents,
                idempotency_key=order.order_hash,
            )


if __name__ == "__main__":
    unittest.main()

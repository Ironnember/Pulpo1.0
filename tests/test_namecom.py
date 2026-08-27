import unittest

from pulpo.commerce import CommerceViolation, DomainPurchaseRequest, assess_quote
from pulpo.namecom import NAMECOM_PRODUCTION_ORIGIN, NAMECOM_SANDBOX_ORIGIN, NameComCoreAdapter


NOW = 1_000_000


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, origin, method, path, body, headers, *, credential_ref):
        self.calls.append((origin, method, path, body, headers, credential_ref))
        if not self.responses:
            raise AssertionError("unexpected provider call")
        return self.responses.pop(0)


class NameComCoreAdapterTests(unittest.TestCase):
    def setUp(self):
        self.request = DomainPurchaseRequest(
            request_id="request-namecom",
            principal="agent:commerce",
            acceptable_domains=("pulpo-proof.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("email", "hosting"),
            expires_at_ns=NOW + 10_000,
        )
        self.availability = {
            "results": [
                {
                    "domainName": "pulpo-proof.example",
                    "purchasable": True,
                    "premium": False,
                    "purchasePrice": 20,
                    "purchaseType": "registration",
                    "renewalPrice": "24.00",
                }
            ]
        }

    def adapter(self, origin=NAMECOM_SANDBOX_ORIGIN, responses=()):
        transport = FakeTransport(responses)
        return NameComCoreAdapter(origin, "credential://name-com/pulpo-pilot", transport), transport

    def order(self, adapter):
        quote = adapter.check_availability(self.request, "pulpo-proof.example", now_ns=NOW, quote_ttl_ns=500)
        return assess_quote(
            self.request,
            quote,
            credential_ref="credential://name-com/pulpo-pilot",
            now_ns=NOW,
        ).order

    def test_discovery_uses_exact_registration_endpoint_and_decimal_cents(self):
        adapter, transport = self.adapter(responses=(self.availability,))
        quote = adapter.check_availability(self.request, "pulpo-proof.example", now_ns=NOW, quote_ttl_ns=500)
        self.assertEqual((2_000, 2_400, NOW + 500), (quote.purchase_price_cents, quote.renewal_price_cents, quote.expires_at_ns))
        self.assertEqual("name.com", quote.registrar)
        self.assertTrue(quote.privacy_enabled)
        self.assertEqual(
            (
                NAMECOM_SANDBOX_ORIGIN,
                "POST",
                "/core/v1/domains:checkAvailability",
                {"domainNames": ["pulpo-proof.example"], "purchaseType": "registration"},
                {"Content-Type": "application/json"},
                "credential://name-com/pulpo-pilot",
            ),
            transport.calls[0],
        )

    def test_discovery_rejects_substitution_premium_type_unavailable_and_bad_money(self):
        cases = (
            ({"domainName": "attacker.example"}, "domain_substitution"),
            ({"premium": True}, "premium_not_allowed"),
            ({"purchaseType": "aftermarket_i"}, "purchase_type_not_allowed"),
            ({"purchasable": False}, "not_purchasable"),
            ({"purchasePrice": "20.001"}, "purchase_price_invalid"),
        )
        for changes, reason in cases:
            result = self.availability["results"][0] | changes
            adapter, _ = self.adapter(responses=({"results": [result]},))
            with self.subTest(reason=reason), self.assertRaisesRegex(CommerceViolation, reason):
                adapter.check_availability(self.request, "pulpo-proof.example", now_ns=NOW, quote_ttl_ns=500)

    def test_production_fails_before_provider_when_hard_cap_is_unavailable(self):
        adapter, transport = self.adapter(NAMECOM_PRODUCTION_ORIGIN, (self.availability,))
        order = self.order(adapter)
        with self.assertRaisesRegex(CommerceViolation, "production_hard_charge_cap_unavailable"):
            adapter.purchase(order, max_charge_cents=order.purchase_price_cents)
        self.assertEqual(1, len(transport.calls))

    def test_sandbox_purchase_uses_idempotency_without_purchase_price(self):
        response = {
            "domain": {"domainName": "pulpo-proof.example", "privacyEnabled": True},
            "order": 123,
            "totalPaid": 19.5,
        }
        adapter, transport = self.adapter(responses=(self.availability, response))
        order = self.order(adapter)
        result = adapter.purchase(order, max_charge_cents=2_000)
        self.assertEqual(("namecom-order:123", 1_950, "pulpo-proof.example"), (result.payment_id, result.charged_cents, result.domain))
        origin, method, path, body, headers, credential_ref = transport.calls[1]
        self.assertEqual(NAMECOM_SANDBOX_ORIGIN, origin)
        self.assertEqual(("POST", "/core/v1/domains"), (method, path))
        self.assertNotIn("purchasePrice", body)
        self.assertEqual("registration", body["purchaseType"])
        self.assertEqual(order.order_hash, headers["X-Idempotency-Key"])
        self.assertEqual("credential://name-com/pulpo-pilot", credential_ref)

    def test_sandbox_response_still_fails_closed_on_cap_privacy_and_delivery(self):
        cases = (
            ({"domain": {"domainName": "pulpo-proof.example", "privacyEnabled": True}, "order": 1, "totalPaid": 20.01}, "charge_exceeded_cap"),
            ({"domain": {"domainName": "pulpo-proof.example", "privacyEnabled": False}, "order": 1, "totalPaid": 20}, "privacy_not_enabled"),
            ({"domain": {"domainName": "attacker.example", "privacyEnabled": True}, "order": 1, "totalPaid": 20}, "delivery_substitution"),
        )
        for response, reason in cases:
            adapter, _ = self.adapter(responses=(self.availability, response))
            order = self.order(adapter)
            with self.subTest(reason=reason), self.assertRaisesRegex(CommerceViolation, reason):
                adapter.purchase(order, max_charge_cents=2_000)

    def test_origin_credential_and_cap_are_exactly_pinned(self):
        transport = FakeTransport(())
        with self.assertRaisesRegex(CommerceViolation, "origin_not_pinned"):
            NameComCoreAdapter("https://attacker.example", "credential://name-com/pulpo-pilot", transport)
        with self.assertRaisesRegex(CommerceViolation, "credential_reference_invalid"):
            NameComCoreAdapter(NAMECOM_SANDBOX_ORIGIN, "plaintext-token", transport)
        adapter, _ = self.adapter(responses=(self.availability,))
        order = self.order(adapter)
        with self.assertRaisesRegex(CommerceViolation, "charge_cap_mismatch"):
            adapter.purchase(order, max_charge_cents=3_000)


if __name__ == "__main__":
    unittest.main()

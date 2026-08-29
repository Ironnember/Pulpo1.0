import json
import unittest

from pulpo.commerce import DomainPurchaseRequest, DomainQuote, assess_quote
from pulpo.namecom_core import (
    NameComCoreClient,
    NameComCoreConfig,
    NameComCoreRegistrarAdapter,
    NameComResponse,
    NameComViolation,
)


NOW = 20_000_000


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError("unexpected provider request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(payload, status=200, headers=None):
    return NameComResponse(
        status=status,
        headers=headers or {},
        body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )


class NameComCoreTests(unittest.TestCase):
    def order(self):
        request = DomainPurchaseRequest(
            request_id="namecom-core-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-namecom-v0.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="namecom-core-quote-v0",
            domain="pulpo-namecom-v0.example",
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
            credential_ref="credential://name-com/custody",
            now_ns=NOW,
        )
        self.assertIsNotNone(result.order)
        return result.order

    def test_sandbox_requires_test_username_and_production_requires_explicit_enable(self):
        with self.assertRaisesRegex(NameComViolation, "sandbox_username_must_end_test"):
            NameComCoreConfig("pulpo", "token", environment="sandbox")
        with self.assertRaisesRegex(NameComViolation, "production_not_enabled"):
            NameComCoreConfig("pulpo", "token", environment="production")
        enabled = NameComCoreConfig(
            "pulpo",
            "token",
            environment="production",
            allow_production=True,
        )
        self.assertEqual("https://api.name.com", enabled.base_url)

    def test_create_domain_uses_exact_core_endpoint_basic_auth_and_idempotency_key(self):
        order = self.order()
        transport = FakeTransport(
            [
                response(
                    {
                        "domain": {
                            "domainName": order.domain,
                            "autorenewEnabled": False,
                            "locked": True,
                            "privacyEnabled": True,
                        },
                        "order": 12345,
                        "totalPaid": 20.00,
                    }
                )
            ]
        )
        client = NameComCoreClient(
            NameComCoreConfig("pulpo-test", "sandbox-token"),
            transport=transport,
        )
        result = NameComCoreRegistrarAdapter(client).purchase(
            order,
            max_charge_cents=2_000,
            idempotency_key="custody-attempt-abc",
        )

        self.assertEqual("namecom-order:12345", result.payment_id)
        self.assertEqual(2_000, result.charged_cents)
        self.assertEqual(order.domain, result.domain)
        self.assertEqual(1, len(transport.calls))
        method, url, headers, raw_body = transport.calls[0]
        self.assertEqual("POST", method)
        self.assertEqual("https://api.dev.name.com/core/v1/domains", url)
        self.assertTrue(headers["Authorization"].startswith("Basic "))
        self.assertEqual("custody-attempt-abc", headers["X-Idempotency-Key"])
        self.assertEqual("application/json", headers["Content-Type"])
        body = json.loads(raw_body.decode())
        self.assertEqual(order.domain, body["domain"]["domainName"])
        self.assertFalse(body["domain"]["autorenewEnabled"])
        self.assertTrue(body["domain"]["locked"])
        self.assertTrue(body["domain"]["privacyEnabled"])
        self.assertEqual(20.0, body["purchasePrice"])
        self.assertEqual("registration", body["purchaseType"])
        self.assertEqual(1, body["years"])

    def test_provider_overcharge_is_detected_and_never_normalized_into_success(self):
        order = self.order()
        transport = FakeTransport(
            [
                response(
                    {
                        "domain": {"domainName": order.domain},
                        "order": 12345,
                        "totalPaid": 20.01,
                    }
                )
            ]
        )
        adapter = NameComCoreRegistrarAdapter(
            NameComCoreClient(
                NameComCoreConfig("pulpo-test", "sandbox-token"),
                transport=transport,
            )
        )
        with self.assertRaisesRegex(NameComViolation, "total_paid_exceeded_authorization"):
            adapter.purchase(
                order,
                max_charge_cents=2_000,
                idempotency_key="custody-attempt-abc",
            )
        self.assertEqual(1, len(transport.calls))

    def test_readback_endpoints_are_separate_provider_observation_calls(self):
        transport = FakeTransport(
            [
                response({"domainName": "pulpo-namecom-v0.example", "privacyEnabled": True}),
                response({"id": 12345, "status": "complete"}),
                response({"orders": [{"id": 12345}], "totalCount": 1}),
            ]
        )
        client = NameComCoreClient(
            NameComCoreConfig("pulpo-test", "sandbox-token"),
            transport=transport,
        )
        self.assertEqual(
            "pulpo-namecom-v0.example",
            client.get_domain("pulpo-namecom-v0.example")["domainName"],
        )
        self.assertEqual(12345, client.get_order(12345)["id"])
        self.assertEqual(12345, client.list_orders_for_domain("pulpo-namecom-v0.example")["orders"][0]["id"])
        self.assertEqual(
            [
                "https://api.dev.name.com/core/v1/domains/pulpo-namecom-v0.example",
                "https://api.dev.name.com/core/v1/orders/12345",
                "https://api.dev.name.com/core/v1/orders?domainName=pulpo-namecom-v0.example",
            ],
            [call[1] for call in transport.calls],
        )

    def test_http_error_is_not_retried_inside_adapter(self):
        order = self.order()
        transport = FakeTransport([response({"message": "timeout"}, status=504)])
        adapter = NameComCoreRegistrarAdapter(
            NameComCoreClient(
                NameComCoreConfig("pulpo-test", "sandbox-token"),
                transport=transport,
            )
        )
        with self.assertRaisesRegex(NameComViolation, "namecom_http_504"):
            adapter.purchase(
                order,
                max_charge_cents=2_000,
                idempotency_key="custody-attempt-abc",
            )
        self.assertEqual(1, len(transport.calls))


if __name__ == "__main__":
    unittest.main()

import json
import unittest

from pulpo.namecom_core import NameComCoreClient, NameComCoreConfig, NameComResponse
from pulpo.namecom_proposal import NameComProposalViolation, NameComSandboxProposalBuilder


NOW = 61_000_000
DOMAIN = "pulpo-proposal-v0.example"


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError("unexpected provider request")
        return self.responses.pop(0)


def response(payload, status=200):
    return NameComResponse(
        status=status,
        headers={},
        body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )


def availability(*, domain=DOMAIN, purchasable=True, premium=False, purchase=20.0, renewal=24.0):
    return {
        "results": [
            {
                "domainName": domain,
                "purchasable": purchasable,
                "premium": premium,
                "purchasePrice": purchase,
                "renewalPrice": renewal,
                "purchaseType": "registration",
            }
        ]
    }


class NameComProposalTests(unittest.TestCase):
    def builder(self, payload):
        transport = FakeTransport([response(payload)])
        client = NameComCoreClient(
            NameComCoreConfig("pulpo-proposal-test", "observer-token"),
            transport=transport,
        )
        return (
            NameComSandboxProposalBuilder(
                client,
                principal="agent:hostile-worker-sandbox-v0",
                owner_ref="owner://iron-ember/namecom-sandbox",
                clock=lambda: NOW,
            ),
            transport,
        )

    def test_domain_only_discovery_builds_exact_bounded_order_without_provider_write(self):
        builder, transport = self.builder(availability())
        proposal = builder.propose(DOMAIN)

        self.assertEqual(DOMAIN, proposal.order.domain)
        self.assertEqual(2_000, proposal.order.purchase_price_cents)
        self.assertEqual(2_400, proposal.order.renewal_price_cents)
        self.assertEqual(2_000, proposal.request.max_purchase_cents)
        self.assertEqual(2_400, proposal.request.max_renewal_cents)
        self.assertEqual((DOMAIN,), proposal.request.acceptable_domains)
        self.assertTrue(proposal.order.privacy_required)
        self.assertEqual("name.com", proposal.order.registrar)
        self.assertEqual(NOW, proposal.observed_at_ns)
        self.assertEqual(proposal.request.expires_at_ns, proposal.quote.expires_at_ns)
        self.assertEqual(proposal.quote.expires_at_ns, proposal.order.expires_at_ns)
        self.assertEqual(64, len(proposal.availability_hash))

        self.assertEqual(1, len(transport.calls))
        method, url, _, raw_body = transport.calls[0]
        self.assertEqual("POST", method)
        self.assertEqual(
            "https://api.dev.name.com/core/v1/domains:checkAvailability",
            url,
        )
        self.assertEqual(
            {"domainNames": [DOMAIN], "purchaseType": "registration"},
            json.loads(raw_body.decode()),
        )
        self.assertNotIn("/core/v1/domains", url.removesuffix(":checkAvailability"))

    def test_premium_unavailable_and_over_budget_inventory_fail_before_order_exists(self):
        for payload, reason in (
            (availability(premium=True), "premium_domain_forbidden"),
            (availability(purchasable=False), "domain_not_purchasable"),
            (availability(purchase=30.01), "purchase_price_exceeds_pilot"),
        ):
            with self.subTest(reason=reason):
                builder, transport = self.builder(payload)
                with self.assertRaisesRegex(NameComProposalViolation, reason):
                    builder.propose(DOMAIN)
                self.assertEqual(1, len(transport.calls))

    def test_worker_domain_input_must_be_normalized_and_v0_builder_cannot_use_production_client(self):
        builder, transport = self.builder(availability())
        for domain in ("Pulpo-Proposal-v0.example", " pulpo-proposal-v0.example", "localhost"):
            with self.subTest(domain=domain):
                with self.assertRaises(NameComProposalViolation):
                    builder.propose(domain)
        self.assertEqual(0, len(transport.calls))

        production_client = NameComCoreClient(
            NameComCoreConfig(
                "pulpo",
                "token",
                environment="production",
                allow_production=True,
            ),
            transport=FakeTransport([]),
        )
        with self.assertRaisesRegex(NameComProposalViolation, "must_use_sandbox"):
            NameComSandboxProposalBuilder(
                production_client,
                principal="agent:hostile-worker-sandbox-v0",
                owner_ref="owner://iron-ember/namecom-sandbox",
            )


if __name__ == "__main__":
    unittest.main()

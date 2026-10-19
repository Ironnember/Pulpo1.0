import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from fastapi.testclient import TestClient

from pulpo.commerce import DomainPurchaseOrder, SQLiteBudgetAccount, purchase_intent
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.namecom_core import NameComCoreClient, NameComCoreConfig, NameComResponse
from pulpo.namecom_proposal import NameComSandboxProposalBuilder
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for

from pulpo_custody_service.api import create_app
from pulpo_custody_service.core import DomainCustodyService


NOW = 71_000_000
DOMAIN = "pulpo-domain-proposal-v0.example"


class FakeTransport:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        payload = {
            "results": [
                {
                    "domainName": DOMAIN,
                    "purchasable": True,
                    "premium": False,
                    "purchasePrice": 20.0,
                    "renewalPrice": 24.0,
                    "purchaseType": "registration",
                }
            ]
        }
        return NameComResponse(
            status=200,
            headers={},
            body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
        )


class UnusedRegistrar:
    def preflight(self, order):
        raise AssertionError("proposal/authorization must not execute provider write path")

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        raise AssertionError("proposal/authorization must not execute provider write path")


class UnusedObserver:
    def observe(self, governed, order):
        raise AssertionError("proposal/authorization must not invoke reconciliation observer")


class DomainProposalApiTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"purchase_domain"}),
            3_000,
            frozenset({"purchase_domain"}),
            authority_trust=trust_for(self.verifier),
        )
        self.custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"domain-proposal-custody-secret",
            clock=lambda: NOW,
        )
        self.budget = SQLiteBudgetAccount(self.path)

        def kernel_factory():
            state = SQLiteKernelState(self.path)
            try:
                return GovernanceKernel(
                    self.policy,
                    secret=b"domain-proposal-kernel-secret",
                    approval_verifier=self.verifier,
                    clock=lambda: NOW,
                    state=state,
                )
            except Exception:
                state.close()
                raise

        self.transport = FakeTransport()
        observer_client = NameComCoreClient(
            NameComCoreConfig("pulpo-domain-proposal-test", "observer-token"),
            transport=self.transport,
        )
        self.service = DomainCustodyService(
            kernel_factory=kernel_factory,
            custody=self.custody,
            budget=self.budget,
            registrar=UnusedRegistrar(),
            observer=UnusedObserver(),
            observer_id="observer:domain-proposal-test",
            executor_id="executor:domain-proposal-test",
            proposal_builder=NameComSandboxProposalBuilder(
                observer_client,
                principal="agent:hostile-worker-sandbox-v0",
                owner_ref="owner://iron-ember/namecom-sandbox",
                clock=lambda: NOW,
            ),
        )
        self.client = TestClient(create_app(self.service))
        self.signing_kernel = GovernanceKernel(
            self.policy,
            secret=b"domain-proposal-kernel-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )

    @staticmethod
    def order_from_payload(payload):
        values = dict(payload)
        values["prohibited_upsells"] = tuple(values["prohibited_upsells"])
        return DomainPurchaseOrder(**values)

    def test_domain_only_proposal_captures_price_commitment_and_approval_request(self):
        response = self.client.post("/v1/domain-proposals", json={"domain": DOMAIN})
        self.assertEqual(200, response.status_code, response.text)
        payload = response.json()

        self.assertEqual("pulpo.namecom-sandbox-proposal.v0", payload["schema"])
        self.assertEqual("none", payload["authority_effect"])
        self.assertEqual(2_000, payload["order"]["purchase_price_cents"])
        self.assertEqual(2_400, payload["order"]["renewal_price_cents"])
        self.assertEqual("agent:hostile-worker-sandbox-v0", payload["order"]["principal"])
        self.assertEqual("owner://iron-ember/namecom-sandbox", payload["order"]["owner_ref"])
        self.assertEqual("credential://name-com/sandbox-executor", payload["order"]["credential_ref"])
        commitment = payload["proposal_commitment"]
        self.assertEqual("pulpo.proposal-commitment.v0", commitment["schema"])
        self.assertEqual("ready", commitment["state"])
        self.assertEqual(payload["availability_hash"], commitment["availability_hash"])
        self.assertEqual(self.order_from_payload(payload["order"]).order_hash, commitment["order_hash"])
        self.assertTrue(payload["approval_challenge"]["approval_required"])
        self.assertEqual(
            payload["approval_challenge"]["intent_hash"],
            payload["approval_challenge"]["authority_request"]["intent_hash"],
        )
        self.assertEqual(1, len(self.transport.calls))
        self.assertEqual(0, self.budget.reserved_cents)
        self.assertEqual(0, self.custody.snapshot().epoch)

        raw = json.dumps(payload)
        self.assertNotIn("observer-token", raw)
        self.assertNotIn("domain-proposal-custody-secret", raw)
        self.assertNotIn("domain-proposal-kernel-secret", raw)

    def test_worker_cannot_inject_consequential_proposal_fields(self):
        injections = (
            ("purchase_price_cents", 1),
            ("renewal_price_cents", 1),
            ("owner_ref", "owner://attacker"),
            ("principal", "agent:attacker"),
            ("expires_at_ns", NOW + 9_999_999_999),
            ("provider_token", "attacker-token"),
        )
        for field, value in injections:
            with self.subTest(field=field):
                response = self.client.post(
                    "/v1/domain-proposals",
                    json={"domain": DOMAIN, field: value},
                )
                self.assertEqual(422, response.status_code)
        self.assertEqual(0, len(self.transport.calls))

    def test_exact_commitment_can_receive_signature_then_create_one_attempt(self):
        proposal = self.client.post(
            "/v1/domain-proposals",
            json={"domain": DOMAIN},
        ).json()
        order = self.order_from_payload(proposal["order"])
        challenge = proposal["approval_challenge"]
        commitment_id = proposal["proposal_commitment"]["commitment_id"]
        self.assertEqual(
            challenge["intent_hash"],
            self.signing_kernel.intent_hash(purchase_intent(order)),
        )
        envelope = signed_envelope(
            self.signing_kernel,
            purchase_intent(order),
            self.verifier,
            now_ns=NOW - 10,
            approval_id="domain-proposal-approval-v0",
            nonce="domain-proposal-approval-nonce-v0",
        )

        authorized = self.client.post(
            "/v1/domain-attempts",
            json={
                "proposal_commitment_id": commitment_id,
                "approval": asdict(envelope),
            },
        )
        self.assertEqual(200, authorized.status_code, authorized.text)
        handle = authorized.json()
        self.assertEqual("attempt_authorized", handle["state"])
        self.assertEqual(order.order_hash, handle["order_hash"])
        self.assertEqual(2_000, handle["reserved_cents"])
        self.assertEqual(2_000, self.budget.reserved_cents)
        self.assertEqual(1, self.custody.snapshot().epoch)
        self.assertEqual(0, self.service.evidence.pending_count())

        replay = self.client.post(
            "/v1/domain-attempts",
            json={
                "proposal_commitment_id": commitment_id,
                "approval": asdict(envelope),
            },
        )
        self.assertEqual(403, replay.status_code)
        self.assertEqual(2_000, self.budget.reserved_cents)
        self.assertEqual(1, self.custody.snapshot().epoch)

    def test_identical_display_order_cannot_replace_commitment_reference(self):
        proposal = self.client.post(
            "/v1/domain-proposals",
            json={"domain": DOMAIN},
        ).json()
        before = self.custody.snapshot()
        response = self.client.post(
            "/v1/domain-attempts",
            json={"order": proposal["order"]},
        )
        self.assertEqual(422, response.status_code)
        self.assertEqual(before, self.custody.snapshot())
        self.assertEqual(0, self.budget.reserved_cents)


if __name__ == "__main__":
    unittest.main()

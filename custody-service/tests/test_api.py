import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from fastapi.testclient import TestClient

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_reconcile import IndependentDomainObservation
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for

from pulpo_custody_service.api import create_app
from pulpo_custody_service.core import DomainCustodyService


NOW = 31_000_000


class FakeRegistrar:
    def __init__(self):
        self.preflight_calls = 0
        self.purchase_calls = 0

    def preflight(self, order):
        self.preflight_calls += 1
        return "b" * 64

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        self.purchase_calls += 1
        return RegistrarResult(
            payment_id="fake-order:1",
            charged_cents=order.purchase_price_cents,
            receipt_hash="c" * 64,
            registration_id="fake-registration:1",
            domain=order.domain,
            registrar=order.registrar,
        )


class FakeObserver:
    def __init__(self, custody):
        self.custody = custody
        self.calls = 0

    def observe(self, governed, order):
        self.calls += 1
        attempt = self.custody.attempt(governed.attempt_id)
        return IndependentDomainObservation(
            observation_id=f"fake-observer:{self.calls}",
            provider_request_id=attempt.provider_request_id,
            provider_request_status="succeeded",
            domain=order.domain,
            registrar=order.registrar,
            owner_ref=order.owner_ref,
            registered=True,
            payment_id="fake-order:1",
            charged_cents=order.purchase_price_cents,
            receipt_hash="d" * 64,
            privacy_enabled=True,
            dns_state="registered",
        )


class CustodyServiceApiTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def order(self):
        request = DomainPurchaseRequest(
            request_id="service-v0",
            principal="agent:hostile-worker",
            acceptable_domains=("pulpo-service.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="service-quote-v0",
            domain="pulpo-service.example",
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

    @staticmethod
    def order_payload(order):
        payload = asdict(order)
        payload["prohibited_upsells"] = list(payload["prohibited_upsells"])
        return payload

    def build(self, *, require_approval=False):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"service-custody-secret",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(self.path)
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        verifier = HmacTestVerifier() if require_approval else None
        policy = (
            Policy(
                frozenset({"purchase_domain"}),
                3_000,
                frozenset({"purchase_domain"}),
                authority_trust=trust_for(verifier),
            )
            if verifier
            else Policy(frozenset({"purchase_domain"}), 3_000)
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"service-kernel-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        registrar = FakeRegistrar()
        observer = FakeObserver(custody)
        service = DomainCustodyService(
            kernel=kernel,
            custody=custody,
            budget=budget,
            registrar=registrar,
            observer=observer,
            observer_id="observer:service-v0",
            executor_id="executor:service-v0",
        )
        return TestClient(create_app(service)), service, registrar, observer, kernel, verifier

    def test_worker_can_use_only_narrow_authorize_execute_reconcile_surface(self):
        client, service, registrar, observer, _, _ = self.build()
        order = self.order()
        payload = self.order_payload(order)

        authorized = client.post("/v1/domain-attempts", json={"order": payload})
        self.assertEqual(200, authorized.status_code)
        handle = authorized.json()
        self.assertNotIn("permit", handle)
        self.assertNotIn("secret", handle)
        self.assertNotIn("now_ns", handle)
        self.assertEqual("attempt_authorized", handle["state"])

        operation = {"handle": handle, "order": payload}
        executed = client.post(
            f"/v1/domain-attempts/{handle['attempt_id']}/execute",
            json=operation,
        )
        self.assertEqual(200, executed.status_code)
        self.assertEqual("provider_claim_recorded", executed.json()["status"])
        self.assertEqual(1, registrar.preflight_calls)
        self.assertEqual(1, registrar.purchase_calls)

        replay = client.post(
            f"/v1/domain-attempts/{handle['attempt_id']}/execute",
            json=operation,
        )
        self.assertEqual(409, replay.status_code)
        self.assertEqual(1, registrar.purchase_calls)

        reconciled = client.post(
            f"/v1/domain-attempts/{handle['attempt_id']}/reconcile",
            json=operation,
        )
        self.assertEqual(200, reconciled.status_code)
        self.assertEqual("success", reconciled.json()["outcome"])
        self.assertEqual(1, observer.calls)
        self.assertEqual("reconciled_success", service.status(handle["attempt_id"])["state"])

    def test_worker_supplied_clock_budget_or_custody_fields_are_rejected_by_schema(self):
        client, _, _, _, _, _ = self.build()
        order = self.order()
        payload = self.order_payload(order)
        for field, value in (
            ("now_ns", 1),
            ("budget_available_cents", 3_000),
            ("custody_epoch", 0),
            ("permit", "worker-forged"),
            ("provider_token", "worker-secret"),
        ):
            body = {"order": {**payload, field: value}}
            response = client.post("/v1/domain-attempts", json=body)
            self.assertEqual(422, response.status_code, field)

    def test_copied_handle_cannot_authorize_second_execution_or_substituted_order(self):
        client, _, registrar, _, _, _ = self.build()
        order = self.order()
        payload = self.order_payload(order)
        handle = client.post("/v1/domain-attempts", json={"order": payload}).json()
        operation = {"handle": handle, "order": payload}
        self.assertEqual(
            200,
            client.post(
                f"/v1/domain-attempts/{handle['attempt_id']}/execute",
                json=operation,
            ).status_code,
        )

        mutated = dict(payload)
        mutated["domain"] = "attacker.example"
        response = client.post(
            f"/v1/domain-attempts/{handle['attempt_id']}/execute",
            json={"handle": handle, "order": mutated},
        )
        self.assertIn(response.status_code, {409, 422})
        self.assertEqual(1, registrar.purchase_calls)

    def test_approval_required_policy_rejects_missing_or_invalid_envelope_and_accepts_external_signature(self):
        client, _, _, _, kernel, verifier = self.build(require_approval=True)
        order = self.order()
        payload = self.order_payload(order)

        missing = client.post("/v1/domain-attempts", json={"order": payload})
        self.assertEqual(403, missing.status_code)

        intent = purchase_intent(order)
        envelope = signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id="service-approval-v0",
            nonce="service-nonce-v0",
        )
        approved = client.post(
            "/v1/domain-attempts",
            json={"order": payload, "approval": asdict(envelope)},
        )
        self.assertEqual(200, approved.status_code)
        self.assertEqual("attempt_authorized", approved.json()["state"])

        # The service has only a verifier. A caller-modified signature cannot be
        # promoted into authority.
        second_order = self.order()
        # Same order is already reserved/attempted; mutate approval first to show
        # signature verification remains fail closed before any new capability.
        bad = asdict(envelope)
        bad["approval_id"] = "service-approval-forged"
        bad["nonce"] = "service-nonce-forged"
        bad["signature"] = "0" * len(envelope.signature)
        rejected = client.post(
            "/v1/domain-attempts",
            json={"order": self.order_payload(second_order), "approval": bad},
        )
        self.assertEqual(403, rejected.status_code)


if __name__ == "__main__":
    unittest.main()

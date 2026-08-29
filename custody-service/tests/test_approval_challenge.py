import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from fastapi.testclient import TestClient

# Compatibility-only import. The custody service does not depend on the
# authority-service package at runtime; CI loads its checked-in request contract
# directly so drift between the two independent trust domains fails closed.
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "authority-service" / "src"))
from pulpo_authority_service.core import ApprovalRequest

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for

from pulpo_custody_service.api import create_app
from pulpo_custody_service.core import DomainCustodyService


NOW = 51_000_000


class UnusedRegistrar:
    def preflight(self, order):
        raise AssertionError("provider must not run while preparing approval")

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        raise AssertionError("provider must not run while preparing approval")


class UnusedObserver:
    def observe(self, governed, order):
        raise AssertionError("observer must not run while preparing approval")


class ApprovalChallengeTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def order(self, domain="pulpo-approval.example"):
        request = DomainPurchaseRequest(
            request_id=f"approval-challenge-v0:{domain}",
            principal="agent:hostile-worker",
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
            quote_id=f"approval-challenge-quote-v0:{domain}",
            domain=domain,
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
    def payload(order):
        value = asdict(order)
        value["prohibited_upsells"] = list(value["prohibited_upsells"])
        return value

    def service(self):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"purchase_domain"}),
            3_000,
            frozenset({"purchase_domain"}),
            authority_trust=trust_for(verifier),
        )
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"approval-challenge-custody",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(self.path)

        def kernel_factory():
            state = SQLiteKernelState(self.path)
            try:
                return GovernanceKernel(
                    policy,
                    secret=b"approval-challenge-kernel",
                    approval_verifier=verifier,
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
            observer_id="observer:approval-challenge",
            executor_id="executor:approval-challenge",
        )
        return service, custody, budget, policy, verifier

    def challenge(self, client, order):
        response = client.post(
            "/v1/domain-approval-challenges",
            json={"order": self.payload(order)},
        )
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def test_exact_authority_request_is_stable_compatible_and_non_authorizing(self):
        service, custody, budget, policy, _ = self.service()
        client = TestClient(create_app(service))
        order = self.order()

        challenge = self.challenge(client, order)
        repeated = self.challenge(client, order)
        request = challenge["authority_request"]

        self.assertEqual(challenge, repeated)
        self.assertTrue(challenge["approval_required"])
        self.assertEqual("none", challenge["authority_effect"])
        self.assertEqual("pulpo.custody-approval-challenge.v0", challenge["schema"])
        self.assertEqual(order.principal, request["principal"])
        self.assertEqual("purchase_domain", request["action"])
        self.assertEqual(order.purchase_price_cents, request["cost"])
        self.assertEqual(challenge["intent_hash"], request["intent_hash"])
        self.assertEqual(challenge["policy_hash"], request["policy_hash"])
        self.assertEqual(policy.authority_trust.deployment_id, request["deployment_id"])
        self.assertEqual(policy.authority_trust.max_approval_ttl_ns, request["requested_ttl_ns"])
        self.assertEqual("pulpo.authority-request.v1", request["schema"])

        # The exact payload must be constructible by the existing separately
        # packaged authority service without translation or privilege-bearing
        # fields added by the worker.
        authority_request = ApprovalRequest(**request)
        self.assertEqual(authority_request.intent_hash, authority_request.recomputed_intent_hash)
        self.assertEqual(challenge["intent_hash"], authority_request.intent_hash)
        self.assertEqual(challenge["policy_hash"], authority_request.policy_hash)

        # Preparing the external ceremony locks an exact non-authorizing target,
        # but does not mint a custody attempt, consume budget, or advance the
        # authoritative custody head.
        self.assertEqual(0, custody.snapshot().epoch)
        self.assertEqual(0, budget.reserved_cents)
        self.assertEqual(3_000, budget.available_cents)
        self.assertEqual(404, client.get("/v1/domain-attempts/not-an-attempt").status_code)

    def test_changed_order_gets_different_target_and_intent_but_same_policy_trust(self):
        service, custody, budget, _, _ = self.service()
        client = TestClient(create_app(service))
        original = self.challenge(client, self.order("pulpo-approval.example"))
        changed = self.challenge(client, self.order("pulpo-approval-alt.example"))

        self.assertNotEqual(original["target_id"], changed["target_id"])
        self.assertNotEqual(original["target_hash"], changed["target_hash"])
        self.assertNotEqual(original["intent_hash"], changed["intent_hash"])
        self.assertNotEqual(original["resource"], changed["resource"])
        self.assertEqual(original["policy_hash"], changed["policy_hash"])
        self.assertEqual(original["deployment_id"], changed["deployment_id"])
        self.assertEqual(0, custody.snapshot().epoch)
        self.assertEqual(0, budget.reserved_cents)

    def test_worker_cannot_inject_target_policy_deployment_ttl_or_time(self):
        service, _, _, _, _ = self.service()
        client = TestClient(create_app(service))
        payload = self.payload(self.order())
        for field, value in (
            ("target_hash", "0" * 64),
            ("policy_hash", "0" * 64),
            ("deployment_id", "deployment:worker"),
            ("requested_ttl_ns", 999_999_999_999),
            ("now_ns", 1),
        ):
            with self.subTest(field=field):
                response = client.post(
                    "/v1/domain-approval-challenges",
                    json={"order": payload, field: value},
                )
                self.assertEqual(422, response.status_code)

    def test_approval_for_one_challenge_cannot_authorize_mutated_order(self):
        service, custody, budget, policy, verifier = self.service()
        client = TestClient(create_app(service))
        original = self.order("pulpo-approval.example")
        mutated = self.order("pulpo-approval-alt.example")
        challenge = self.challenge(client, original)

        signing_kernel = GovernanceKernel(
            policy,
            secret=b"approval-challenge-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        self.assertEqual(
            challenge["intent_hash"],
            signing_kernel.intent_hash(purchase_intent(original)),
        )
        envelope = signed_envelope(
            signing_kernel,
            purchase_intent(original),
            verifier,
            now_ns=NOW - 10,
            approval_id="approval-challenge-original",
            nonce="approval-challenge-original-nonce",
        )
        response = client.post(
            "/v1/domain-attempts",
            json={
                "order": self.payload(mutated),
                "approval": asdict(envelope),
            },
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual(0, budget.reserved_cents)
        self.assertEqual(0, custody.snapshot().epoch)


if __name__ == "__main__":
    unittest.main()

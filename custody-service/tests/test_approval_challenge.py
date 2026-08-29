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
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, trust_for

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

    def order(self):
        request = DomainPurchaseRequest(
            request_id="approval-challenge-v0",
            principal="agent:hostile-worker",
            acceptable_domains=("pulpo-approval.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="approval-challenge-quote-v0",
            domain="pulpo-approval.example",
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
        return service, custody, budget, policy

    def test_exact_authority_request_is_exposed_without_creating_attempt_or_reservation(self):
        service, custody, budget, policy = self.service()
        client = TestClient(create_app(service))
        order = self.order()

        response = client.post(
            "/v1/domain-approval-challenges",
            json={"order": self.payload(order)},
        )
        self.assertEqual(200, response.status_code)
        challenge = response.json()
        request = challenge["authority_request"]

        self.assertTrue(challenge["approval_required"])
        self.assertEqual("none", challenge["authority_effect"])
        self.assertEqual(order.principal, request["principal"])
        self.assertEqual("purchase_domain", request["action"])
        self.assertEqual(order.purchase_price_cents, request["cost"])
        self.assertEqual(challenge["intent_hash"], request["intent_hash"])
        self.assertEqual(challenge["policy_hash"], request["policy_hash"])
        self.assertEqual(policy.authority_trust.deployment_id, request["deployment_id"])
        self.assertEqual(policy.authority_trust.max_approval_ttl_ns, request["requested_ttl_ns"])
        self.assertEqual("pulpo.authority-request.v1", request["schema"])

        # Preparing the external ceremony locks an exact non-authorizing target,
        # but does not mint a custody attempt, consume budget, or advance the
        # authoritative custody head.
        self.assertEqual(0, custody.snapshot().epoch)
        self.assertEqual(0, budget.reserved_cents)
        self.assertEqual(3_000, budget.available_cents)

        status = client.get("/v1/domain-attempts/not-an-attempt")
        self.assertEqual(404, status.status_code)


if __name__ == "__main__":
    unittest.main()

import sys
import tempfile
import unittest
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from fastapi.testclient import TestClient

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
from pulpo.namecom_proposal import NameComSandboxProposal
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


class FakeProposalBuilder:
    def __init__(self, owner):
        self.owner = owner

    def propose(self, domain):
        order = self.owner.order(domain)
        availability_hash = sha256(f"availability:{domain}".encode()).hexdigest()
        return NameComSandboxProposal(
            request=self.owner.request_for(domain),
            quote=self.owner.quote_for(domain),
            order=order,
            availability_hash=availability_hash,
            observed_at_ns=NOW,
            expires_at_ns=order.expires_at_ns,
        )


class ApprovalChallengeTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def request_for(self, domain):
        return DomainPurchaseRequest(
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

    def quote_for(self, domain):
        return DomainQuote(
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

    def order(self, domain="pulpo-approval.example"):
        result = assess_quote(
            self.request_for(domain),
            self.quote_for(domain),
            credential_ref="credential://service/namecom",
            now_ns=NOW,
        )
        self.assertIsNotNone(result.order)
        return result.order

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
            proposal_builder=FakeProposalBuilder(self),
        )
        return service, custody, budget, policy, verifier

    def proposal(self, client, domain="pulpo-approval.example"):
        response = client.post("/v1/domain-proposals", json={"domain": domain})
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def test_exact_authority_request_is_compatible_and_non_authorizing(self):
        service, custody, budget, policy, _ = self.service()
        client = TestClient(create_app(service))
        payload = self.proposal(client)
        challenge = payload["approval_challenge"]
        request = challenge["authority_request"]

        self.assertTrue(challenge["approval_required"])
        self.assertEqual("none", challenge["authority_effect"])
        self.assertEqual("pulpo.custody-approval-challenge.v0", challenge["schema"])
        self.assertEqual("purchase_domain", request["action"])
        self.assertEqual(2_000, request["cost"])
        self.assertEqual(challenge["intent_hash"], request["intent_hash"])
        self.assertEqual(challenge["policy_hash"], request["policy_hash"])
        self.assertEqual(policy.authority_trust.deployment_id, request["deployment_id"])
        self.assertEqual(policy.authority_trust.max_approval_ttl_ns, request["requested_ttl_ns"])
        self.assertEqual("pulpo.authority-request.v1", request["schema"])

        authority_request = ApprovalRequest(**request)
        self.assertEqual(authority_request.intent_hash, authority_request.recomputed_intent_hash)
        self.assertEqual(challenge["intent_hash"], authority_request.intent_hash)
        self.assertEqual(challenge["policy_hash"], authority_request.policy_hash)

        self.assertEqual(0, custody.snapshot().epoch)
        self.assertEqual(0, budget.reserved_cents)
        self.assertEqual(3_000, budget.available_cents)

    def test_changed_domain_gets_different_commitment_target_and_intent(self):
        service, custody, budget, _, _ = self.service()
        client = TestClient(create_app(service))
        original = self.proposal(client, "pulpo-approval.example")
        changed = self.proposal(client, "pulpo-approval-alt.example")

        self.assertNotEqual(
            original["proposal_commitment"]["commitment_id"],
            changed["proposal_commitment"]["commitment_id"],
        )
        self.assertNotEqual(
            original["approval_challenge"]["target_hash"],
            changed["approval_challenge"]["target_hash"],
        )
        self.assertNotEqual(
            original["approval_challenge"]["intent_hash"],
            changed["approval_challenge"]["intent_hash"],
        )
        self.assertEqual(
            original["approval_challenge"]["policy_hash"],
            changed["approval_challenge"]["policy_hash"],
        )
        self.assertEqual(0, custody.snapshot().epoch)
        self.assertEqual(0, budget.reserved_cents)

    def test_worker_cannot_inject_target_policy_deployment_ttl_time_or_order(self):
        service, _, _, _, _ = self.service()
        client = TestClient(create_app(service))
        for field, value in (
            ("target_hash", "0" * 64),
            ("policy_hash", "0" * 64),
            ("deployment_id", "deployment:worker"),
            ("requested_ttl_ns", 999_999_999_999),
            ("now_ns", 1),
            ("order", {"domain": "attacker.example"}),
        ):
            with self.subTest(field=field):
                response = client.post(
                    "/v1/domain-proposals",
                    json={"domain": "pulpo-approval.example", field: value},
                )
                self.assertEqual(422, response.status_code)
        self.assertEqual(
            404,
            client.post("/v1/domain-approval-challenges", json={"order": {}}).status_code,
        )

    def test_approval_for_one_commitment_cannot_authorize_another(self):
        service, custody, budget, policy, verifier = self.service()
        client = TestClient(create_app(service))
        original = self.proposal(client, "pulpo-approval.example")
        mutated = self.proposal(client, "pulpo-approval-alt.example")
        original_order = self.order("pulpo-approval.example")

        signing_kernel = GovernanceKernel(
            policy,
            secret=b"approval-challenge-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        envelope = signed_envelope(
            signing_kernel,
            purchase_intent(original_order),
            verifier,
            now_ns=NOW - 10,
            approval_id="approval-challenge-original",
            nonce="approval-challenge-original-nonce",
        )
        response = client.post(
            "/v1/domain-attempts",
            json={
                "proposal_commitment_id": mutated["proposal_commitment"]["commitment_id"],
                "approval": asdict(envelope),
            },
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual(0, budget.reserved_cents)
        self.assertEqual(0, custody.snapshot().epoch)


if __name__ == "__main__":
    unittest.main()

from dataclasses import replace
import unittest

from pulpo.authority_client import AuthorityPoll
from pulpo.commerce import (
    BudgetAccount,
    CommerceViolation,
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    assess_quote,
    purchase_intent,
)
from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.orchestrator import ApprovalHandle, PulpoOrchestrator
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 5_000_000


class FakeAuthorityClient:
    def __init__(self, kernel, verifier, *, status="approved"):
        self.kernel = kernel
        self.verifier = verifier
        self.status = status
        self.requests = []
        self.polls = 0

    def request_approval(self, request):
        self.requests.append(request)
        return "request-1", "https://authority.pulpo.ai/human/approval/request-1"

    def poll_approval(self, request_id):
        self.polls += 1
        if request_id != "request-1":
            return AuthorityPoll("denied", reason="unknown_request")
        if self.status != "approved":
            return AuthorityPoll(self.status, reason=f"authority_{self.status}")
        request = self.requests[-1]
        intent = Intent(
            request.principal,
            request.action,
            request.resource,
            request.cost,
            request.session_id,
        )
        envelope = signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW - 10,
            approval_id="approval-orchestrator-1",
            nonce="nonce-orchestrator-1",
        )
        return AuthorityPoll("approved", envelope)


class FakeRegistrar:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def purchase(self, order, *, max_charge_cents):
        self.calls += 1
        if self.result.charged_cents is not None and self.result.charged_cents > max_charge_cents:
            raise CommerceViolation("provider_charge_cap_rejected")
        return self.result


class OrchestratorProofTests(unittest.TestCase):
    def governed(self, actions, approval_actions):
        verifier = HmacTestVerifier()
        kernel = GovernanceKernel(
            Policy(
                frozenset(actions),
                3_000,
                frozenset(approval_actions),
                authority_trust=trust_for(verifier),
            ),
            secret=b"orchestrator-proof",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        client = FakeAuthorityClient(kernel, verifier)
        return kernel, verifier, client, PulpoOrchestrator(kernel, authority_client=client)

    def test_exact_target_authority_request_is_hash_bound_and_one_use(self):
        kernel, _, client, orchestrator = self.governed({"write"}, {"write"})
        intent = Intent("agent:builder", "write", "repo:demo.txt", 1, "session:demo")
        target = orchestrator.lock_target("demo-write", intent)

        handle = orchestrator.request_target_approval(target, requested_ttl_ns=500)
        request = client.requests[-1]
        self.assertEqual(kernel.intent_hash(intent), request.intent_hash)
        self.assertEqual(kernel.policy_hash, request.policy_hash)
        self.assertEqual(kernel.policy.authority_trust.deployment_id, request.deployment_id)
        self.assertEqual(target.target_hash, handle.target_hash)

        attempt = orchestrator.authorize_target(handle)
        self.assertEqual("match", attempt.resolution.outcome)
        self.assertEqual("approved", attempt.poll.status)
        self.assertEqual("allow", attempt.decision.outcome)
        self.assertIsNotNone(attempt.decision.permit)
        self.assertTrue(orchestrator.consume_authorized_target(attempt))
        self.assertFalse(orchestrator.consume_authorized_target(attempt))
        self.assertTrue(orchestrator.evidence_snapshot().audit_valid)

    def test_target_mismatch_stops_before_authority_poll(self):
        _, _, client, orchestrator = self.governed({"write"}, {"write"})
        target = orchestrator.lock_target(
            "demo-write",
            Intent("agent:builder", "write", "repo:demo.txt", 1, "session:demo"),
        )
        handle = orchestrator.request_target_approval(target, requested_ttl_ns=500)
        forged = replace(handle, target_hash="0" * 64)

        attempt = orchestrator.authorize_target(forged)
        self.assertEqual(("deny", "target_hash_mismatch"), (attempt.resolution.outcome, attempt.resolution.reason))
        self.assertIsNone(attempt.poll)
        self.assertIsNone(attempt.decision)
        self.assertEqual(0, client.polls)

    def test_pending_or_denied_authority_never_reaches_permit_issuance(self):
        kernel, verifier, _, _ = self.governed({"write"}, {"write"})
        for status in ("pending", "denied", "expired"):
            with self.subTest(status=status):
                local_kernel = GovernanceKernel(
                    kernel.policy,
                    secret=b"orchestrator-proof",
                    approval_verifier=verifier,
                    clock=lambda: NOW,
                )
                client = FakeAuthorityClient(local_kernel, verifier, status=status)
                orchestrator = PulpoOrchestrator(local_kernel, authority_client=client)
                target = orchestrator.lock_target(
                    f"demo-{status}",
                    Intent("agent:builder", "write", f"repo:{status}.txt", 1, f"session:{status}"),
                )
                handle = orchestrator.request_target_approval(target, requested_ttl_ns=500)
                attempt = orchestrator.authorize_target(handle)
                self.assertEqual(status, attempt.poll.status)
                self.assertIsNone(attempt.decision)
                self.assertFalse(orchestrator.consume_authorized_target(attempt))
                self.assertFalse(any(record["event"] == "approval_verified" for record in local_kernel.audit))

    def test_exact_purchase_executes_once_and_substitution_fails_before_provider(self):
        kernel, _, client, orchestrator = self.governed({"purchase_domain"}, {"purchase_domain"})
        request = DomainPurchaseRequest(
            request_id="purchase-1",
            principal="agent:commerce",
            acceptable_domains=("pulpo-demo.example", "pulpo-demo-two.example"),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 10_000,
        )
        quote = DomainQuote(
            quote_id="quote-1",
            domain="pulpo-demo.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 5_000,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref="credential://name-com/demo",
            now_ns=NOW,
        )
        order = assessment.order
        self.assertIsNotNone(order)
        intent = purchase_intent(order)
        target = orchestrator.lock_target("purchase-domain", intent)
        handle = orchestrator.request_target_approval(target, requested_ttl_ns=500)
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual("allow", attempt.decision.outcome)

        budget = BudgetAccount()
        reservation = budget.reserve(order, now_ns=NOW)
        registrar = FakeRegistrar(
            RegistrarResult("payment-1", 2_000, "a" * 64, "registration-1", order.domain, order.registrar)
        )
        outcome = orchestrator.execute_domain_purchase(
            order,
            attempt.decision.permit,
            registrar,
            budget,
            reservation.reservation_id,
            now_ns=NOW,
        )
        self.assertTrue(outcome.authorized)
        self.assertEqual(1, registrar.calls)

        changed_quote = DomainQuote(
            quote_id="quote-2",
            domain="pulpo-demo-two.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 5_000,
        )
        changed_order = assess_quote(
            request,
            changed_quote,
            credential_ref="credential://name-com/demo",
            now_ns=NOW,
        ).order
        changed_budget = BudgetAccount()
        changed_reservation = changed_budget.reserve(changed_order, now_ns=NOW)
        changed_registrar = FakeRegistrar(RegistrarResult(None, None, None, None, None, None))
        with self.assertRaisesRegex(CommerceViolation, "permit_rejected"):
            orchestrator.execute_domain_purchase(
                changed_order,
                attempt.decision.permit,
                changed_registrar,
                changed_budget,
                changed_reservation.reservation_id,
                now_ns=NOW,
            )
        self.assertEqual(0, changed_registrar.calls)
        self.assertEqual(1, client.polls)


if __name__ == "__main__":
    unittest.main()

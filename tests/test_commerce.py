import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
import unittest
from dataclasses import replace

from pulpo.authority import ApprovalEnvelope
from pulpo.commerce import (
    BudgetAccount,
    CommerceViolation,
    DomainCommerceExecutor,
    DomainPurchaseRequest,
    DomainQuote,
    PaymentEvidence,
    RegistrarResult,
    SQLiteBudgetAccount,
    VerificationEvidence,
    accept_delivery,
    assess_quote,
    build_proof_bundle,
    purchase_intent,
    record_value,
)
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.profiles import ESSENTIAL_AGENT_GRANTS


NOW = 1_000_000


class CommerceTestVerifier:
    authority_id = "authority:test-owner"

    @staticmethod
    def signature(payload):
        return hashlib.sha256(b"test-authority:" + payload).hexdigest()

    def verify(self, payload, signature):
        return signature == self.signature(payload)


def verified_approval(kernel, intent, verifier):
    unsigned = ApprovalEnvelope(
        approval_id=f"approval-{kernel.intent_hash(intent)[:12]}",
        authority_id=verifier.authority_id,
        session_id=intent.session_id,
        principal=intent.principal,
        intent_hash=kernel.intent_hash(intent),
        policy_hash=kernel.policy_hash,
        nonce=f"nonce-{kernel.intent_hash(intent)[12:24]}",
        expires_at_ns=NOW + 100,
        signature="",
    )
    return replace(unsigned, signature=verifier.signature(unsigned.signing_bytes()))


class FakeRegistrar:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def purchase(self, order, *, max_charge_cents):
        self.calls += 1
        if self.result.charged_cents is not None and self.result.charged_cents > max_charge_cents:
            raise CommerceViolation("provider_charge_cap_rejected")
        return self.result


class UncertainRegistrar:
    def __init__(self):
        self.calls = 0

    def purchase(self, order, *, max_charge_cents):
        del order, max_charge_cents
        self.calls += 1
        raise ConnectionError("provider result is unknown")


class CommerceProofTests(unittest.TestCase):
    def setUp(self):
        self.request = DomainPurchaseRequest(
            request_id="request-1",
            principal="agent:commerce",
            acceptable_domains=("pulpo-proof.example", "pulpo-proof-two.example"),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("email", "hosting", "site-builder"),
            expires_at_ns=NOW + 1_000,
        )
        self.quote = DomainQuote(
            quote_id="quote-1",
            domain="pulpo-proof.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 500,
        )

    def assessment(self, request=None, quote=None, now_ns=NOW):
        return assess_quote(
            request or self.request,
            quote or self.quote,
            credential_ref="credential://name-com/pulpo-pilot",
            now_ns=now_ns,
        )

    def authorized_execution(self, order):
        actions = frozenset().union(*(grant.allowed_actions for grant in ESSENTIAL_AGENT_GRANTS))
        verifier = CommerceTestVerifier()
        kernel = GovernanceKernel(
            Policy(actions, 3_000, frozenset({"purchase_domain"}), ESSENTIAL_AGENT_GRANTS),
            secret=b"test-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        budget = BudgetAccount()
        reservation = budget.reserve(order, now_ns=NOW)
        intent = purchase_intent(order)
        envelope = verified_approval(kernel, intent, verifier)
        permit = kernel.evaluate_with_approval(intent, envelope).permit
        return kernel, budget, reservation, permit

    def test_exact_order_requires_approval_and_uses_one_permit(self):
        order = self.assessment().order
        actions = frozenset().union(*(grant.allowed_actions for grant in ESSENTIAL_AGENT_GRANTS))
        verifier = CommerceTestVerifier()
        kernel = GovernanceKernel(
            Policy(actions, 3_000, frozenset({"purchase_domain"}), ESSENTIAL_AGENT_GRANTS),
            secret=b"test-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        intent = purchase_intent(order)
        self.assertEqual("require_approval", kernel.evaluate(intent).outcome)
        budget = BudgetAccount()
        reservation = budget.reserve(order, now_ns=NOW)
        envelope = verified_approval(kernel, intent, verifier)
        permit = kernel.evaluate_with_approval(intent, envelope).permit
        registrar = FakeRegistrar(
            RegistrarResult("payment-1", 2_000, "a" * 64, "registration-1", order.domain, order.registrar)
        )
        executor = DomainCommerceExecutor()
        outcome = executor.execute(
            kernel,
            order,
            permit,
            registrar,
            budget,
            reservation.reservation_id,
            now_ns=NOW,
        )
        self.assertTrue(outcome.authorized)
        self.assertTrue(outcome.capability_revoked)
        self.assertEqual(2_000, budget.spent_cents)
        with self.assertRaisesRegex(CommerceViolation, "duplicate"):
            executor.execute(
                kernel,
                order,
                permit,
                registrar,
                budget,
                reservation.reservation_id,
                now_ns=NOW,
            )
        self.assertEqual(1, registrar.calls)

    def test_hard_pilot_ceiling_denies_30_01(self):
        with self.assertRaisesRegex(CommerceViolation, r"\$30"):
            DomainPurchaseRequest(
                request_id="too-high",
                principal="agent:commerce",
                acceptable_domains=("pulpo-proof.example",),
                max_purchase_cents=3_001,
                max_renewal_cents=2_500,
                approved_registrar="name.com",
                owner_ref="owner://iron-ember",
                privacy_required=True,
                prohibited_upsells=(),
                expires_at_ns=NOW + 1,
            )

        quote = DomainQuote(**(self.quote.__dict__ | {"purchase_price_cents": 3_001}))
        assessment = self.assessment(quote=quote)
        self.assertEqual(("deny", "purchase_price_exceeded"), (assessment.outcome, assessment.reason))

    def test_malformed_quote_prices_and_upsells_fail_closed(self):
        with self.assertRaisesRegex(CommerceViolation, "non-negative"):
            DomainQuote(**(self.quote.__dict__ | {"purchase_price_cents": -1}))
        with self.assertRaisesRegex(CommerceViolation, "normalized"):
            DomainQuote(**(self.quote.__dict__ | {"upsells": ("Hosting",)}))

    def test_unapproved_domain_registrar_renewal_and_upsell_are_distinct_denials(self):
        cases = (
            ({"domain": "other.example"}, "domain_not_approved"),
            ({"registrar": "other.example"}, "registrar_not_approved"),
            ({"renewal_price_cents": 2_501}, "renewal_price_exceeded"),
            ({"upsells": ("hosting",)}, "prohibited_upsell"),
        )
        for changes, expected in cases:
            values = self.quote.__dict__ | changes
            with self.subTest(expected=expected):
                decision = self.assessment(quote=DomainQuote(**values))
                self.assertEqual(("deny", expected), (decision.outcome, decision.reason))
                self.assertIsNone(decision.order)

    def test_expiration_ownership_privacy_and_credential_fail_closed(self):
        expired = self.assessment(now_ns=self.request.expires_at_ns)
        owner = self.assessment(quote=DomainQuote(**(self.quote.__dict__ | {"owner_ref": "owner://attacker"})))
        privacy = self.assessment(quote=DomainQuote(**(self.quote.__dict__ | {"privacy_enabled": False})))
        credential = assess_quote(self.request, self.quote, credential_ref="plaintext-secret", now_ns=NOW)
        self.assertEqual("request_expired", expired.reason)
        self.assertEqual("owner_mismatch", owner.reason)
        self.assertEqual("privacy_required", privacy.reason)
        self.assertEqual("credential_reference_invalid", credential.reason)

    def test_exact_order_hash_blocks_substitution(self):
        order = self.assessment().order
        changed_quote = DomainQuote(**(self.quote.__dict__ | {"purchase_price_cents": 2_001, "quote_id": "quote-2"}))
        changed_order = self.assessment(quote=changed_quote).order
        kernel = GovernanceKernel(Policy(frozenset({"purchase_domain"}), 3_000), secret=b"test-secret")
        budget = BudgetAccount()
        reservation = budget.reserve(changed_order, now_ns=NOW)
        permit = kernel.evaluate(purchase_intent(order)).permit
        registrar = FakeRegistrar(RegistrarResult(None, None, None, None, None, None))
        with self.assertRaisesRegex(CommerceViolation, "permit_rejected"):
            DomainCommerceExecutor().execute(
                kernel,
                changed_order,
                permit,
                registrar,
                budget,
                reservation.reservation_id,
                now_ns=NOW,
            )
        self.assertEqual(0, registrar.calls)

    def test_authorized_paid_delivered_accepted_and_valuable_are_separate(self):
        order = self.assessment().order
        kernel, budget, reservation, permit = self.authorized_execution(order)
        registrar = FakeRegistrar(
            RegistrarResult("payment-1", 1_950, "b" * 64, None, None, None)
        )
        outcome = DomainCommerceExecutor().execute(
            kernel,
            order,
            permit,
            registrar,
            budget,
            reservation.reservation_id,
            now_ns=NOW,
        )
        self.assertTrue(outcome.authorized)
        self.assertIsNotNone(outcome.payment)
        self.assertIsNone(outcome.delivery)
        self.assertFalse(outcome.accepted)
        self.assertFalse(outcome.valuable)
        with self.assertRaisesRegex(CommerceViolation, "delivery_not_proven"):
            accept_delivery(
                order,
                outcome,
                VerificationEvidence(order.domain, order.registrar, order.owner_ref, 1, True, "registered"),
            )

    def test_acceptance_requires_independent_ownership_period_privacy_and_dns(self):
        order = self.assessment().order
        kernel, budget, reservation, permit = self.authorized_execution(order)
        result = RegistrarResult("payment-1", 2_000, "c" * 64, "registration-1", order.domain, order.registrar)
        outcome = DomainCommerceExecutor().execute(
            kernel,
            order,
            permit,
            FakeRegistrar(result),
            budget,
            reservation.reservation_id,
            now_ns=NOW,
        )
        wrong_owner = VerificationEvidence(order.domain, order.registrar, "owner://attacker", 1, True, "registered")
        with self.assertRaisesRegex(CommerceViolation, "ownership_not_verified"):
            accept_delivery(order, outcome, wrong_owner)
        self.assertIsNone(outcome.verification)
        verified = VerificationEvidence(order.domain, order.registrar, order.owner_ref, 1, True, "configured")
        accept_delivery(order, outcome, verified)
        self.assertTrue(outcome.accepted)
        self.assertFalse(outcome.valuable)
        record_value(outcome, "domain resolves to the intended service after 24 hours")
        self.assertTrue(outcome.valuable)

    def test_payment_rail_rejects_provider_charge_above_exact_cap(self):
        order = self.assessment().order
        kernel, budget, reservation, permit = self.authorized_execution(order)
        registrar = FakeRegistrar(
            RegistrarResult("payment-1", 2_001, "d" * 64, "registration-1", order.domain, order.registrar)
        )
        with self.assertRaisesRegex(CommerceViolation, "provider_charge_cap_rejected"):
            DomainCommerceExecutor().execute(
                kernel,
                order,
                permit,
                registrar,
                budget,
                reservation.reservation_id,
                now_ns=NOW,
            )

    def test_budget_reservation_rejects_duplicate_insufficient_and_mismatch(self):
        order = self.assessment().order
        budget = BudgetAccount(2_000)
        reservation = budget.reserve(order, now_ns=NOW)
        self.assertEqual(0, budget.available_cents)
        with self.assertRaisesRegex(CommerceViolation, "already_reserved"):
            budget.reserve(order, now_ns=NOW)
        changed_quote = DomainQuote(**(self.quote.__dict__ | {"purchase_price_cents": 1_999, "quote_id": "quote-2"}))
        changed_order = self.assessment(quote=changed_quote).order
        with self.assertRaisesRegex(CommerceViolation, "order_mismatch"):
            budget.require_active(reservation.reservation_id, changed_order, now_ns=NOW)
        with self.assertRaisesRegex(CommerceViolation, "insufficient_available"):
            budget.reserve(changed_order, now_ns=NOW)

    def test_durable_budget_survives_restart_and_blocks_attempt_replay(self):
        order = self.assessment().order
        with TemporaryDirectory() as directory:
            path = Path(directory) / "commerce.sqlite3"
            first = SQLiteBudgetAccount(path)
            reservation = first.reserve(order, now_ns=NOW)
            first.mark_attempted(reservation.reservation_id)

            restarted = SQLiteBudgetAccount(path)
            self.assertEqual(order.purchase_price_cents, restarted.reserved_cents)
            with self.assertRaisesRegex(CommerceViolation, "already_attempted"):
                restarted.require_active(reservation.reservation_id, order, now_ns=NOW)
            with self.assertRaisesRegex(CommerceViolation, "already_reserved"):
                restarted.reserve(order, now_ns=NOW)

    def test_uncertain_external_result_cannot_be_blindly_retried_after_restart(self):
        order = self.assessment().order
        with TemporaryDirectory() as directory:
            path = Path(directory) / "commerce.sqlite3"
            budget = SQLiteBudgetAccount(path)
            reservation = budget.reserve(order, now_ns=NOW)
            kernel = GovernanceKernel(Policy(frozenset({"purchase_domain"}), 3_000), secret=b"test-secret")
            permit = kernel.evaluate(purchase_intent(order)).permit
            uncertain = UncertainRegistrar()

            with self.assertRaisesRegex(ConnectionError, "unknown"):
                DomainCommerceExecutor().execute(
                    kernel,
                    order,
                    permit,
                    uncertain,
                    budget,
                    reservation.reservation_id,
                    now_ns=NOW,
                )
            self.assertEqual(1, uncertain.calls)

            restarted = SQLiteBudgetAccount(path)
            retry_kernel = GovernanceKernel(Policy(frozenset({"purchase_domain"}), 3_000), secret=b"retry-secret")
            retry_permit = retry_kernel.evaluate(purchase_intent(order)).permit
            should_not_run = FakeRegistrar(RegistrarResult(None, None, None, None, None, None))
            with self.assertRaisesRegex(CommerceViolation, "already_attempted"):
                DomainCommerceExecutor().execute(
                    retry_kernel,
                    order,
                    retry_permit,
                    should_not_run,
                    restarted,
                    reservation.reservation_id,
                    now_ns=NOW,
                )
            self.assertEqual(0, should_not_run.calls)

    def test_durable_reconciliation_survives_restart(self):
        order = self.assessment().order
        payment = RegistrarResult("payment-1", 1_950, "e" * 64, None, None, None)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "commerce.sqlite3"
            budget = SQLiteBudgetAccount(path)
            reservation = budget.reserve(order, now_ns=NOW)
            budget.mark_attempted(reservation.reservation_id)
            evidence = PaymentEvidence(payment.payment_id, payment.charged_cents, payment.receipt_hash)
            reconciliation = budget.reconcile(reservation.reservation_id, evidence)

            restarted = SQLiteBudgetAccount(path)
            self.assertEqual(1_950, restarted.spent_cents)
            self.assertEqual(0, restarted.reserved_cents)
            self.assertEqual(1_050, restarted.available_cents)
            self.assertEqual(50, reconciliation.variance_cents)
            with self.assertRaisesRegex(CommerceViolation, "not_attempted"):
                restarted.reconcile(reservation.reservation_id, evidence)

    def test_durable_budget_reservation_is_atomic_between_workers(self):
        first_order = self.assessment().order
        second_quote = DomainQuote(**(self.quote.__dict__ | {"domain": "pulpo-proof-two.example", "quote_id": "quote-2"}))
        second_order = self.assessment(quote=second_quote).order
        with TemporaryDirectory() as directory:
            path = Path(directory) / "commerce.sqlite3"
            SQLiteBudgetAccount(path)
            barrier = Barrier(2)
            results = []

            def reserve(order):
                account = SQLiteBudgetAccount(path)
                barrier.wait()
                try:
                    account.reserve(order, now_ns=NOW)
                    results.append("reserved")
                except CommerceViolation as error:
                    results.append(str(error))

            workers = [Thread(target=reserve, args=(order,)) for order in (first_order, second_order)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()

            self.assertEqual(1, results.count("reserved"))
            self.assertEqual(1, results.count("insufficient_available_budget"))

    def test_durable_budget_requires_stable_path_and_ceiling(self):
        with self.assertRaisesRegex(CommerceViolation, "filesystem path"):
            SQLiteBudgetAccount(":memory:")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "commerce.sqlite3"
            SQLiteBudgetAccount(path, 2_000)
            with self.assertRaisesRegex(CommerceViolation, "does not match"):
                SQLiteBudgetAccount(path, 3_000)

    def test_order_binds_complete_request_and_quote_hashes(self):
        order = self.assessment().order
        self.assertEqual(self.request.request_hash, order.request_hash)
        self.assertEqual(self.quote.quote_hash, order.quote_hash)
        with self.assertRaisesRegex(CommerceViolation, "SHA-256"):
            type(order)(**(order.__dict__ | {"request_hash": "not-a-hash"}))

    def test_bundle_projects_kernel_audit_without_becoming_a_second_ledger(self):
        assessment = self.assessment()
        kernel = GovernanceKernel(Policy(frozenset({"purchase_domain"}), 3_000), secret=b"test-secret")
        kernel.evaluate(purchase_intent(assessment.order))
        bundle = build_proof_bundle(kernel, self.request, self.quote, assessment, None)
        self.assertEqual("pulpo.commerce.proof.v1", bundle["schema"])
        self.assertTrue(bundle["audit_valid"])
        self.assertEqual(64, len(bundle["bundle_hash"]))
        self.assertEqual(kernel.audit[-1]["hash"], bundle["audit_tip"])


if __name__ == "__main__":
    unittest.main()

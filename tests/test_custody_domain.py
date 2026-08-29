import tempfile
import unittest
from pathlib import Path

from pulpo.commerce import DomainPurchaseRequest, DomainQuote, assess_quote, purchase_intent
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 8_000_000
OPERATOR = "operator:owner"


class CustodyDomainIntegrationTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def order(self, domain="pulpo-hostile-worker.example"):
        request = DomainPurchaseRequest(
            request_id="request-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-hostile-worker.example", "pulpo-substitute.example"),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id=f"quote:{domain}",
            domain=domain,
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref="credential://name-com/hostile-worker-v0",
            now_ns=NOW,
        )
        self.assertIsNotNone(assessment.order)
        return assessment.order

    def basic_stack(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-domain-v0",
            clock=lambda: NOW,
        )
        state = SQLiteKernelState(self.path)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"canonical-domain-kernel",
            clock=lambda: NOW,
            state=state,
        )
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody)
        self.addCleanup(state.close)
        return kernel, custody, coordinator

    def test_exact_locked_domain_permit_is_consumed_before_custody_attempt(self):
        kernel, custody, coordinator = self.basic_stack()
        order = self.order()
        intent = purchase_intent(order)
        target = kernel.lock_target("domain-v0", intent)
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)

        attempt = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
        )

        self.assertEqual(order.order_hash, attempt.order_hash)
        self.assertEqual("attempt_authorized", custody.attempt(attempt.attempt_id).state)
        self.assertEqual("permit_consumed", kernel.audit[-1]["event"])
        self.assertTrue(custody.verify_receipt(attempt.custody.receipt))

        with self.assertRaisesRegex(CustodyViolation, "canonical_permit_rejected"):
            coordinator.authorize(
                target_id=target.target_id,
                expected_target_hash=target.target_hash,
                order=order,
                permit=decision.permit,
            )

    def test_substituted_domain_order_fails_before_permit_consumption(self):
        kernel, custody, coordinator = self.basic_stack()
        original = self.order("pulpo-hostile-worker.example")
        substituted = self.order("pulpo-substitute.example")
        intent = purchase_intent(original)
        target = kernel.lock_target("domain-v0", intent)
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)

        with self.assertRaisesRegex(CustodyViolation, "custody_order_target_mismatch"):
            coordinator.authorize(
                target_id=target.target_id,
                expected_target_hash=target.target_hash,
                order=substituted,
                permit=decision.permit,
            )

        # The failed substitution never consumed the exact original permit.
        attempt = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=original,
            permit=decision.permit,
        )
        self.assertEqual("attempt_authorized", custody.attempt(attempt.attempt_id).state)

    def test_revoked_directive_is_revalidated_before_custody_attempt(self):
        verifier = HmacTestVerifier()
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-domain-v0",
            clock=lambda: NOW,
        )
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            Policy(
                frozenset({"purchase_domain", "activate_directive", "revoke_directive"}),
                3_000,
                frozenset({"activate_directive", "revoke_directive"}),
                authority_trust=trust_for(verifier),
            ),
            secret=b"directive-domain-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody)
        order = self.order()
        intent = purchase_intent(order)
        target = kernel.lock_target("directive-domain-v0", intent)
        directive = Directive(
            directive_id="directive-domain-v0",
            version=1,
            issuer_authority_id=verifier.authority_id,
            principal=intent.principal,
            allowed_actions=frozenset({"purchase_domain"}),
            resource_prefixes=("commerce:domain:",),
            max_cost=3_000,
            issued_at_ns=NOW - 1_000,
            expires_at_ns=NOW + 100_000,
        )
        controller = DirectiveAuthorityController(kernel)
        activation_intent = controller.authority_intent(
            controller.ACTIVATE,
            directive,
            operator_principal=OPERATOR,
        )
        activation = signed_envelope(
            kernel,
            activation_intent,
            verifier,
            now_ns=NOW - 10,
            approval_id="approval-domain-activate",
            nonce="nonce-domain-activate",
        )
        self.assertEqual(
            "allow",
            controller.activate(
                directive,
                activation,
                operator_principal=OPERATOR,
            ).outcome,
        )

        decision = GovernedDirectiveProjection(kernel).evaluate(intent, directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revocation_intent = controller.authority_intent(
            controller.REVOKE,
            directive,
            operator_principal=OPERATOR,
        )
        revocation = signed_envelope(
            kernel,
            revocation_intent,
            verifier,
            now_ns=NOW - 10,
            approval_id="approval-domain-revoke",
            nonce="nonce-domain-revoke",
        )
        self.assertEqual(
            "allow",
            controller.revoke(
                directive,
                revocation,
                operator_principal=OPERATOR,
            ).outcome,
        )

        with self.assertRaisesRegex(CustodyViolation, "canonical_permit_rejected"):
            coordinator.authorize(
                target_id=target.target_id,
                expected_target_hash=target.target_hash,
                order=order,
                permit=decision.permit,
            )
        self.assertEqual(0, custody.snapshot().epoch)

    def test_worker_rollback_after_restart_cannot_restore_consumed_domain_permit(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-domain-v0",
            clock=lambda: NOW,
        )
        state = SQLiteKernelState(self.path)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"canonical-domain-kernel",
            clock=lambda: NOW,
            state=state,
        )
        order = self.order()
        intent = purchase_intent(order)
        target = kernel.lock_target("restart-domain-v0", intent)
        decision = kernel.evaluate(intent)
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody)
        first = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
        )
        self.assertEqual("attempt_authorized", custody.attempt(first.attempt_id).state)
        state.close()

        restarted_state = SQLiteKernelState(self.path)
        self.addCleanup(restarted_state.close)
        restarted_kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"canonical-domain-kernel",
            clock=lambda: NOW,
            state=restarted_state,
        )
        restarted_custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-domain-v0",
            clock=lambda: NOW,
        )
        restarted = GovernedDomainAttemptCoordinator(restarted_kernel, restarted_custody)

        with self.assertRaisesRegex(CustodyViolation, "canonical_permit_rejected"):
            restarted.authorize(
                target_id=target.target_id,
                expected_target_hash=target.target_hash,
                order=order,
                permit=decision.permit,
            )
        self.assertEqual(1, restarted_custody.snapshot().epoch)


if __name__ == "__main__":
    unittest.main()

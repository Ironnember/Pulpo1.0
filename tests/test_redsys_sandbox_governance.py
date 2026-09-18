import tempfile
import unittest
from pathlib import Path

from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.execution_context import ExecutionContext
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.redsys import (
    REDSYS_PRODUCTION_ORIGIN,
    REDSYS_SANDBOX_ORIGIN,
    RedsysExternalRealityUnknown,
    RedsysPayment,
    RedsysSandboxGateway,
    RedsysViolation,
    payment_intent,
    refund_intent,
)
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 10_000_000
PRINCIPAL = "agent:commerce"
SESSION = "redsys-sandbox-proof-1"
MERCHANT = "999008881"
TERMINAL = "001"


class RecordingTransport:
    def __init__(self, *, response=None, error=None):
        self.calls = []
        self.response = response
        self.error = error

    def __call__(self, origin, path, payload):
        self.calls.append((origin, path, dict(payload)))
        if self.error is not None:
            raise self.error
        if self.response is not None:
            return dict(self.response)
        return {
            **dict(payload),
            "provider_reference": "sandbox-ref-1",
            "result": "approved",
        }


class RedsysSandboxGovernanceTests(unittest.TestCase):
    def payment(self, **overrides):
        values = {
            "merchant_code": MERCHANT,
            "terminal": TERMINAL,
            "order_id": "PULPO000001",
            "amount_cents": 123,
            "currency": "978",
            "transaction_type": "0",
            "principal": PRINCIPAL,
            "session_id": SESSION,
            "expires_at_ns": NOW + 100_000,
        }
        values.update(overrides)
        return RedsysPayment(**values)

    def basic_kernel(self, *, state=None):
        return GovernanceKernel(
            Policy(frozenset({"redsys_payment", "redsys_refund"}), 3_000),
            secret=b"redsys-sandbox-kernel-secret",
            clock=lambda: NOW,
            state=state,
        )

    def authorized(self, payment, *, kernel=None):
        kernel = kernel or self.basic_kernel()
        intent = payment_intent(payment)
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return kernel, intent, decision.permit

    def test_no_permit_makes_zero_provider_calls(self):
        payment = self.payment()
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        with self.assertRaisesRegex(RedsysViolation, "permit_required"):
            gateway.execute_payment(
                kernel=self.basic_kernel(),
                permit=None,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )
        self.assertEqual([], transport.calls)

    def test_amount_substitution_is_denied_before_provider_call(self):
        original = self.payment()
        substituted = self.payment(amount_cents=124)
        kernel, _, permit = self.authorized(original)
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=substituted,
                observed_context=substituted.expected_context,
                now_ns=NOW,
            )
        self.assertEqual([], transport.calls)

    def test_currency_substitution_is_denied_before_provider_call(self):
        original = self.payment()
        substituted = self.payment(currency="840")
        kernel, _, permit = self.authorized(original)
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=substituted,
                observed_context=substituted.expected_context,
                now_ns=NOW,
            )
        self.assertEqual([], transport.calls)

    def test_order_substitution_is_denied_before_provider_call(self):
        original = self.payment()
        substituted = self.payment(order_id="PULPO000002")
        kernel, _, permit = self.authorized(original)
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=substituted,
                observed_context=substituted.expected_context,
                now_ns=NOW,
            )
        self.assertEqual([], transport.calls)

    def test_merchant_or_terminal_substitution_is_denied_before_provider_call(self):
        for substituted in (
            self.payment(merchant_code="999008882"),
            self.payment(terminal="002"),
        ):
            with self.subTest(payment=substituted):
                original = self.payment()
                kernel, _, permit = self.authorized(original)
                transport = RecordingTransport()
                gateway = RedsysSandboxGateway(transport=transport)
                with self.assertRaises(RedsysViolation):
                    gateway.execute_payment(
                        kernel=kernel,
                        permit=permit,
                        payment=substituted,
                        observed_context=substituted.expected_context,
                        now_ns=NOW,
                    )
                self.assertEqual([], transport.calls)

    def test_production_origin_is_rejected_at_adapter_construction(self):
        with self.assertRaisesRegex(RedsysViolation, "production_origin_forbidden"):
            RedsysSandboxGateway(
                origin=REDSYS_PRODUCTION_ORIGIN,
                transport=RecordingTransport(),
            )

    def test_execution_context_mismatch_is_denied_before_provider_call(self):
        payment = self.payment()
        kernel, _, permit = self.authorized(payment)
        wrong_context = ExecutionContext(
            surface="redsys",
            authority_scope="merchant:other:terminal:999:environment:sandbox",
            principal=PRINCIPAL,
            connection=f"origin:{REDSYS_SANDBOX_ORIGIN}",
        )
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        with self.assertRaisesRegex(RedsysViolation, "execution_context_mismatch"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=wrong_context,
                now_ns=NOW,
            )
        self.assertEqual([], transport.calls)

    def test_one_use_replay_cannot_make_second_provider_call(self):
        payment = self.payment()
        kernel, _, permit = self.authorized(payment)
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)

        result = gateway.execute_payment(
            kernel=kernel,
            permit=permit,
            payment=payment,
            observed_context=payment.expected_context,
            now_ns=NOW,
        )
        self.assertEqual("approved", result.receipt.result)

        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )
        self.assertEqual(1, len(transport.calls))

    def test_revocation_after_permit_issue_denies_before_provider_call(self):
        verifier = HmacTestVerifier()
        kernel = GovernanceKernel(
            Policy(
                frozenset(
                    {
                        "redsys_payment",
                        "activate_directive",
                        "revoke_directive",
                    }
                ),
                3_000,
                frozenset({"activate_directive", "revoke_directive"}),
                authority_trust=trust_for(verifier),
            ),
            secret=b"redsys-directive-kernel-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        payment = self.payment()
        intent = payment_intent(payment)
        directive = Directive(
            directive_id="redsys-sandbox-v0",
            version=1,
            issuer_authority_id=verifier.authority_id,
            principal=PRINCIPAL,
            allowed_actions=frozenset({"redsys_payment"}),
            resource_prefixes=(intent.resource,),
            max_cost=3_000,
            issued_at_ns=NOW - 1_000,
            expires_at_ns=NOW + 100_000,
        )
        controller = DirectiveAuthorityController(kernel)
        activate_intent = controller.authority_intent(
            controller.ACTIVATE,
            directive,
            operator_principal="operator:owner",
        )
        activate = signed_envelope(
            kernel,
            activate_intent,
            verifier,
            now_ns=NOW - 10,
            approval_id="redsys-activate",
            nonce="redsys-activate-nonce",
        )
        self.assertEqual(
            "allow",
            controller.activate(
                directive,
                activate,
                operator_principal="operator:owner",
            ).outcome,
        )

        decision = GovernedDirectiveProjection(kernel).evaluate(intent, directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revoke_intent = controller.authority_intent(
            controller.REVOKE,
            directive,
            operator_principal="operator:owner",
        )
        revoke = signed_envelope(
            kernel,
            revoke_intent,
            verifier,
            now_ns=NOW - 10,
            approval_id="redsys-revoke",
            nonce="redsys-revoke-nonce",
        )
        self.assertEqual(
            "allow",
            controller.revoke(
                directive,
                revoke,
                operator_principal="operator:owner",
            ).outcome,
        )

        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=decision.permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )
        self.assertEqual([], transport.calls)

    def test_restart_does_not_restore_spent_payment_authority(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))

        state = SQLiteKernelState(path)
        kernel = self.basic_kernel(state=state)
        payment = self.payment()
        _, _, permit = self.authorized(payment, kernel=kernel)
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)
        gateway.execute_payment(
            kernel=kernel,
            permit=permit,
            payment=payment,
            observed_context=payment.expected_context,
            now_ns=NOW,
        )
        state.close()

        restarted_state = SQLiteKernelState(path)
        self.addCleanup(restarted_state.close)
        restarted_kernel = self.basic_kernel(state=restarted_state)
        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=restarted_kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )
        self.assertEqual(1, len(transport.calls))

    def test_payment_permit_does_not_authorize_refund(self):
        payment = self.payment()
        kernel, _, permit = self.authorized(payment)
        self.assertFalse(kernel.consume(permit, refund_intent(payment)))
        self.assertTrue(kernel.consume(permit, payment_intent(payment)))

    def test_network_ambiguity_consumes_authority_and_never_auto_retries(self):
        payment = self.payment()
        kernel, _, permit = self.authorized(payment)
        transport = RecordingTransport(error=TimeoutError("simulated timeout"))
        gateway = RedsysSandboxGateway(transport=transport)

        with self.assertRaisesRegex(
            RedsysExternalRealityUnknown,
            "external_reality_unknown",
        ):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )

        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )
        self.assertEqual(1, len(transport.calls))

    def test_mismatched_provider_response_is_not_accepted_or_retryable(self):
        payment = self.payment()
        kernel, _, permit = self.authorized(payment)
        response = {
            "merchant_code": MERCHANT,
            "terminal": TERMINAL,
            "order_id": "SUBSTITUTED",
            "amount_cents": payment.amount_cents,
            "currency": payment.currency,
            "transaction_type": payment.transaction_type,
            "environment": "sandbox",
            "payment_hash": payment.payment_hash,
            "provider_reference": "sandbox-ref-mismatch",
            "result": "approved",
        }
        transport = RecordingTransport(response=response)
        gateway = RedsysSandboxGateway(transport=transport)

        with self.assertRaisesRegex(RedsysViolation, "response_object_mismatch"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )

        with self.assertRaisesRegex(RedsysViolation, "permit_rejected"):
            gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=NOW,
            )
        self.assertEqual(1, len(transport.calls))

    def test_exact_positive_control_makes_one_call_and_returns_evidence_only(self):
        payment = self.payment()
        kernel, _, permit = self.authorized(payment)
        transport = RecordingTransport()
        gateway = RedsysSandboxGateway(transport=transport)

        result = gateway.execute_payment(
            kernel=kernel,
            permit=permit,
            payment=payment,
            observed_context=payment.expected_context,
            now_ns=NOW,
        )

        self.assertEqual(1, len(transport.calls))
        origin, _path, payload = transport.calls[0]
        self.assertEqual(REDSYS_SANDBOX_ORIGIN, origin)
        self.assertEqual(payment.payment_hash, payload["payment_hash"])
        self.assertEqual("approved", result.receipt.result)
        self.assertEqual(payment.payment_hash, result.receipt.payment_hash)
        self.assertEqual("none", result.receipt.authority_effect)


if __name__ == "__main__":
    unittest.main()

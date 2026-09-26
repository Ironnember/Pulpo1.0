import unittest

from pulpo import GovernanceKernel, Intent, Policy
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 7_000_000
SESSION = "capability-activation-proof-1"
PRINCIPAL = "agent:assistant"
CASE = "conversation:attachment-only-case"


class CapabilityActivationAuthorityTests(unittest.TestCase):
    """Prove that capability elevation is governable before any downstream effect.

    This is a kernel proof, not a claim about how any external product chooses a
    UI mode. It models a mode/capability transition as an exact Pulpo intent and
    proves that existing approval and one-use permit semantics can keep that
    transition separate from ordinary read-only inspection.
    """

    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"inspect_attachment", "activate_capability"}),
            0,
            frozenset({"activate_capability"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"capability-activation-proof-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.inspect = Intent(
            PRINCIPAL,
            "inspect_attachment",
            f"{CASE}:attachment:image",
            0,
            SESSION,
        )
        self.activate_work = Intent(
            PRINCIPAL,
            "activate_capability",
            f"{CASE}:capability:work",
            0,
            SESSION,
        )

    def test_read_only_permission_does_not_authorize_capability_activation(self):
        inspection = self.kernel.evaluate(self.inspect)
        activation = self.kernel.evaluate(self.activate_work)

        self.assertEqual("allow", inspection.outcome)
        self.assertIsNotNone(inspection.permit)
        self.assertEqual(
            ("require_approval", "approval_required", None),
            (activation.outcome, activation.reason, activation.permit),
        )

    def test_inspection_permit_cannot_be_substituted_for_activation(self):
        decision = self.kernel.evaluate(self.inspect)
        self.assertEqual("allow", decision.outcome)

        self.assertFalse(self.kernel.consume(decision.permit, self.activate_work))
        self.assertTrue(self.kernel.consume(decision.permit, self.inspect))
        self.assertFalse(self.kernel.consume(decision.permit, self.inspect))

    def test_exact_approval_issues_one_bound_activation_permit(self):
        envelope = signed_envelope(
            self.kernel,
            self.activate_work,
            self.verifier,
            now_ns=NOW,
        )
        decision = self.kernel.evaluate_with_approval(self.activate_work, envelope)

        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.kernel.consume(decision.permit, self.activate_work))
        self.assertFalse(self.kernel.consume(decision.permit, self.activate_work))

    def test_activation_approval_cannot_be_retargeted(self):
        envelope = signed_envelope(
            self.kernel,
            self.activate_work,
            self.verifier,
            now_ns=NOW,
        )
        substituted = Intent(
            PRINCIPAL,
            "activate_capability",
            "conversation:other-case:capability:work",
            0,
            SESSION,
        )

        decision = self.kernel.evaluate_with_approval(substituted, envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch", None),
            (decision.outcome, decision.reason, decision.permit),
        )


class WorkModeSpendAuthorityBoundaryTests(unittest.TestCase):
    """Prove task, execution-environment, and spend authority remain distinct."""

    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"continue_task", "activate_capability", "spend_credits"}),
            10,
            frozenset({"activate_capability", "spend_credits"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"work-mode-spend-boundary-proof",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.task = Intent(
            PRINCIPAL,
            "continue_task",
            "conversation:pulpo-proof:task",
            0,
            SESSION,
        )
        self.activate_work = Intent(
            PRINCIPAL,
            "activate_capability",
            "conversation:pulpo-proof:execution-environment:work",
            0,
            SESSION,
        )
        self.spend = Intent(
            PRINCIPAL,
            "spend_credits",
            "conversation:pulpo-proof:execution-environment:work:credits",
            1,
            SESSION,
        )

    def _approval(self, intent, approval_id, nonce):
        return signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )

    def test_parent_task_authority_does_not_authorize_work_or_spend(self):
        task = self.kernel.evaluate(self.task)
        activation = self.kernel.evaluate(self.activate_work)
        spend = self.kernel.evaluate(self.spend)

        self.assertEqual("allow", task.outcome)
        self.assertEqual(("require_approval", None), (activation.outcome, activation.permit))
        self.assertEqual(("require_approval", None), (spend.outcome, spend.permit))
        self.assertFalse(self.kernel.consume(task.permit, self.activate_work))
        self.assertFalse(self.kernel.consume(task.permit, self.spend))
        self.assertTrue(self.kernel.consume(task.permit, self.task))

    def test_work_activation_approval_cannot_authorize_credit_spend(self):
        envelope = self._approval(self.activate_work, "approve-work-mode", "nonce-work-mode")
        activation = self.kernel.evaluate_with_approval(self.activate_work, envelope)
        retargeted = self.kernel.evaluate_with_approval(self.spend, envelope)

        self.assertEqual("allow", activation.outcome)
        self.assertEqual(("deny", "approval_intent_mismatch"), (retargeted.outcome, retargeted.reason))
        self.assertFalse(self.kernel.consume(activation.permit, self.spend))
        self.assertTrue(self.kernel.consume(activation.permit, self.activate_work))

    def test_credit_spend_requires_separate_exact_one_use_approval(self):
        activation_envelope = self._approval(
            self.activate_work,
            "approve-work-mode-separate",
            "nonce-work-mode-separate",
        )
        activation = self.kernel.evaluate_with_approval(self.activate_work, activation_envelope)
        self.assertTrue(self.kernel.consume(activation.permit, self.activate_work))

        spend_envelope = self._approval(self.spend, "approve-credit-spend", "nonce-credit-spend")
        spend = self.kernel.evaluate_with_approval(self.spend, spend_envelope)

        self.assertEqual("allow", spend.outcome)
        self.assertTrue(self.kernel.consume(spend.permit, self.spend))
        self.assertFalse(self.kernel.consume(spend.permit, self.spend))

    def test_credit_amount_substitution_invalidates_spend_approval(self):
        envelope = self._approval(self.spend, "approve-one-credit", "nonce-one-credit")
        substituted = Intent(
            PRINCIPAL,
            "spend_credits",
            self.spend.resource,
            2,
            SESSION,
        )

        decision = self.kernel.evaluate_with_approval(substituted, envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch", None),
            (decision.outcome, decision.reason, decision.permit),
        )


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

import unittest

from pulpo import GovernanceKernel, Intent, Policy
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 8_000_000
SESSION = "capability-derivation-proof-1"
PRINCIPAL = "agent:assistant"
CASE = "conversation:authenticated-browser-inspection"


class CapabilityDerivationDuplicationTests(unittest.TestCase):
    """Prove that authority to use a capability does not authorize deriving a new one.

    This is a kernel proof. It does not claim that Pulpo currently controls Chrome,
    browser cookies, SSO sessions, or external debugging surfaces. It proves that
    use and derivation/duplication can be represented as distinct governed intents
    and cannot share permits or approvals.
    """

    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset(
                {
                    "use_capability",
                    "duplicate_capability",
                    "export_capability",
                    "expose_capability",
                }
            ),
            0,
            frozenset(
                {
                    "duplicate_capability",
                    "export_capability",
                    "expose_capability",
                }
            ),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"capability-derivation-proof-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.use_session = Intent(
            PRINCIPAL,
            "use_capability",
            f"{CASE}:capability:existing-session",
            0,
            SESSION,
        )
        self.duplicate_session = Intent(
            PRINCIPAL,
            "duplicate_capability",
            f"{CASE}:capability:existing-session",
            0,
            SESSION,
        )

    def test_use_authority_does_not_authorize_duplication(self):
        use = self.kernel.evaluate(self.use_session)
        duplicate = self.kernel.evaluate(self.duplicate_session)

        self.assertEqual("allow", use.outcome)
        self.assertIsNotNone(use.permit)
        self.assertEqual(
            ("require_approval", "approval_required", None),
            (duplicate.outcome, duplicate.reason, duplicate.permit),
        )

    def test_use_permit_cannot_be_substituted_for_duplication(self):
        decision = self.kernel.evaluate(self.use_session)
        self.assertEqual("allow", decision.outcome)

        self.assertFalse(self.kernel.consume(decision.permit, self.duplicate_session))
        self.assertTrue(self.kernel.consume(decision.permit, self.use_session))
        self.assertFalse(self.kernel.consume(decision.permit, self.use_session))

    def test_exact_approval_issues_one_bound_duplication_permit(self):
        envelope = signed_envelope(
            self.kernel,
            self.duplicate_session,
            self.verifier,
            now_ns=NOW,
        )
        decision = self.kernel.evaluate_with_approval(self.duplicate_session, envelope)

        self.assertEqual(
            ("allow", "verified_approval"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.kernel.consume(decision.permit, self.duplicate_session))
        self.assertFalse(self.kernel.consume(decision.permit, self.duplicate_session))

    def test_duplication_approval_cannot_be_reinterpreted_as_export(self):
        envelope = signed_envelope(
            self.kernel,
            self.duplicate_session,
            self.verifier,
            now_ns=NOW,
        )
        export = Intent(
            PRINCIPAL,
            "export_capability",
            f"{CASE}:capability:existing-session",
            0,
            SESSION,
        )

        decision = self.kernel.evaluate_with_approval(export, envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch", None),
            (decision.outcome, decision.reason, decision.permit),
        )

    def test_duplication_approval_cannot_be_retargeted(self):
        envelope = signed_envelope(
            self.kernel,
            self.duplicate_session,
            self.verifier,
            now_ns=NOW,
        )
        other = Intent(
            PRINCIPAL,
            "duplicate_capability",
            "conversation:other-case:capability:other-session",
            0,
            SESSION,
        )

        decision = self.kernel.evaluate_with_approval(other, envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch", None),
            (decision.outcome, decision.reason, decision.permit),
        )


if __name__ == "__main__":
    unittest.main()

import unittest

from pulpo import GovernanceKernel, Intent, Policy
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000


class CeremonyProvenanceGapTests(unittest.TestCase):
    """Expose the current gap between a valid signer and proven human ceremony."""

    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.kernel = GovernanceKernel(
            Policy(
                frozenset({"push"}),
                0,
                frozenset({"push"}),
                authority_trust=trust_for(self.verifier),
            ),
            secret=b"ceremony-provenance-gap-proof",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.intent = Intent(
            "agent:publisher",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/main",
            0,
            "ceremony-gap-session",
        )

    @unittest.expectedFailure
    def test_signature_without_independently_verifiable_ceremony_must_be_denied(self):
        # Deliberately bypass AuthorityService.approve(), WebAuthn verification,
        # credential lookup, and the authority evidence sink. This helper signs
        # the envelope directly with the already trusted verifier material.
        envelope = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=NOW,
        )

        decision = self.kernel.evaluate_with_approval(self.intent, envelope)

        # Constitutional target. This currently fails because pulpo.approval.v2
        # carries no independently verifiable ceremony/evidence provenance and
        # the kernel therefore accepts the otherwise-valid signature.
        self.assertEqual(
            ("deny", "approval_ceremony_proof_missing"),
            (decision.outcome, decision.reason),
        )


if __name__ == "__main__":
    unittest.main()

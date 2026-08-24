import hashlib
import hmac
import unittest
from dataclasses import replace

from pulpo import ApprovalEnvelope, GovernanceKernel, Intent, Policy


NOW = 1_000_000
SESSION = "commerce-proof-1"


class HmacTestVerifier:
    """Test double only; production signer material must be outside Pulpo."""

    authority_id = "authority:test-owner"

    def __init__(self, secret=b"external-test-authority"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def signed_envelope(kernel, intent, verifier, **changes):
    values = {
        "approval_id": "approval-1",
        "authority_id": verifier.authority_id,
        "session_id": SESSION,
        "principal": intent.principal,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "nonce": "approval-nonce-1",
        "expires_at_ns": NOW + 1_000,
        "signature": "",
    }
    values.update(changes)
    unsigned = ApprovalEnvelope(**values)
    return replace(unsigned, signature=verifier.sign(unsigned.signing_bytes()))


class VerifiedApprovalTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(frozenset({"read", "push"}), 100, frozenset({"push"}))
        self.kernel = GovernanceKernel(self.policy, secret=b"permit-secret", approval_verifier=self.verifier)
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0)

    def test_valid_external_envelope_issues_one_bound_permit(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier)
        decision = self.kernel.evaluate_with_approval(self.intent, envelope, session_id=SESSION, now_ns=NOW)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.kernel.consume(decision.permit, self.intent))
        self.assertFalse(self.kernel.consume(decision.permit, self.intent))
        self.assertTrue(any(record["event"] == "approval_verified" for record in self.kernel.audit))

    def test_envelope_bindings_fail_closed_even_with_valid_authority_signature(self):
        cases = (
            ({"authority_id": "authority:other"}, "approval_authority_mismatch", SESSION, self.intent),
            ({"session_id": "other-session"}, "approval_session_mismatch", SESSION, self.intent),
            ({"principal": "agent:other"}, "approval_principal_mismatch", SESSION, self.intent),
            ({"intent_hash": "a" * 64}, "approval_intent_mismatch", SESSION, self.intent),
            ({"policy_hash": "b" * 64}, "approval_policy_mismatch", SESSION, self.intent),
            ({"expires_at_ns": NOW}, "approval_expired", SESSION, self.intent),
        )
        for changes, expected, session_id, intent in cases:
            with self.subTest(expected=expected):
                envelope = signed_envelope(self.kernel, intent, self.verifier, **changes)
                decision = self.kernel.evaluate_with_approval(intent, envelope, session_id=session_id, now_ns=NOW)
                self.assertEqual(("deny", expected), (decision.outcome, decision.reason))

    def test_invalid_or_missing_signature_fails_closed(self):
        valid = signed_envelope(self.kernel, self.intent, self.verifier)
        invalid = replace(valid, signature="invalid")
        missing = replace(valid, signature="")
        self.assertEqual(
            "approval_signature_invalid",
            self.kernel.evaluate_with_approval(self.intent, invalid, session_id=SESSION, now_ns=NOW).reason,
        )
        self.assertEqual(
            "approval_signature_missing",
            self.kernel.evaluate_with_approval(self.intent, missing, session_id=SESSION, now_ns=NOW).reason,
        )

    def test_approval_id_and_nonce_are_each_single_use(self):
        first = signed_envelope(self.kernel, self.intent, self.verifier)
        self.assertEqual(
            "allow",
            self.kernel.evaluate_with_approval(self.intent, first, session_id=SESSION, now_ns=NOW).outcome,
        )
        self.assertEqual(
            "approval_id_replayed",
            self.kernel.evaluate_with_approval(self.intent, first, session_id=SESSION, now_ns=NOW).reason,
        )
        same_nonce = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            approval_id="approval-2",
            nonce=first.nonce,
        )
        self.assertEqual(
            "approval_nonce_replayed",
            self.kernel.evaluate_with_approval(self.intent, same_nonce, session_id=SESSION, now_ns=NOW).reason,
        )

    def test_verifier_is_configured_at_kernel_boundary(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier)
        kernel = GovernanceKernel(self.policy, secret=b"permit-secret")
        envelope = signed_envelope(kernel, self.intent, self.verifier)
        decision = kernel.evaluate_with_approval(self.intent, envelope, session_id=SESSION, now_ns=NOW)
        self.assertEqual("approval_verifier_unavailable", decision.reason)

    def test_configured_verifier_disables_caller_boolean_bypass(self):
        decision = self.kernel.evaluate(self.intent, approved=True)
        self.assertEqual(("deny", "caller_approval_disabled"), (decision.outcome, decision.reason))

    def test_verifier_exception_fails_closed(self):
        class BrokenVerifier(HmacTestVerifier):
            def verify(self, payload, signature):
                raise RuntimeError("signer unavailable")

        verifier = BrokenVerifier()
        kernel = GovernanceKernel(self.policy, secret=b"permit-secret", approval_verifier=verifier)
        envelope = signed_envelope(kernel, self.intent, verifier)
        decision = kernel.evaluate_with_approval(self.intent, envelope, session_id=SESSION, now_ns=NOW)
        self.assertEqual(("deny", "approval_verifier_failed"), (decision.outcome, decision.reason))

    def test_approval_path_rejects_actions_that_do_not_need_approval(self):
        intent = Intent("agent:publisher", "read", "repo:README.md", 0)
        envelope = signed_envelope(self.kernel, intent, self.verifier)
        decision = self.kernel.evaluate_with_approval(intent, envelope, session_id=SESSION, now_ns=NOW)
        self.assertEqual("approval_not_required", decision.reason)

    def test_policy_hash_is_canonical(self):
        first = GovernanceKernel(Policy(frozenset({"read", "push"}), 100, frozenset({"push"})))
        second = GovernanceKernel(Policy(frozenset({"push", "read"}), 100, frozenset({"push"})))
        self.assertEqual(first.policy_hash, second.policy_hash)

    def test_malformed_envelope_is_rejected_before_verification(self):
        with self.assertRaisesRegex(ValueError, "intent_hash"):
            ApprovalEnvelope(
                "approval",
                self.verifier.authority_id,
                SESSION,
                self.intent.principal,
                "not-a-hash",
                self.kernel.policy_hash,
                "nonce",
                NOW + 1,
                "signature",
            )


if __name__ == "__main__":
    unittest.main()

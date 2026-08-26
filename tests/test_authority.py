import inspect
import unittest
from dataclasses import replace

from pulpo import ApprovalEnvelope, AuthorityTrustError, GovernanceKernel, Intent, Policy
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
SESSION = "commerce-proof-1"


class VerifiedApprovalTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"permit-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, SESSION)

    def test_valid_external_envelope_issues_one_bound_permit(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        decision = self.kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.kernel.consume(decision.permit, self.intent))
        self.assertFalse(self.kernel.consume(decision.permit, self.intent))
        self.assertTrue(any(record["event"] == "approval_verified" for record in self.kernel.audit))

    def test_envelope_bindings_fail_closed_even_with_valid_authority_signature(self):
        cases = (
            ({"authority_id": "authority:other"}, "approval_authority_mismatch", self.intent),
            ({"verifier_id": "verifier:other"}, "approval_verifier_mismatch", self.intent),
            ({"key_id": "key:other"}, "approval_key_mismatch", self.intent),
            ({"deployment_id": "deployment:other"}, "approval_deployment_mismatch", self.intent),
            ({"trust_hash": "c" * 64}, "approval_trust_mismatch", self.intent),
            ({"session_id": "other-session"}, "approval_session_mismatch", self.intent),
            ({"principal": "agent:other"}, "approval_principal_mismatch", self.intent),
            ({"intent_hash": "a" * 64}, "approval_intent_mismatch", self.intent),
            ({"policy_hash": "b" * 64}, "approval_policy_mismatch", self.intent),
            ({"issued_at_ns": NOW - 1_000, "expires_at_ns": NOW}, "approval_expired", self.intent),
        )
        for changes, expected, intent in cases:
            with self.subTest(expected=expected):
                envelope = signed_envelope(self.kernel, intent, self.verifier, now_ns=NOW, **changes)
                decision = self.kernel.evaluate_with_approval(intent, envelope)
                self.assertEqual(("deny", expected), (decision.outcome, decision.reason))

    def test_invalid_or_missing_signature_fails_closed(self):
        valid = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        invalid = replace(valid, signature="invalid")
        missing = replace(valid, signature="")
        self.assertEqual(
            "approval_signature_invalid",
            self.kernel.evaluate_with_approval(self.intent, invalid).reason,
        )
        self.assertEqual(
            "approval_signature_missing",
            self.kernel.evaluate_with_approval(self.intent, missing).reason,
        )

    def test_approval_id_and_nonce_are_each_single_use(self):
        first = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        self.assertEqual(
            "allow",
            self.kernel.evaluate_with_approval(self.intent, first).outcome,
        )
        self.assertEqual(
            "approval_id_replayed",
            self.kernel.evaluate_with_approval(self.intent, first).reason,
        )
        same_nonce = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-2",
            nonce=first.nonce,
        )
        self.assertEqual(
            "approval_nonce_replayed",
            self.kernel.evaluate_with_approval(self.intent, same_nonce).reason,
        )

    def test_verifier_is_configured_at_kernel_boundary(self):
        kernel = GovernanceKernel(self.policy, secret=b"permit-secret", clock=lambda: NOW)
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual("approval_verifier_unavailable", decision.reason)

    def test_caller_boolean_bypass_is_removed_for_every_kernel(self):
        self.assertNotIn("approved", inspect.signature(self.kernel.evaluate).parameters)
        for kernel in (self.kernel, GovernanceKernel(self.policy, secret=b"permit-secret")):
            with self.subTest(verifier=kernel is self.kernel):
                with self.assertRaises(TypeError):
                    kernel.evaluate(self.intent, approved=True)
                with self.assertRaises(TypeError):
                    kernel.evaluate(self.intent, True)

    def test_session_and_time_are_not_caller_controlled(self):
        parameters = inspect.signature(self.kernel.evaluate_with_approval).parameters
        self.assertNotIn("session_id", parameters)
        self.assertNotIn("now_ns", parameters)
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        with self.assertRaises(TypeError):
            self.kernel.evaluate_with_approval(self.intent, envelope, now_ns=NOW)
        changed_session = replace(self.intent, session_id="attacker-session")
        self.assertEqual(
            "approval_session_mismatch",
            self.kernel.evaluate_with_approval(changed_session, envelope).reason,
        )

        clock = [NOW]
        kernel = GovernanceKernel(
            self.policy,
            secret=b"permit-secret",
            approval_verifier=self.verifier,
            clock=lambda: clock[0],
        )
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        clock[0] = envelope.expires_at_ns
        self.assertEqual("approval_expired", kernel.evaluate_with_approval(self.intent, envelope).reason)

    def test_verifier_exception_fails_closed(self):
        class BrokenVerifier(HmacTestVerifier):
            def verify(self, payload, signature):
                raise RuntimeError("signer unavailable")

        verifier = BrokenVerifier()
        kernel = GovernanceKernel(
            self.policy,
            secret=b"permit-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        envelope = signed_envelope(kernel, self.intent, verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("deny", "approval_verifier_failed"), (decision.outcome, decision.reason))

    def test_approval_path_rejects_actions_that_do_not_need_approval(self):
        intent = Intent("agent:publisher", "read", "repo:README.md", 0, SESSION)
        envelope = signed_envelope(self.kernel, intent, self.verifier, now_ns=NOW)
        decision = self.kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual("approval_not_required", decision.reason)

    def test_malformed_envelope_object_fails_closed(self):
        decision = self.kernel.evaluate_with_approval(self.intent, object())
        self.assertEqual(("deny", "approval_envelope_invalid"), (decision.outcome, decision.reason))

    def test_policy_hash_is_canonical(self):
        trust = trust_for(self.verifier)
        first = GovernanceKernel(
            Policy(frozenset({"read", "push"}), 100, frozenset({"push"}), authority_trust=trust)
        )
        second = GovernanceKernel(
            Policy(frozenset({"push", "read"}), 100, frozenset({"push"}), authority_trust=trust)
        )
        self.assertEqual(first.policy_hash, second.policy_hash)

    def test_policy_requires_and_hashes_pinned_authority_trust(self):
        with self.assertRaisesRegex(ValueError, "pinned authority trust"):
            Policy(frozenset({"push"}), 100, frozenset({"push"}))
        rotated = replace(self.policy.authority_trust, key_id="key:test-only:v2")
        rotated_policy = replace(self.policy, authority_trust=rotated)
        self.assertNotEqual(
            self.kernel.policy_hash,
            GovernanceKernel(rotated_policy).policy_hash,
        )

    def test_substituted_verifier_fails_at_bootstrap(self):
        attacker = HmacTestVerifier(b"attacker-key")
        attacker.key_fingerprint = "d" * 64
        with self.assertRaisesRegex(AuthorityTrustError, "pinned authority trust"):
            GovernanceKernel(
                self.policy,
                approval_verifier=attacker,
                clock=lambda: NOW,
            )

        class MetadataFailure(HmacTestVerifier):
            @property
            def verifier_id(self):
                raise RuntimeError("unreadable verifier metadata")

        with self.assertRaises(AuthorityTrustError):
            GovernanceKernel(
                self.policy,
                approval_verifier=MetadataFailure(),
                clock=lambda: NOW,
            )

    def test_verifier_replacement_after_bootstrap_fails_closed(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        self.verifier.key_id = "key:substituted"
        decision = self.kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("deny", "approval_verifier_untrusted"), (decision.outcome, decision.reason))

    def test_truthy_non_boolean_verifier_result_is_rejected(self):
        class TruthyVerifier(HmacTestVerifier):
            def verify(self, payload, signature):
                return "yes"

        verifier = TruthyVerifier()
        kernel = GovernanceKernel(
            self.policy,
            approval_verifier=verifier,
            clock=lambda: NOW,
        )
        envelope = signed_envelope(kernel, self.intent, verifier, now_ns=NOW)
        self.assertEqual(
            "approval_signature_invalid",
            kernel.evaluate_with_approval(self.intent, envelope).reason,
        )

    def test_issued_at_ttl_and_verification_time_fail_closed(self):
        not_yet_valid = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=NOW + 1,
        )
        self.assertEqual(
            "approval_not_yet_valid",
            self.kernel.evaluate_with_approval(self.intent, not_yet_valid).reason,
        )
        excessive_ttl = signed_envelope(
            self.kernel,
            self.intent,
            self.verifier,
            now_ns=NOW,
            ttl_ns=self.policy.authority_trust.max_approval_ttl_ns + 1,
        )
        self.assertEqual(
            "approval_ttl_exceeded",
            self.kernel.evaluate_with_approval(self.intent, excessive_ttl).reason,
        )

        clock = [NOW]

        class AdvancingVerifier(HmacTestVerifier):
            def verify(self, payload, signature):
                valid = super().verify(payload, signature)
                clock[0] = NOW + 1_000
                return valid

        advancing = AdvancingVerifier()
        kernel = GovernanceKernel(
            self.policy,
            approval_verifier=advancing,
            clock=lambda: clock[0],
        )
        expiring = signed_envelope(kernel, self.intent, advancing, now_ns=NOW, ttl_ns=1_000)
        self.assertEqual(
            "approval_expired_during_verification",
            kernel.evaluate_with_approval(self.intent, expiring).reason,
        )

    def test_clock_failure_and_rollback_fail_closed_with_evidence(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)

        def broken_clock():
            raise RuntimeError("trusted time unavailable")

        kernel = GovernanceKernel(
            self.policy,
            approval_verifier=self.verifier,
            clock=broken_clock,
        )
        decision = kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("deny", "approval_clock_invalid"), (decision.outcome, decision.reason))
        self.assertEqual(0, kernel.audit[0]["timestamp_ns"])

        clock = [NOW]

        class RollbackVerifier(HmacTestVerifier):
            def verify(self, payload, signature):
                valid = super().verify(payload, signature)
                clock[0] = NOW - 1
                return valid

        rollback = RollbackVerifier()
        rollback_kernel = GovernanceKernel(
            self.policy,
            approval_verifier=rollback,
            clock=lambda: clock[0],
        )
        rollback_envelope = signed_envelope(
            rollback_kernel,
            self.intent,
            rollback,
            now_ns=NOW,
        )
        self.assertEqual(
            "approval_clock_rollback",
            rollback_kernel.evaluate_with_approval(self.intent, rollback_envelope).reason,
        )

    def test_verified_evidence_records_pinned_public_trust(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        self.assertEqual("allow", self.kernel.evaluate_with_approval(self.intent, envelope).outcome)
        evidence = next(record["payload"] for record in self.kernel.audit if record["event"] == "approval_verified")
        self.assertEqual(self.policy.authority_trust.key_fingerprint, evidence["key_fingerprint"])
        self.assertEqual(self.policy.authority_trust.algorithm, evidence["algorithm"])
        self.assertEqual(self.policy.authority_trust.deployment_id, evidence["deployment_id"])
        self.assertEqual(self.policy.authority_trust.trust_hash, evidence["trust_hash"])
        self.assertEqual(envelope.signing_payload_hash, evidence["signing_payload_hash"])
        self.assertNotIn("signature", evidence)

    def test_every_intent_field_is_bound_by_the_signed_envelope(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        substitutions = {
            "principal": "agent:attacker",
            "action": "read",
            "resource": "repo:attacker",
            "cost": 1,
            "session_id": "session:attacker",
        }
        for field, value in substitutions.items():
            with self.subTest(field=field):
                decision = self.kernel.evaluate_with_approval(
                    replace(self.intent, **{field: value}),
                    envelope,
                )
                self.assertEqual("deny", decision.outcome)

    def test_old_envelope_is_invalid_after_separately_configured_key_rotation(self):
        envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW)
        rotated_verifier = HmacTestVerifier()
        rotated_verifier.key_id = "key:test-only:v2"
        rotated_trust = replace(self.policy.authority_trust, key_id=rotated_verifier.key_id)
        rotated_policy = replace(self.policy, authority_trust=rotated_trust)
        rotated_kernel = GovernanceKernel(
            rotated_policy,
            approval_verifier=rotated_verifier,
            clock=lambda: NOW,
        )
        self.assertEqual(
            "approval_key_mismatch",
            rotated_kernel.evaluate_with_approval(self.intent, envelope).reason,
        )

    def test_malformed_envelope_is_rejected_before_verification(self):
        with self.assertRaisesRegex(ValueError, "intent_hash"):
            ApprovalEnvelope(
                "approval",
                self.verifier.authority_id,
                self.verifier.verifier_id,
                self.verifier.key_id,
                self.policy.authority_trust.deployment_id,
                self.policy.authority_trust.trust_hash,
                SESSION,
                self.intent.principal,
                "not-a-hash",
                self.kernel.policy_hash,
                "nonce",
                NOW,
                NOW + 1,
                "signature",
            )


if __name__ == "__main__":
    unittest.main()

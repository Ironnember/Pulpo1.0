"""Kernel-checked ceremony evidence for ceremony-required approval actions.

The ceremony signer/verifier below is a same-process test double standing on
the ceremony side of the boundary. It is not a ceremony and these tests are
not evidence that any human ceremony occurred; they prove only that the
kernel checks ceremony evidence, bound to the exact approval context, inside
its own evaluation path before it issues a permit.
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from dataclasses import asdict, replace
from hashlib import sha256

from pulpo import (
    AuthorityTrustError,
    CeremonyEvidence,
    CeremonyTrust,
    GovernanceKernel,
    Intent,
    Policy,
    SQLiteKernelState,
)
from pulpo.state import ApprovalUse, InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
SESSION = "ceremony-proof-1"


class HmacCeremonyTestVerifier:
    """Test-only ceremony signer/verifier; never import this as a ceremony."""

    authority_id = "ceremony:test-owner"
    verifier_id = "ceremony-verifier:test-only"
    key_id = "ceremony-key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"pulpo-test-ceremony-key").hexdigest()

    def __init__(self, secret=b"external-test-ceremony"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def ceremony_trust_for(verifier, *, method="test-ceremony", max_evidence_ttl_ns=10_000):
    return CeremonyTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        method=method,
        max_evidence_ttl_ns=max_evidence_ttl_ns,
    )


def signed_evidence(
    kernel,
    intent,
    envelope,
    ceremony_verifier,
    *,
    now_ns,
    ttl_ns=1_000,
    signer=None,
    **changes,
):
    trust = kernel.policy.ceremony_trust
    values = {
        "evidence_id": "ceremony-evidence-1",
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "key_id": trust.key_id,
        "method": trust.method,
        "trust_hash": trust.trust_hash,
        "approval_id": envelope.approval_id,
        "envelope_hash": envelope.envelope_hash,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "principal": intent.principal,
        "session_id": intent.session_id,
        "approval_nonce": envelope.nonce,
        "issued_at_ns": now_ns,
        "expires_at_ns": now_ns + ttl_ns,
        "signature": "",
    }
    values.update(changes)
    unsigned = CeremonyEvidence(**values)
    return replace(unsigned, signature=(signer or ceremony_verifier).sign(unsigned.signing_bytes()))


class CeremonyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.ceremony = HmacCeremonyTestVerifier()
        self.policy = Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.verifier),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=ceremony_trust_for(self.ceremony),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            ceremony_verifier=self.ceremony,
        )
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, SESSION)

    def envelope(self, **changes):
        return signed_envelope(self.kernel, self.intent, self.verifier, now_ns=NOW, **changes)

    def evidence(self, envelope, **kwargs):
        kwargs.setdefault("now_ns", NOW)
        return signed_evidence(self.kernel, self.intent, envelope, self.ceremony, **kwargs)

    def test_genuine_ceremony_evidence_admits_and_is_recorded(self):
        envelope = self.envelope()
        evidence = self.evidence(envelope)
        decision = self.kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(self.kernel.consume(decision.permit, self.intent))
        self.assertFalse(self.kernel.consume(decision.permit, self.intent))
        verified = [
            record["payload"]
            for record in self.kernel.audit
            if record["event"] == "approval_verified"
        ]
        self.assertEqual(1, len(verified))
        self.assertEqual("ceremony-evidence-1", verified[0]["ceremony_evidence_id"])
        self.assertEqual(evidence.evidence_hash, verified[0]["ceremony_evidence_hash"])
        self.assertEqual("test-ceremony", verified[0]["ceremony_method"])
        self.assertEqual(
            "ceremony_evidence_replayed",
            self.kernel._state.ceremony_replay_reason("ceremony-evidence-1"),
        )

    def test_signature_mint_without_ceremony_is_denied(self):
        # The #280 invariant, now enforced for opted-in actions:
        # SIGNATURE_MINT_WITHOUT_VALID_CEREMONY -> KERNEL_DENY. The envelope
        # below is correctly bound and correctly signed with the already
        # trusted authority material; no ceremony evidence accompanies it.
        envelope = self.envelope()
        decision = self.kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(
            ("deny", "ceremony_evidence_missing"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            any(record["event"] == "approval_verified" for record in self.kernel.audit)
        )
        rejections = [
            record["payload"]
            for record in self.kernel.audit
            if record["event"] == "approval_rejected"
        ]
        self.assertEqual("ceremony_evidence_missing", rejections[-1]["reason"])

    def test_forged_or_self_attested_evidence_signature_denies(self):
        envelope = self.envelope()
        forged = self.evidence(envelope, signer=HmacCeremonyTestVerifier(b"attacker-key"))
        decision = self.kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=forged
        )
        self.assertEqual(
            ("deny", "ceremony_signature_invalid"), (decision.outcome, decision.reason)
        )
        # Key separation: evidence signed by the approval authority itself
        # (the retained signer self-attesting ceremony) must not verify.
        self_attested = self.evidence(envelope, signer=self.verifier)
        decision = self.kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=self_attested
        )
        self.assertEqual(
            ("deny", "ceremony_signature_invalid"), (decision.outcome, decision.reason)
        )
        missing = replace(self.evidence(envelope), signature="")
        decision = self.kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=missing
        )
        self.assertEqual(
            ("deny", "ceremony_signature_missing"), (decision.outcome, decision.reason)
        )

    def test_replayed_evidence_denies(self):
        envelope = self.envelope()
        evidence = self.evidence(envelope)
        first = self.kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual("allow", first.outcome)
        second = self.kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual("deny", second.outcome)
        self.assertIn(second.reason, ("approval_id_replayed", "ceremony_evidence_replayed"))

    def test_evidence_consumption_is_atomic_in_state(self):
        for state in (InMemoryKernelState(), self._sqlite_state()):
            with self.subTest(state=type(state).__name__):
                use = ApprovalUse(
                    "approval-a", "nonce-a", {}, ceremony_evidence_id="evidence-x"
                )
                self.assertIsNone(
                    state.issue_permit("permit:1", "h" * 64, "verified_approval", NOW, use)
                )
                other = ApprovalUse(
                    "approval-b", "nonce-b", {}, ceremony_evidence_id="evidence-x"
                )
                self.assertEqual(
                    "ceremony_evidence_replayed",
                    state.issue_permit("permit:2", "h" * 64, "verified_approval", NOW, other),
                )

    def test_ceremony_replay_survives_sqlite_restart(self):
        state = self._sqlite_state()
        kernel = GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=state,
            ceremony_verifier=self.ceremony,
        )
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        evidence = signed_evidence(kernel, self.intent, envelope, self.ceremony, now_ns=NOW)
        self.assertEqual(
            "allow",
            kernel.evaluate_with_approval(
                self.intent, envelope, ceremony_evidence=evidence
            ).outcome,
        )
        state.close()
        reopened = GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=SQLiteKernelState(self._sqlite_path),
            ceremony_verifier=self.ceremony,
        )
        decision = reopened.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual("deny", decision.outcome)

    def test_evidence_bound_to_other_context_denies(self):
        envelope = self.envelope()
        cases = (
            ({"principal": "agent:other"}, "ceremony_principal_mismatch"),
            ({"session_id": "other-session"}, "ceremony_session_mismatch"),
            ({"intent_hash": "a" * 64}, "ceremony_intent_mismatch"),
            ({"policy_hash": "b" * 64}, "ceremony_policy_mismatch"),
            ({"approval_nonce": "other-nonce"}, "ceremony_nonce_mismatch"),
            ({"approval_id": "approval-2"}, "ceremony_approval_mismatch"),
            ({"envelope_hash": "c" * 64}, "ceremony_envelope_mismatch"),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                evidence = self.evidence(envelope, **changes)
                decision = self.kernel.evaluate_with_approval(
                    self.intent, envelope, ceremony_evidence=evidence
                )
                self.assertEqual(("deny", expected), (decision.outcome, decision.reason))

    def test_evidence_for_one_envelope_does_not_validate_another(self):
        envelope_a = self.envelope()
        evidence_a = self.evidence(envelope_a)
        envelope_b = self.envelope(approval_id="approval-2", nonce="approval-nonce-2")
        decision = self.kernel.evaluate_with_approval(
            self.intent, envelope_b, ceremony_evidence=evidence_a
        )
        self.assertEqual("deny", decision.outcome)
        self.assertTrue(decision.reason.startswith("ceremony_"))

    def test_evidence_for_other_intent_principal_or_session_denies(self):
        envelope = self.envelope()
        other_intents = (
            Intent("agent:publisher", "push", "repo:origin/other", 0, SESSION),
            Intent("agent:other", "push", "repo:origin/main", 0, SESSION),
            Intent("agent:publisher", "push", "repo:origin/main", 0, "other-session"),
        )
        for other in other_intents:
            with self.subTest(other=other):
                other_envelope = signed_envelope(
                    self.kernel, other, self.verifier, now_ns=NOW,
                    approval_id="approval-x", nonce="nonce-x",
                )
                evidence = signed_evidence(
                    self.kernel, other, other_envelope, self.ceremony, now_ns=NOW
                )
                decision = self.kernel.evaluate_with_approval(
                    self.intent, envelope, ceremony_evidence=evidence
                )
                self.assertEqual("deny", decision.outcome)
                self.assertTrue(decision.reason.startswith("ceremony_"))

    def test_expired_overlong_and_future_evidence_denies(self):
        envelope = self.envelope()
        expired = self.evidence(envelope, now_ns=NOW - 2_000, ttl_ns=1_000)
        self.assertEqual(
            "ceremony_expired",
            self.kernel.evaluate_with_approval(
                self.intent, envelope, ceremony_evidence=expired
            ).reason,
        )
        overlong = self.evidence(envelope, ttl_ns=20_000)
        self.assertEqual(
            "ceremony_ttl_exceeded",
            self.kernel.evaluate_with_approval(
                self.intent, envelope, ceremony_evidence=overlong
            ).reason,
        )
        future = self.evidence(envelope, now_ns=NOW + 100)
        self.assertEqual(
            "ceremony_not_yet_valid",
            self.kernel.evaluate_with_approval(
                self.intent, envelope, ceremony_evidence=future
            ).reason,
        )

    def test_evidence_from_other_ceremony_trust_denies(self):
        envelope = self.envelope()
        cases = (
            ({"authority_id": "ceremony:other"}, "ceremony_authority_mismatch"),
            ({"verifier_id": "ceremony-verifier:other"}, "ceremony_verifier_mismatch"),
            ({"key_id": "ceremony-key:other"}, "ceremony_key_mismatch"),
            ({"method": "other-method"}, "ceremony_method_mismatch"),
            ({"trust_hash": "d" * 64}, "ceremony_trust_mismatch"),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                evidence = self.evidence(envelope, **changes)
                decision = self.kernel.evaluate_with_approval(
                    self.intent, envelope, ceremony_evidence=evidence
                )
                self.assertEqual(("deny", expected), (decision.outcome, decision.reason))

    def test_ceremony_verifier_unavailable_denies(self):
        kernel = GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        evidence = signed_evidence(kernel, self.intent, envelope, self.ceremony, now_ns=NOW)
        decision = kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(
            ("deny", "ceremony_verifier_unavailable"), (decision.outcome, decision.reason)
        )

    def test_policy_and_verifier_configuration_fail_closed(self):
        with self.assertRaises(ValueError):
            Policy(
                frozenset({"push"}),
                100,
                frozenset({"push"}),
                authority_trust=trust_for(self.verifier),
                ceremony_actions=frozenset({"push"}),
            )
        with self.assertRaises(ValueError):
            Policy(
                frozenset({"read", "push"}),
                100,
                frozenset({"read"}),
                authority_trust=trust_for(self.verifier),
                ceremony_actions=frozenset({"push"}),
                ceremony_trust=ceremony_trust_for(self.ceremony),
            )
        with self.assertRaises(ValueError):
            Policy(
                frozenset({"push"}),
                100,
                frozenset({"push"}),
                authority_trust=trust_for(self.verifier),
                ceremony_trust=ceremony_trust_for(self.ceremony),
            )
        mismatched = HmacCeremonyTestVerifier()
        mismatched.key_id = "ceremony-key:test-only:v2"
        with self.assertRaises(AuthorityTrustError):
            GovernanceKernel(
                self.policy,
                approval_verifier=self.verifier,
                clock=lambda: NOW,
                ceremony_verifier=mismatched,
            )

    def test_non_opted_in_behavior_is_exactly_unchanged(self):
        # A policy that never opted in keeps the pre-ceremony policy hash and
        # admits approval actions on envelope verification alone.
        legacy_policy = Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.verifier),
        )
        legacy_kernel = GovernanceKernel(
            legacy_policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        trust = legacy_policy.authority_trust
        expected_payload = {
            "schema": "pulpo.policy.v1",
            "allowed_actions": ["push", "read"],
            "max_cost": 100,
            "approval_actions": ["push"],
            "agent_grants": [],
            "authority_trust": asdict(trust),
        }
        expected_hash = sha256(
            json.dumps(expected_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(expected_hash, legacy_kernel.policy_hash)
        envelope = signed_envelope(legacy_kernel, self.intent, self.verifier, now_ns=NOW)
        decision = legacy_kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        # Opting in binds the ceremony configuration into the policy hash.
        self.assertNotEqual(legacy_kernel.policy_hash, self.kernel.policy_hash)

    def test_approval_action_outside_ceremony_actions_needs_no_evidence(self):
        policy = Policy(
            frozenset({"read", "push", "release"}),
            100,
            frozenset({"push", "release"}),
            authority_trust=trust_for(self.verifier),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=ceremony_trust_for(self.ceremony),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            ceremony_verifier=self.ceremony,
        )
        release = Intent("agent:publisher", "release", "repo:origin/main", 0, SESSION)
        envelope = signed_envelope(kernel, release, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(release, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        # The plain evaluator is untouched by the ceremony configuration.
        plain = kernel.evaluate(self.intent)
        self.assertEqual(
            ("require_approval", "approval_required"), (plain.outcome, plain.reason)
        )

    def _sqlite_state(self):
        fd, path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        self._sqlite_path = path
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return SQLiteKernelState(path)


if __name__ == "__main__":
    unittest.main()

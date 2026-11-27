"""Signed, versioned policy envelope verified at kernel construction.

Ported from Pulpo-Preview (door-two ◆2, 2026-11-27) and reconciled against
canonical: before this change a canonical kernel constructed with an older
Policy kept governing indefinitely, because no authenticated current policy
head existed anywhere in canonical. The envelope's version/previous-hash
chain is that head: it is signed by the holder of the already-pinned issuer
key and verified at construction, and the accepted head is recorded in the
canonical audit chain, so a stale kernel reopening the same state is refused
instead of governing under an older policy.

Reconciliation note (see docs/CHANGE_RECORD_2026-11-27_POLICY_ENVELOPE_PORT.md):
the fork requires an envelope whenever a pinned trust and an approval
verifier coexist. Canonical requires one exactly where a chain is claimed
or already exists -- a versioned policy (version > 1), or state that
already records a policy head -- and verifies any envelope supplied. A
genesis policy with no recorded head keeps the exact pre-envelope
construction behavior. All test keys are same-process synthetic doubles,
clearly labeled test-only; no production or human signer is exercised.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac
import unittest

from pulpo import (
    CeremonyEvidence,
    CeremonyTrust,
    GovernanceKernel,
    Intent,
    Policy,
    PolicyEnvelopeError,
)
from pulpo.kernel import policy_hash_for
from pulpo.state import InMemoryKernelState
from tests.authority_support import (
    HmacTestVerifier,
    signed_envelope,
    signed_policy_envelope,
    trust_for,
)

NOW = 1_000_000
SESSION = "policy-envelope-proof-1"


class HmacCeremonyTestVerifier:
    """Same-process synthetic test double; not a human ceremony signer."""

    authority_id = "ceremony:test-owner"
    verifier_id = "ceremony-verifier:test-only"
    key_id = "ceremony-key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"synthetic-ceremony-test-key").hexdigest()

    def __init__(self):
        self._secret = b"synthetic-ceremony-test-key"

    def sign(self, payload):
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


class PolicyEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.verifier),
        )
        self.envelope = signed_policy_envelope(self.policy, self.verifier)
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, SESSION)

    def make_kernel(self, *, policy=None, envelope=None, verifier=None, state=None):
        return GovernanceKernel(
            policy or self.policy,
            approval_verifier=verifier or self.verifier,
            clock=lambda: NOW,
            state=state,
            policy_envelope=self.envelope if envelope is None else envelope,
        )

    # (a) Tampered envelopes are rejected at construction.
    def test_bad_signature_is_refused_at_construction(self):
        tampered = replace(self.envelope, signature="00" * 64)
        with self.assertRaisesRegex(PolicyEnvelopeError, "signature invalid"):
            self.make_kernel(envelope=tampered)

    def test_missing_signature_is_refused_at_construction(self):
        tampered = replace(self.envelope, signature="")
        with self.assertRaisesRegex(PolicyEnvelopeError, "signature missing"):
            self.make_kernel(envelope=tampered)

    def test_wrong_version_is_refused_at_construction(self):
        tampered = replace(
            self.envelope, version=2, previous_policy_hash="b" * 64
        )
        with self.assertRaisesRegex(PolicyEnvelopeError, "version mismatch"):
            self.make_kernel(envelope=tampered)

    def test_wrong_previous_hash_is_refused_at_construction(self):
        policy_v2 = replace(
            self.policy, version=2, previous_policy_hash=policy_hash_for(self.policy)
        )
        envelope_v2 = signed_policy_envelope(policy_v2, self.verifier)
        tampered = replace(envelope_v2, previous_policy_hash="c" * 64)
        with self.assertRaisesRegex(PolicyEnvelopeError, "previous-hash mismatch"):
            self.make_kernel(policy=policy_v2, envelope=tampered)

    def test_wrong_policy_hash_is_refused_at_construction(self):
        tampered = replace(self.envelope, policy_hash="d" * 64)
        with self.assertRaisesRegex(PolicyEnvelopeError, "policy-hash mismatch"):
            self.make_kernel(envelope=tampered)

    def test_envelope_for_another_trust_is_refused_at_construction(self):
        other_trust = replace(
            self.policy.authority_trust, key_id="key:test-only:v2"
        )
        other_policy = replace(self.policy, authority_trust=other_trust)
        other_envelope = signed_policy_envelope(other_policy, self.verifier)
        with self.assertRaisesRegex(PolicyEnvelopeError, "key mismatch"):
            self.make_kernel(envelope=other_envelope)

    def test_envelope_without_pinned_trust_is_refused(self):
        plain = Policy(frozenset({"read"}), 1)
        with self.assertRaisesRegex(
            PolicyEnvelopeError, "requires a pinned authority trust"
        ):
            GovernanceKernel(plain, policy_envelope=self.envelope)

    def test_envelope_without_approval_verifier_is_refused(self):
        with self.assertRaisesRegex(
            PolicyEnvelopeError, "cannot be verified without an approval verifier"
        ):
            GovernanceKernel(
                self.policy, clock=lambda: NOW, policy_envelope=self.envelope
            )

    # (a2) A missing envelope is refused exactly where a chain is claimed
    # or already exists (canonical reconciliation of the fork's rule).
    def test_missing_envelope_is_refused_for_a_versioned_policy(self):
        policy_v2 = replace(
            self.policy, version=2, previous_policy_hash=policy_hash_for(self.policy)
        )
        with self.assertRaisesRegex(
            PolicyEnvelopeError, "signed policy envelope is required"
        ):
            GovernanceKernel(
                policy_v2, approval_verifier=self.verifier, clock=lambda: NOW
            )

    def test_missing_envelope_is_refused_once_a_head_is_recorded(self):
        state = InMemoryKernelState()
        self.make_kernel(state=state)
        with self.assertRaisesRegex(
            PolicyEnvelopeError, "signed policy envelope is required"
        ):
            GovernanceKernel(
                self.policy,
                approval_verifier=self.verifier,
                clock=lambda: NOW,
                state=state,
            )

    def test_genesis_policy_without_envelope_keeps_legacy_construction(self):
        kernel = GovernanceKernel(
            self.policy, approval_verifier=self.verifier, clock=lambda: NOW
        )
        self.assertIsNone(kernel.policy_head)
        self.assertEqual("require_approval", kernel.evaluate(self.intent).outcome)

    def test_policy_version_chain_shape_is_validated(self):
        with self.assertRaisesRegex(ValueError, "genesis policy version"):
            replace(self.policy, previous_policy_hash="a" * 64)
        with self.assertRaisesRegex(ValueError, "previous policy hash"):
            replace(self.policy, version=2)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            replace(self.policy, version=0)

    # (a3) Door-two ◆1: no no-expiry form exists anywhere in the envelope
    # regime -- versions and lifetimes are mandatory positive integers.
    def test_no_expiry_forms_are_refused(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            replace(self.envelope, version=0)
        with self.assertRaisesRegex(ValueError, "genesis policy envelope"):
            replace(self.envelope, previous_policy_hash="a" * 64)
        with self.assertRaisesRegex(ValueError, "max_permit_ttl_ns must be positive"):
            replace(self.policy, max_permit_ttl_ns=0)
        with self.assertRaisesRegex(ValueError, "must be greater than issued_at_ns"):
            replace(
                signed_envelope(
                    self.make_kernel(), self.intent, self.verifier, now_ns=NOW
                ),
                expires_at_ns=NOW,
            )

    # (b) A stale policy is detected and refused rather than governing.
    def test_stale_policy_is_refused_after_the_head_advances(self):
        state = InMemoryKernelState()
        first = self.make_kernel(state=state)
        self.assertEqual("require_approval", first.evaluate(self.intent).outcome)
        policy_v2 = replace(
            self.policy, version=2, previous_policy_hash=policy_hash_for(self.policy)
        )
        envelope_v2 = signed_policy_envelope(policy_v2, self.verifier)
        second = self.make_kernel(policy=policy_v2, envelope=envelope_v2, state=state)
        self.assertEqual(2, second.policy_head["policy_version"])
        with self.assertRaisesRegex(PolicyEnvelopeError, "stale policy envelope"):
            self.make_kernel(state=state)
        heads = [r for r in state.audit if r["event"] == "policy_head_accepted"]
        self.assertEqual(2, len(heads))

    def test_broken_chain_is_refused_after_the_head_advances(self):
        state = InMemoryKernelState()
        self.make_kernel(state=state)
        policy_v3 = replace(self.policy, version=3, previous_policy_hash="a" * 64)
        envelope_v3 = signed_policy_envelope(policy_v3, self.verifier)
        with self.assertRaisesRegex(PolicyEnvelopeError, "chain is broken"):
            self.make_kernel(policy=policy_v3, envelope=envelope_v3, state=state)

    def test_same_version_with_different_policy_is_refused(self):
        state = InMemoryKernelState()
        self.make_kernel(state=state)
        forked = replace(self.policy, max_cost=50)
        forked_envelope = signed_policy_envelope(forked, self.verifier)
        with self.assertRaisesRegex(PolicyEnvelopeError, "conflicts with the recorded"):
            self.make_kernel(policy=forked, envelope=forked_envelope, state=state)

    def test_reopening_with_the_identical_head_is_a_restart_not_a_fork(self):
        state = InMemoryKernelState()
        first = self.make_kernel(state=state)
        second = self.make_kernel(state=state)
        self.assertEqual(first.policy_hash, second.policy_hash)
        self.assertEqual(first.policy_head, second.policy_head)
        heads = [r for r in state.audit if r["event"] == "policy_head_accepted"]
        self.assertEqual(1, len(heads))

    # (c) A valid signed envelope is accepted and the kernel governs under it.
    def test_valid_envelope_governs_and_permits_bind_to_the_versioned_hash(self):
        kernel = self.make_kernel()
        self.assertEqual(1, kernel.policy_head["policy_version"])
        self.assertEqual(kernel.policy_hash, kernel.policy_head["policy_hash"])
        self.assertEqual("require_approval", kernel.evaluate(self.intent).outcome)
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(kernel.consume(decision.permit, self.intent))
        self.assertFalse(kernel.consume(decision.permit, self.intent))

    def test_versioned_policy_hash_differs_from_the_legacy_hash(self):
        policy_v2 = replace(
            self.policy, version=2, previous_policy_hash=policy_hash_for(self.policy)
        )
        self.assertNotEqual(policy_hash_for(self.policy), policy_hash_for(policy_v2))
        self.assertEqual(
            policy_hash_for(self.policy),
            signed_policy_envelope(self.policy, self.verifier).policy_hash,
        )

    def test_head_is_recorded_in_the_canonical_audit_chain(self):
        kernel = self.make_kernel()
        heads = [r for r in kernel.audit if r["event"] == "policy_head_accepted"]
        self.assertEqual(1, len(heads))
        payload = heads[0]["payload"]
        self.assertEqual(1, payload["policy_version"])
        self.assertEqual(kernel.policy_hash, payload["policy_hash"])
        self.assertIsNone(payload["previous_policy_hash"])
        self.assertNotIn("signature", payload)
        self.assertTrue(kernel.verify_audit())

    # (d) The existing ceremony/approval paths still pass under a signed policy.
    def _ceremony_kernel_and_evidence(self):
        ceremony_verifier = HmacCeremonyTestVerifier()
        ceremony_trust = CeremonyTrust(
            authority_id=ceremony_verifier.authority_id,
            verifier_id=ceremony_verifier.verifier_id,
            key_id=ceremony_verifier.key_id,
            algorithm=ceremony_verifier.algorithm,
            key_fingerprint=ceremony_verifier.key_fingerprint,
            method="synthetic-test-ceremony",
            max_evidence_ttl_ns=500,
        )
        policy = replace(
            self.policy,
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=ceremony_trust,
        )
        envelope = signed_policy_envelope(policy, self.verifier)
        kernel = GovernanceKernel(
            policy,
            approval_verifier=self.verifier,
            ceremony_verifier=ceremony_verifier,
            clock=lambda: NOW,
            policy_envelope=envelope,
        )
        approval = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        trust = policy.ceremony_trust
        values = {
            "evidence_id": "ceremony-evidence-1",
            "authority_id": trust.authority_id,
            "verifier_id": trust.verifier_id,
            "key_id": trust.key_id,
            "method": trust.method,
            "trust_hash": trust.trust_hash,
            "approval_id": approval.approval_id,
            "envelope_hash": approval.envelope_hash,
            "intent_hash": kernel.intent_hash(self.intent),
            "policy_hash": kernel.policy_hash,
            "principal": self.intent.principal,
            "session_id": self.intent.session_id,
            "approval_nonce": approval.nonce,
            "issued_at_ns": NOW,
            "expires_at_ns": NOW + 200,
            "signature": "",
        }
        unsigned = CeremonyEvidence(**values)
        evidence = replace(
            unsigned, signature=ceremony_verifier.sign(unsigned.signing_bytes())
        )
        return kernel, approval, evidence

    def test_ceremony_path_passes_under_a_signed_policy(self):
        kernel, approval, evidence = self._ceremony_kernel_and_evidence()
        decision = kernel.evaluate_with_approval(
            self.intent, approval, ceremony_evidence=evidence
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(kernel.consume(decision.permit, self.intent))

    def test_replayed_ceremony_evidence_is_refused_under_a_signed_policy(self):
        kernel, approval, evidence = self._ceremony_kernel_and_evidence()
        first = kernel.evaluate_with_approval(
            self.intent, approval, ceremony_evidence=evidence
        )
        self.assertEqual("allow", first.outcome)
        second = kernel.evaluate_with_approval(
            self.intent, approval, ceremony_evidence=evidence
        )
        self.assertEqual("deny", second.outcome)
        self.assertIn(
            second.reason, ("approval_id_replayed", "ceremony_evidence_replayed")
        )

    def test_ceremony_key_matching_authority_key_is_refused(self):
        # The ceremony gate is a separate-key gate: a ceremony trust pinned
        # to the authority key itself is refused at policy construction.
        ceremony_trust = CeremonyTrust(
            authority_id="ceremony:test-owner",
            verifier_id="ceremony-verifier:test-only",
            key_id="ceremony-key:test-only:v1",
            algorithm="hmac-sha256-test-only",
            key_fingerprint=self.verifier.key_fingerprint,
            method="synthetic-test-ceremony",
            max_evidence_ttl_ns=500,
        )
        with self.assertRaisesRegex(ValueError, "must be distinct from authority"):
            replace(
                self.policy,
                ceremony_actions=frozenset({"push"}),
                ceremony_trust=ceremony_trust,
            )


if __name__ == "__main__":
    unittest.main()

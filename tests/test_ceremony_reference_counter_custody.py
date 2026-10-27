"""Cross-candidate custody + durable WebAuthn counter tests, software fixtures only.

Uses real Pulpo GovernanceKernel and SQLiteKernelState, a fake signer and a
synthetic verifier. It does not validate live WebAuthn signatures or external
storage IAM. Reference hash is never treated as authority by itself.
"""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
import json
import tempfile
import unittest

from pulpo import (
    CeremonyProof, CeremonyTrust, CeremonyVerification,
    GovernanceKernel, Intent, Policy, SQLiteKernelState,
    expected_ceremony_challenge,
)
from pulpo.ceremony import CeremonyEvidenceReference
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for

NOW = 9_000_000
CREDENTIAL = "credential:protected-counter-fixture"
CREDENTIAL_HASH = sha256(CREDENTIAL.encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class MutableVerifier:
    verifier_id = "ceremony-verifier:counter-reader-fixture"
    rp_id = "authority.example.com"
    origin = "https://authority.example.com"
    credential_set_hash = CREDENTIAL_HASH

    def __init__(self, count=5):
        self.count = count
        self.calls = 0

    def verify(self, proof, *, expected_challenge):
        self.calls += 1
        credential = json.loads(proof.assertion)
        if credential.get("challenge") != expected_challenge.hex():
            raise ValueError("challenge mismatch")
        if credential.get("id") != proof.credential_id:
            raise ValueError("credential mismatch")
        return CeremonyVerification(proof.credential_id, True, True, False, False, self.count)


class MemoryReader:
    def __init__(self):
        self.data = None
        self.calls = 0

    def read(self, evidence_hash):
        self.calls += 1
        if self.data is None:
            raise FileNotFoundError("protected evidence unavailable")
        return self.data


class ProtectedCounterIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.signer = HmacTestVerifier()
        self.verifier = MutableVerifier()
        self.reader = MemoryReader()
        self.intent = Intent("agent:fixture", "write", "resource:zero-effect", 0, "session:fixture")
        self.policy = Policy(
            frozenset({"write"}), 0, frozenset({"write"}),
            authority_trust=trust_for(self.signer),
            ceremony_actions=frozenset({"write"}),
            ceremony_trust=CeremonyTrust(
                self.verifier.verifier_id, self.verifier.rp_id,
                self.verifier.origin, self.verifier.credential_set_hash,
            ),
        )

    def kernel(self, state=None, *, reader=True):
        return GovernanceKernel(
            self.policy,
            approval_verifier=self.signer,
            ceremony_verifier=self.verifier,
            ceremony_evidence_reader=self.reader if reader else None,
            clock=lambda: NOW,
            state=state,
            secret=b"synthetic-counter-reader-test",
        )

    def authority_input(self, kernel, label):
        envelope = signed_envelope(
            kernel, self.intent, self.signer,
            now_ns=NOW - 10,
            approval_id="approval:" + label, nonce="nonce:" + label,
        )
        request_id = "request:" + label
        challenge = expected_ceremony_challenge(envelope, request_id)
        assertion = json.dumps({"id": CREDENTIAL, "challenge": challenge.hex()})
        bundle = {
            "schema": "pulpo.authority-evidence.v1", "sequence": 1,
            "request": {
                "principal": envelope.principal,
                "session_id": envelope.session_id,
                "intent_hash": envelope.intent_hash,
                "policy_hash": envelope.policy_hash,
                "deployment_id": envelope.deployment_id,
            },
            "request_id": request_id,
            "challenge_hash": sha256(challenge).hexdigest(),
            "credential_id_hash": CREDENTIAL_HASH,
            "assertion": assertion,
            "envelope": asdict(envelope),
        }
        bytes_ = canonical(bundle)
        self.reader.data = bytes_ + b"\n"
        reference = CeremonyEvidenceReference(request_id, sha256(bytes_).hexdigest())
        return envelope, reference, CeremonyProof(request_id, CREDENTIAL, assertion)

    def test_reference_missing_raw_bypass_and_reader_absence_deny(self):
        kernel = self.kernel()
        envelope, reference, proof = self.authority_input(kernel, "missing")
        missing = kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual(("deny", "approval_ceremony_evidence_reference_missing"),
                         (missing.outcome, missing.reason))
        raw = kernel.evaluate_with_approval(self.intent, envelope, ceremony_proof=proof)
        self.assertEqual(("deny", "approval_ceremony_raw_proof_rejected"),
                         (raw.outcome, raw.reason))
        no_reader = self.kernel(reader=False).evaluate_with_approval(
            self.intent, envelope, ceremony_evidence_ref=reference,
        )
        self.assertEqual(("deny", "approval_ceremony_evidence_reader_unavailable"),
                         (no_reader.outcome, no_reader.reason))
        self.assertEqual(0, self.reader.calls)
        self.assertTrue(kernel.verify_audit())

    def test_protected_reference_counter_replay_after_restart_and_higher_counter(self):
        with tempfile.TemporaryDirectory(prefix="pulpo-ceremony-counter-") as td:
            db = Path(td) / "canonical.sqlite3"
            first_state = SQLiteKernelState(db)
            try:
                kernel = self.kernel(first_state)
                e1, r1, _ = self.authority_input(kernel, "first")
                first = kernel.evaluate_with_approval(self.intent, e1, ceremony_evidence_ref=r1)
                self.assertEqual(("allow", "verified_approval"),
                                 (first.outcome, first.reason))
                self.assertIsNotNone(first.permit)
                self.assertTrue(kernel.consume(first.permit, self.intent))
                self.assertFalse(kernel.consume(first.permit, self.intent))
                e2, r2, _ = self.authority_input(kernel, "second")
                second = kernel.evaluate_with_approval(self.intent, e2, ceremony_evidence_ref=r2)
                self.assertEqual(("deny", "approval_ceremony_sign_count_replayed"),
                                 (second.outcome, second.reason))
                self.assertIsNone(second.permit)
                self.assertTrue(kernel.verify_audit())
            finally:
                first_state.close()
            restarted_state = SQLiteKernelState(db)
            try:
                restarted = self.kernel(restarted_state)
                self.assertFalse(restarted.consume(first.permit, self.intent))
                e3, r3, _ = self.authority_input(restarted, "third")
                third = restarted.evaluate_with_approval(
                    self.intent, e3, ceremony_evidence_ref=r3,
                )
                self.assertEqual(("deny", "approval_ceremony_sign_count_replayed"),
                                 (third.outcome, third.reason))
                self.verifier.count = 6
                e4, r4, _ = self.authority_input(restarted, "fourth")
                fourth = restarted.evaluate_with_approval(
                    self.intent, e4, ceremony_evidence_ref=r4,
                )
                self.assertEqual("allow", fourth.outcome)
                self.assertTrue(restarted.consume(fourth.permit, self.intent))
                self.assertFalse(restarted.consume(fourth.permit, self.intent))
                verified = [
                    x["payload"] for x in restarted.audit
                    if x["event"] == "approval_verified"
                ]
                self.assertEqual([5, 6], [x["ceremony_sign_count"] for x in verified])
                self.assertEqual([None, 5], [x["ceremony_previous_sign_count"] for x in verified])
                self.assertTrue(restarted.verify_audit())
            finally:
                restarted_state.close()

    def test_tampered_reference_digest_denied_before_verifier_and_permit(self):
        kernel = self.kernel()
        envelope, reference, _ = self.authority_input(kernel, "tampered")
        wrong = CeremonyEvidenceReference(reference.request_id, "0" * 64)
        result = kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence_ref=wrong,
        )
        self.assertEqual(("deny", "approval_ceremony_evidence_unavailable_or_mismatch"),
                         (result.outcome, result.reason))
        self.assertIsNone(result.permit)
        self.assertEqual(0, self.verifier.calls)

    def test_unknown_reader_failure_fails_closed_not_reauthorized(self):
        kernel = self.kernel()
        envelope, ref, _ = self.authority_input(kernel, "unavailable")
        self.reader.data = None
        result = kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence_ref=ref,
        )
        self.assertEqual(("deny", "approval_ceremony_evidence_unavailable_or_mismatch"),
                         (result.outcome, result.reason))
        self.assertIsNone(result.permit)


if __name__ == "__main__":
    unittest.main()

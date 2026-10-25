"""Synthetic protected-reference proof: no live WebAuthn or provider."""
from dataclasses import asdict
from hashlib import sha256
import json
import unittest

from pulpo import CeremonyTrust, CeremonyVerification, GovernanceKernel, Intent, Policy
from pulpo.ceremony import CeremonyEvidenceReference, expected_ceremony_challenge
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Reader:
    def __init__(self):
        self.content = None
        self.calls = 0

    def read(self, digest):
        self.calls += 1
        if self.content is None:
            raise FileNotFoundError()
        return self.content


class Verifier:
    verifier_id = "ceremony:test"
    rp_id = "authority.example.com"
    origin = "https://authority.example.com"
    credential_set_hash = sha256(b"credential:test").hexdigest()

    def verify(self, proof, *, expected_challenge):
        value = json.loads(proof.assertion)
        if value["challenge"] != expected_challenge.hex():
            raise ValueError("challenge mismatch")
        return CeremonyVerification(proof.credential_id, True, True, False, False, 1)


class ProtectedReferenceTests(unittest.TestCase):
    def setUp(self):
        self.signer = HmacTestVerifier()
        self.reader = Reader()
        self.kernel = GovernanceKernel(
            Policy(
                frozenset({"write"}), 0, frozenset({"write"}),
                authority_trust=trust_for(self.signer),
                ceremony_actions=frozenset({"write"}),
                ceremony_trust=CeremonyTrust(
                    Verifier.verifier_id, Verifier.rp_id, Verifier.origin,
                    Verifier.credential_set_hash,
                ),
            ),
            approval_verifier=self.signer, ceremony_verifier=Verifier(),
            ceremony_evidence_reader=self.reader, clock=lambda: 1_000_000,
        )
        self.intent = Intent("agent:example", "write", "resource:example", 0, "session:example")
        self.envelope = signed_envelope(
            self.kernel, self.intent, self.signer, now_ns=999_990,
            approval_id="approval:test", nonce="nonce:test",
        )
        self.request_id = "request:test"
        challenge = expected_ceremony_challenge(self.envelope, self.request_id)
        self.bundle = {
            "schema": "pulpo.authority-evidence.v1",
            "sequence": 1,
            "request": {
                "principal": self.envelope.principal,
                "session_id": self.envelope.session_id,
                "intent_hash": self.envelope.intent_hash,
                "policy_hash": self.envelope.policy_hash,
                "deployment_id": self.envelope.deployment_id,
            },
            "request_id": self.request_id,
            "challenge_hash": sha256(challenge).hexdigest(),
            "credential_id_hash": sha256(b"credential:test").hexdigest(),
            "assertion": json.dumps(
                {"id": "credential:test", "challenge": challenge.hex()}
            ),
            "envelope": asdict(self.envelope),
        }
        self.set_bundle(self.bundle)

    def set_bundle(self, bundle):
        data = canonical(bundle)
        self.reader.content = data + b"\n"
        self.reference = CeremonyEvidenceReference(self.request_id, sha256(data).hexdigest())

    def evaluate(self):
        return self.kernel.evaluate_with_approval(
            self.intent, self.envelope, ceremony_evidence_ref=self.reference
        )

    def test_exact_protected_evidence_allows_one_permit_only(self):
        first = self.evaluate()
        self.assertEqual("allow", first.outcome)
        self.assertIsNotNone(first.permit)
        self.assertEqual("deny", self.evaluate().outcome)

    def test_missing_reference_denies(self):
        result = self.kernel.evaluate_with_approval(self.intent, self.envelope)
        self.assertEqual("approval_ceremony_evidence_reference_missing", result.reason)
        self.assertEqual(0, self.reader.calls)

    def test_missing_object_denies(self):
        self.reader.content = None
        self.assertEqual("approval_ceremony_evidence_unavailable_or_mismatch", self.evaluate().reason)

    def test_tampered_digest_denies(self):
        self.reference = CeremonyEvidenceReference(self.request_id, "0" * 64)
        self.assertEqual("approval_ceremony_evidence_unavailable_or_mismatch", self.evaluate().reason)

    def test_other_envelope_denies_even_when_rehashed(self):
        changed = dict(self.bundle)
        changed["envelope"] = dict(self.bundle["envelope"], approval_id="approval:other")
        self.set_bundle(changed)
        self.assertEqual("approval_ceremony_evidence_unavailable_or_mismatch", self.evaluate().reason)

    def test_bad_challenge_denies_after_hash_check(self):
        changed = dict(self.bundle)
        changed["assertion"] = json.dumps({"id": "credential:test", "challenge": "0" * 64})
        self.set_bundle(changed)
        self.assertEqual("approval_ceremony_verification_failed", self.evaluate().reason)

    def test_noncanonical_bytes_denied(self):
        self.reader.content = canonical(self.bundle)
        self.assertEqual("approval_ceremony_evidence_unavailable_or_mismatch", self.evaluate().reason)


if __name__ == "__main__":
    unittest.main()

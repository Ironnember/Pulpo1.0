"""Cross-boundary authority-service -> reference-only worker poll -> protected kernel.

An Ed25519 test authority signer is used, but authenticator and evidence reader
are synthetic. This test does NOT establish human WebAuthn or cloud custody.
"""
from dataclasses import asdict, replace
from hashlib import sha256
import json
import unittest

from pulpo import (
    AuthorityClient, CeremonyTrust, CeremonyVerification, GovernanceKernel,
    Policy,
)
from pulpo.ceremony import CeremonyEvidenceReference
from test_service import AuthorityServiceTests, NOW


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class TestEvidenceReader:
    def __init__(self, evidence):
        self.evidence = evidence
        self.calls = 0

    def read(self, digest):
        self.calls += 1
        for entry in self.evidence.bundles:
            if entry["hash"] == digest:
                return canonical(entry["bundle"]) + b"\n"
        raise FileNotFoundError("test protected evidence unavailable")


class TestCeremonyVerifier:
    verifier_id = "test:external-ceremony-verifier"
    rp_id = "example.com"
    origin = "https://authority.example.com"

    def __init__(self, credential_id):
        self.credential_id = credential_id
        self.credential_set_hash = sha256(credential_id.encode()).hexdigest()
        self.calls = 0

    def verify(self, proof, *, expected_challenge):
        self.calls += 1
        actual = json.loads(proof.assertion)
        if actual.get("id") != self.credential_id:
            raise ValueError("credential mismatch")
        if actual.get("challenge") != expected_challenge.hex():
            raise ValueError("challenge mismatch")
        return CeremonyVerification(
            self.credential_id, True, True, False, False, 5,
        )


class AuthorityEvidenceWireIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = AuthorityServiceTests()
        self.fixture.setUp()
        self.reader = TestEvidenceReader(self.fixture.evidence)
        self.verifier = TestCeremonyVerifier(self.fixture.primary.credential_id)
        self.policy = Policy(
            frozenset({"push"}), 100, frozenset({"push"}),
            authority_trust=self.fixture.trust,
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=CeremonyTrust(
                self.verifier.verifier_id,
                self.verifier.rp_id,
                self.verifier.origin,
                self.verifier.credential_set_hash,
            ),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            approval_verifier=self.fixture.approval_verifier,
            ceremony_verifier=self.verifier,
            ceremony_evidence_reader=self.reader,
            clock=lambda: NOW,
        )
        self.request = replace(
            self.fixture.request, policy_hash=self.kernel.policy_hash
        )

    def approval(self):
        request_id, _ = self.fixture.service.request_approval(self.request)
        challenge = self.fixture.service.challenge(request_id)
        assertion = json.dumps({
            "id": self.fixture.primary.credential_id,
            "challenge": challenge.hex(),
        })
        self.fixture.service.approve(
            request_id, self.fixture.primary.credential_id, assertion
        )
        response = self.fixture.service.poll(request_id)
        self.assertNotIn("ceremony_proof", response)
        self.assertNotIn("assertion", response)
        self.assertIn("ceremony_evidence_ref", response)
        client = AuthorityClient(
            "https://authority.example.com",
            transport=lambda method, endpoint, body: response,
        )
        poll = client.poll_approval(request_id)
        self.assertEqual("approved", poll.status)
        self.assertEqual(request_id, poll.ceremony_evidence_ref.request_id)
        self.assertEqual(1, len(self.fixture.evidence.bundles))
        self.assertEqual(
            self.fixture.evidence.bundles[0]["hash"],
            poll.ceremony_evidence_ref.evidence_hash,
        )
        return request_id, poll

    def test_service_poll_reference_passes_full_kernel_approval_checks(self):
        _, poll = self.approval()
        decision = self.kernel.evaluate_with_approval(
            self.fixture.intent, poll.envelope,
            ceremony_evidence_ref=poll.ceremony_evidence_ref,
        )
        self.assertEqual(("allow", "verified_approval"),
                         (decision.outcome, decision.reason))
        self.assertEqual(1, self.verifier.calls)
        self.assertEqual(1, self.reader.calls)
        self.assertTrue(self.kernel.consume(decision.permit, self.fixture.intent))
        self.assertFalse(self.kernel.consume(decision.permit, self.fixture.intent))
        self.assertTrue(self.kernel.verify_audit())

    def test_missing_protected_reader_blocks_signed_service_envelope(self):
        _, poll = self.approval()
        unprotected = GovernanceKernel(
            self.policy,
            approval_verifier=self.fixture.approval_verifier,
            ceremony_verifier=self.verifier,
            clock=lambda: NOW,
        )
        decision = unprotected.evaluate_with_approval(
            self.fixture.intent, poll.envelope,
            ceremony_evidence_ref=poll.ceremony_evidence_ref,
        )
        self.assertEqual(("deny", "approval_ceremony_evidence_reader_unavailable"),
                         (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)
        self.assertEqual(0, self.verifier.calls)

    def test_tampered_reference_cannot_authorize_signed_service_envelope(self):
        _, poll = self.approval()
        tampered = CeremonyEvidenceReference(
            poll.ceremony_evidence_ref.request_id, "0" * 64
        )
        decision = self.kernel.evaluate_with_approval(
            self.fixture.intent, poll.envelope,
            ceremony_evidence_ref=tampered,
        )
        self.assertEqual(("deny", "approval_ceremony_evidence_unavailable_or_mismatch"),
                         (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)
        self.assertEqual(0, self.verifier.calls)

    def test_incomplete_approved_service_evidence_cannot_be_polled(self):
        request_id, poll = self.approval()
        self.fixture.state.requests[request_id].evidence_hash = None
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.fixture.service.poll(request_id)
        self.assertEqual("approved", poll.status)
        self.assertEqual(0, self.verifier.calls)


if __name__ == "__main__":
    unittest.main()

"""Synthetic acceptance checks for ceremony-proof handoff only.

This is a transport/kernel composition test. It does not prove actual WebAuthn
authenticator verification, custody of assertions or production authority.
"""
from dataclasses import asdict
import hashlib
import unittest

from pulpo import (
    AuthorityClient,
    CeremonyProof,
    CeremonyTrust,
    CeremonyVerification,
    GovernanceKernel,
    Intent,
    Policy,
    expected_ceremony_challenge,
)
from pulpo.orchestrator import OrchestrationError, PulpoOrchestrator
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 10_000_000
CREDENTIAL_ID = "credential:test-primary"
CREDENTIAL_HASH = hashlib.sha256(CREDENTIAL_ID.encode()).hexdigest()


class SyntheticCeremonyVerifier:
    verifier_id = "ceremony-verifier:handoff-fixture"
    rp_id = "authority.example.com"
    origin = "https://authority.example.com"
    credential_set_hash = CREDENTIAL_HASH

    def __init__(self):
        self.calls = []

    def verify(self, proof, *, expected_challenge):
        self.calls.append((proof, expected_challenge))
        if proof.assertion != expected_challenge.hex():
            raise ValueError("invalid challenge")
        return CeremonyVerification(
            credential_id=proof.credential_id,
            user_present=True,
            user_verified=True,
            backup_eligible=False,
            backed_up=False,
            new_sign_count=5,
        )


class CeremonyHandoffTests(unittest.TestCase):
    def setUp(self):
        self.signer = HmacTestVerifier()
        self.verifier = SyntheticCeremonyVerifier()
        self.kernel = GovernanceKernel(
            Policy(
                allowed_actions=frozenset({"write"}),
                max_cost=1,
                approval_actions=frozenset({"write"}),
                authority_trust=trust_for(self.signer),
                ceremony_actions=frozenset({"write"}),
                ceremony_trust=CeremonyTrust(
                    verifier_id=self.verifier.verifier_id,
                    rp_id=self.verifier.rp_id,
                    origin=self.verifier.origin,
                    credential_set_hash=self.verifier.credential_set_hash,
                ),
            ),
            approval_verifier=self.signer,
            ceremony_verifier=self.verifier,
            clock=lambda: NOW,
            secret=b"synthetic-ceremony-handoff",
        )
        self.intent = Intent("agent:fixture", "write", "repo:fixture", 1, "session:fixture")
        self.envelope = signed_envelope(
            self.kernel,
            self.intent,
            self.signer,
            now_ns=NOW - 10,
            approval_id="approval:handoff",
            nonce="nonce:handoff",
        )
        self.proof = CeremonyProof(
            request_id="request:handoff",
            credential_id=CREDENTIAL_ID,
            assertion=expected_ceremony_challenge(self.envelope, "request:handoff").hex(),
        )

    def setup_orchestrator(self, *, proof_marker="valid"):
        envelope = self.envelope
        proof = self.proof if proof_marker == "valid" else (
            None if proof_marker == "missing" else
            CeremonyProof("request:substituted", CREDENTIAL_ID, self.proof.assertion)
        )
        calls = []

        def transport(method, path, body):
            calls.append((method, path))
            if method == "POST":
                return {
                    "request_id": "request:handoff",
                    "approval_url": "https://authority.example.com/human/approval/request:handoff",
                }
            result = {"status": "approved", "envelope": asdict(envelope)}
            if proof is not None:
                result["ceremony_proof"] = asdict(proof)
            return result

        client = AuthorityClient("https://authority.example.com", transport=transport)
        orchestrator = PulpoOrchestrator(self.kernel, authority_client=client)
        target = orchestrator.lock_target("target:handoff", self.intent)
        handle = orchestrator.request_target_approval(target, requested_ttl_ns=100)
        return orchestrator, handle, calls

    def test_valid_exact_proof_is_forwarded_through_client_target_and_kernel(self):
        orchestrator, handle, calls = self.setup_orchestrator()
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual("match", attempt.resolution.outcome)
        self.assertEqual("allow", attempt.decision.outcome)
        self.assertEqual(1, len(self.verifier.calls))
        self.assertEqual(self.proof, self.verifier.calls[0][0])
        self.assertEqual(1, len([x for x in calls if x[0] == "GET"]))
        self.assertTrue(orchestrator.consume_authorized_target(attempt))
        self.assertFalse(orchestrator.consume_authorized_target(attempt))

    def test_missing_proof_fails_closed_for_required_ceremony(self):
        orchestrator, handle, _ = self.setup_orchestrator(proof_marker="missing")
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual(("deny", "approval_ceremony_proof_missing"),
                         (attempt.decision.outcome, attempt.decision.reason))
        self.assertIsNone(attempt.decision.permit)
        self.assertEqual([], self.verifier.calls)

    def test_mismatched_request_id_fails_before_kernel(self):
        orchestrator, handle, _ = self.setup_orchestrator(proof_marker="wrong")
        with self.assertRaisesRegex(OrchestrationError, "approval_ceremony_request_mismatch"):
            orchestrator.authorize_target(handle)
        self.assertEqual([], self.verifier.calls)
        self.assertFalse(any(r["event"] == "approval_verified" for r in self.kernel.audit))

    def test_mismatched_challenge_fails_at_independent_verifier(self):
        orchestrator, handle, _ = self.setup_orchestrator(proof_marker="valid")
        wrong = CeremonyProof(self.proof.request_id, CREDENTIAL_ID, "00" * 32)

        def transport(method, path, body):
            if method == "POST":
                return {
                    "request_id": "request:handoff",
                    "approval_url": "https://authority.example.com/human/approval/request:handoff",
                }
            return {
                "status": "approved",
                "envelope": asdict(self.envelope),
                "ceremony_proof": asdict(wrong),
            }

        orchestrator.authority_client = AuthorityClient(
            "https://authority.example.com", transport=transport
        )
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual(("deny", "approval_ceremony_verification_failed"),
                         (attempt.decision.outcome, attempt.decision.reason))
        self.assertIsNone(attempt.decision.permit)

    def test_nonapproved_poll_cannot_carry_ceremony_proof(self):
        client = AuthorityClient(
            "https://authority.example.com",
            transport=lambda *_: {
                "status": "denied", "reason": "human_denied",
                "ceremony_proof": asdict(self.proof)
            },
        )
        with self.assertRaisesRegex(ValueError, "only approved polls"):
            client.poll_approval("request:handoff")

    def test_malformed_ceremony_proof_fails_closed(self):
        client = AuthorityClient(
            "https://authority.example.com",
            transport=lambda *_: {
                "status": "approved",
                "envelope": asdict(self.envelope),
                "ceremony_proof": "caller-provided-claim",
            },
        )
        with self.assertRaisesRegex(ValueError, "invalid ceremony proof"):
            client.poll_approval("request:handoff")

    def test_target_substitution_stops_before_poll_or_approval(self):
        orchestrator, handle, calls = self.setup_orchestrator()
        from dataclasses import replace
        wrong = replace(handle, target_hash="0" * 64)
        attempt = orchestrator.authorize_target(wrong)
        self.assertEqual("deny", attempt.resolution.outcome)
        self.assertIsNone(attempt.decision)
        self.assertEqual(0, len([c for c in calls if c[0] == "GET"]))

    def test_legacy_envelope_without_proof_remains_non_ceremony_legacy(self):
        legacy = GovernanceKernel(
            Policy(frozenset({"write"}), 1, frozenset({"write"}),
                   authority_trust=trust_for(self.signer)),
            approval_verifier=self.signer,
            clock=lambda: NOW,
        )
        legacy_envelope = signed_envelope(
            legacy, self.intent, self.signer, now_ns=NOW - 10,
            approval_id="approval:legacy", nonce="nonce:legacy",
        )
        self.assertEqual("allow", legacy.evaluate_with_approval(self.intent, legacy_envelope).outcome)


if __name__ == "__main__":
    unittest.main()

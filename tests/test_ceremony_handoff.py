"""Synthetic protected-reference handoff; not live WebAuthn, HSM or provider proof."""
from dataclasses import asdict, replace
from hashlib import sha256
import json
import unittest
from pulpo import AuthorityClient, CeremonyProof, CeremonyTrust, CeremonyVerification, GovernanceKernel, Intent, Policy, expected_ceremony_challenge
from pulpo.ceremony import CeremonyEvidenceReference
from pulpo.orchestrator import OrchestrationError, PulpoOrchestrator
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for

NOW = 10_000_000
CREDENTIAL = "credential:test-primary"
REQUEST = "request:handoff"
CREDENTIAL_HASH = sha256(CREDENTIAL.encode()).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

class SyntheticVerifier:
    verifier_id = "ceremony-verifier:handoff-fixture"
    rp_id = "authority.example.com"
    origin = "https://authority.example.com"
    credential_set_hash = CREDENTIAL_HASH
    def __init__(self):
        self.calls = []
    def verify(self, proof, *, expected_challenge):
        self.calls.append((proof, expected_challenge))
        value = json.loads(proof.assertion)
        if value.get("challenge") != expected_challenge.hex() or value.get("id") != proof.credential_id:
            raise ValueError("fixture challenge or credential mismatch")
        return CeremonyVerification(proof.credential_id, True, True, False, False, 5)

class ProtectedReader:
    def __init__(self):
        self.data = None
        self.calls = 0
    def read(self, digest):
        self.calls += 1
        if self.data is None:
            raise FileNotFoundError("fixture evidence missing")
        return self.data

class CeremonyHandoffTests(unittest.TestCase):
    def setUp(self):
        self.signer = HmacTestVerifier()
        self.verifier = SyntheticVerifier()
        self.reader = ProtectedReader()
        self.kernel = GovernanceKernel(
            Policy(
                frozenset({"write"}), 1, frozenset({"write"}),
                authority_trust=trust_for(self.signer),
                ceremony_actions=frozenset({"write"}),
                ceremony_trust=CeremonyTrust(
                    self.verifier.verifier_id, self.verifier.rp_id,
                    self.verifier.origin, self.verifier.credential_set_hash,
                ),
            ),
            approval_verifier=self.signer, ceremony_verifier=self.verifier,
            ceremony_evidence_reader=self.reader, clock=lambda: NOW,
            secret=b"synthetic-ceremony-handoff",
        )
        self.intent = Intent("agent:fixture", "write", "repo:fixture", 1, "session:fixture")
        self.envelope = signed_envelope(
            self.kernel, self.intent, self.signer, now_ns=NOW - 10,
            approval_id="approval:handoff", nonce="nonce:handoff",
        )
        self.challenge = expected_ceremony_challenge(self.envelope, REQUEST)
        self.set_bundle()

    def set_bundle(self, *, assertion_challenge=None):
        challenge = self.challenge.hex() if assertion_challenge is None else assertion_challenge
        assertion = json.dumps({"id": CREDENTIAL, "challenge": challenge}, sort_keys=True)
        bundle = {
            "schema": "pulpo.authority-evidence.v1",
            "sequence": 1,
            "request": {
                "principal": self.envelope.principal, "session_id": self.envelope.session_id,
                "intent_hash": self.envelope.intent_hash, "policy_hash": self.envelope.policy_hash,
                "deployment_id": self.envelope.deployment_id,
            },
            "request_id": REQUEST, "challenge_hash": sha256(self.challenge).hexdigest(),
            "credential_id_hash": CREDENTIAL_HASH, "assertion": assertion,
            "envelope": asdict(self.envelope),
        }
        raw = canonical(bundle)
        self.reader.data = raw + b"\n"
        self.reference = CeremonyEvidenceReference(REQUEST, sha256(raw).hexdigest())
        self.proof = CeremonyProof(REQUEST, CREDENTIAL, assertion)

    def orchestrator(self, *, mode="valid"):
        reference = self.reference if mode == "valid" else (
            None if mode == "missing" else
            CeremonyEvidenceReference("request:substituted", self.reference.evidence_hash)
        )
        calls = []
        def transport(method, endpoint, body):
            calls.append((method, endpoint))
            if method == "POST":
                return {
                    "request_id": REQUEST,
                    "approval_url": "https://authority.example.com/human/approval/" + REQUEST,
                }
            result = {"status": "approved", "envelope": asdict(self.envelope)}
            if reference is not None:
                result["ceremony_evidence_ref"] = asdict(reference)
            return result
        client = AuthorityClient("https://authority.example.com", transport=transport)
        orchestrator = PulpoOrchestrator(self.kernel, authority_client=client)
        target = orchestrator.lock_target("target:handoff", self.intent)
        handle = orchestrator.request_target_approval(target, requested_ttl_ns=100)
        return orchestrator, handle, calls

    def test_exact_reference_reaches_reader_verifier_and_one_use_permit(self):
        orchestrator, handle, calls = self.orchestrator()
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual(("match", "allow"), (attempt.resolution.outcome, attempt.decision.outcome))
        self.assertEqual(self.reference, attempt.poll.ceremony_evidence_ref)
        self.assertEqual([(self.proof, self.challenge)], self.verifier.calls)
        self.assertEqual(1, self.reader.calls)
        self.assertEqual(1, len([x for x in calls if x[0] == "GET"]))
        self.assertTrue(orchestrator.consume_authorized_target(attempt))
        self.assertFalse(orchestrator.consume_authorized_target(attempt))

    def test_missing_reference_denies_before_reader(self):
        orchestrator, handle, _ = self.orchestrator(mode="missing")
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual(("deny", "approval_ceremony_evidence_reference_missing"),
                         (attempt.decision.outcome, attempt.decision.reason))
        self.assertIsNone(attempt.decision.permit)
        self.assertEqual(0, self.reader.calls)

    def test_wrong_request_reference_denied_before_reader(self):
        orchestrator, handle, _ = self.orchestrator(mode="wrong")
        with self.assertRaisesRegex(OrchestrationError, "approval_ceremony_evidence_request_mismatch"):
            orchestrator.authorize_target(handle)
        self.assertEqual(0, self.reader.calls)

    def test_bad_challenge_denied_by_verifier(self):
        self.set_bundle(assertion_challenge="00" * 32)
        orchestrator, handle, _ = self.orchestrator()
        attempt = orchestrator.authorize_target(handle)
        self.assertEqual(("deny", "approval_ceremony_verification_failed"),
                         (attempt.decision.outcome, attempt.decision.reason))
        self.assertIsNone(attempt.decision.permit)

    def test_nonapproved_poll_cannot_carry_reference(self):
        client = AuthorityClient("https://authority.example.com", transport=lambda *_: {
            "status": "denied", "reason": "human_denied",
            "ceremony_evidence_ref": asdict(self.reference),
        })
        with self.assertRaisesRegex(ValueError, "only approved polls"):
            client.poll_approval(REQUEST)

    def test_malformed_reference_fails_closed(self):
        client = AuthorityClient("https://authority.example.com", transport=lambda *_: {
            "status": "approved", "envelope": asdict(self.envelope),
            "ceremony_evidence_ref": "caller-claim",
        })
        with self.assertRaisesRegex(ValueError, "invalid ceremony evidence reference"):
            client.poll_approval(REQUEST)

    def test_raw_worker_poll_rejected_even_with_valid_envelope(self):
        for raw in (asdict(self.proof), None, "caller-claim"):
            for include_reference in (True, False):
                with self.subTest(raw=raw, reference=include_reference):
                    result = {
                        "status": "approved", "envelope": asdict(self.envelope),
                        "ceremony_proof": raw,
                    }
                    if include_reference:
                        result["ceremony_evidence_ref"] = asdict(self.reference)
                    client = AuthorityClient(
                        "https://authority.example.com",
                        transport=lambda *_, result=result: result,
                    )
                    with self.assertRaisesRegex(ValueError, "raw ceremony proof forbidden"):
                        client.poll_approval(REQUEST)
        self.assertEqual(0, self.reader.calls)

    def test_target_substitution_stops_before_poll(self):
        orchestrator, handle, calls = self.orchestrator()
        attempt = orchestrator.authorize_target(replace(handle, target_hash="0" * 64))
        self.assertEqual("deny", attempt.resolution.outcome)
        self.assertIsNone(attempt.decision)
        self.assertEqual(0, len([c for c in calls if c[0] == "GET"]))

    def test_legacy_non_ceremony_signature_remains_explicit(self):
        legacy = GovernanceKernel(
            Policy(frozenset({"write"}), 1, frozenset({"write"}),
                   authority_trust=trust_for(self.signer)),
            approval_verifier=self.signer, clock=lambda: NOW,
        )
        envelope = signed_envelope(
            legacy, self.intent, self.signer,
            now_ns=NOW - 10, approval_id="approval:legacy", nonce="nonce:legacy",
        )
        self.assertEqual("allow", legacy.evaluate_with_approval(self.intent, envelope).outcome)


if __name__ == "__main__":
    unittest.main()

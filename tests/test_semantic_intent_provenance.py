from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from pulpo import (
    GovernanceKernel,
    Intent,
    IntentProvenance,
    Policy,
    PulpoOrchestrator,
    SQLiteKernelState,
)
from pulpo.mcp_boundary import PulpoMCPProjection, freeze_mcp_snapshot
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 41_000_000
ACTION = "render_image"
RESOURCE = "image:uploaded-nun-animation"


class SemanticIntentProvenanceProofTests(unittest.TestCase):
    def _path(self) -> Path:
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        return path

    @staticmethod
    def _kernel(path: Path):
        verifier = HmacTestVerifier(secret=b"semantic-provenance-test-authority")
        policy = Policy(
            allowed_actions=frozenset({ACTION}),
            max_cost=0,
            approval_actions=frozenset({ACTION}),
            authority_trust=trust_for(verifier, max_approval_ttl_ns=10_000),
            exact_object_actions=frozenset({ACTION}),
        )
        state = SQLiteKernelState(path)
        kernel = GovernanceKernel(
            policy,
            secret=b"semantic-provenance-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return state, kernel, verifier

    @staticmethod
    def _approved_provenance(transcript: str) -> IntentProvenance:
        return IntentProvenance.from_stages(
            source_kind="voice",
            source="audio-source:screen-recording-2026-09-19",
            transcript=transcript,
            interpretation="Improve the existing animation's polish while keeping the subject fully clothed and non-explicit.",
            proposal="Render one polished, fully clothed, comedic pin-up-style revision of the uploaded nun animation.",
        )

    def test_transcription_drift_cannot_inherit_human_approval(self):
        path = self._path()
        state, kernel, verifier = self._kernel(path)
        self.addCleanup(state.close)

        approved = self._approved_provenance("pin-up territory")
        corrupted = self._approved_provenance("penetratory")
        self.assertNotEqual(approved.transcript_hash, corrupted.transcript_hash)
        self.assertNotEqual(approved.object_hash, corrupted.object_hash)

        approved_intent = Intent(
            "human:owner",
            ACTION,
            RESOURCE,
            0,
            "case-study-1",
            approved.object_hash,
        )
        drifted_intent = replace(approved_intent, object_hash=corrupted.object_hash)

        missing_binding = replace(approved_intent, object_hash=None)
        self.assertEqual(
            ("deny", "object_hash_required"),
            (
                kernel.evaluate(missing_binding).outcome,
                kernel.evaluate(missing_binding).reason,
            ),
        )

        envelope = signed_envelope(
            kernel,
            approved_intent,
            verifier,
            now_ns=NOW,
            approval_id="approval:semantic-provenance",
            nonce="nonce:semantic-provenance",
        )

        denied = kernel.evaluate_with_approval(drifted_intent, envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch", None),
            (denied.outcome, denied.reason, denied.permit),
        )

        allowed = kernel.evaluate_with_approval(approved_intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (allowed.outcome, allowed.reason))
        self.assertIsNotNone(allowed.permit)
        assert allowed.permit is not None

        self.assertFalse(kernel.consume(allowed.permit, drifted_intent))
        self.assertTrue(kernel.consume(allowed.permit, approved_intent))
        self.assertFalse(kernel.consume(allowed.permit, approved_intent))

        state.close()
        restarted_state, restarted_kernel, _ = self._kernel(path)
        self.addCleanup(restarted_state.close)
        self.assertTrue(restarted_kernel.verify_audit())
        self.assertFalse(restarted_kernel.consume(allowed.permit, approved_intent))
        future = restarted_kernel.evaluate(
            replace(approved_intent, session_id="case-study-future")
        )
        self.assertEqual(("require_approval", None), (future.outcome, future.permit))

    def test_capability_stripped_proposal_carries_binding_without_authority(self):
        path = self._path()
        state, kernel, _ = self._kernel(path)
        self.addCleanup(state.close)
        projection = PulpoMCPProjection(freeze_mcp_snapshot(PulpoOrchestrator(kernel)))
        provenance = self._approved_provenance("pin-up territory")
        before = list(kernel.audit)

        proposal = projection.propose_intent(
            "semantic-case-study",
            "human:owner",
            ACTION,
            RESOURCE,
            0,
            "case-study-1",
            1,
            provenance.object_hash,
        )

        self.assertEqual(provenance.object_hash, proposal["intent"]["object_hash"])
        self.assertEqual(
            GovernanceKernel.intent_hash(Intent(**proposal["intent"])),
            proposal["intent_hash"],
        )
        self.assertEqual("none", proposal["authority_effect"])
        self.assertFalse(proposal["canonical_state_mutation"])
        self.assertEqual(before, kernel.audit)

    def test_legacy_unbound_intent_hash_is_byte_for_byte_stable(self):
        intent = Intent("agent", "read", "repo:file", 7, "session-1")
        legacy_payload = {
            "principal": "agent",
            "action": "read",
            "resource": "repo:file",
            "cost": 7,
            "session_id": "session-1",
        }
        expected = sha256(
            json.dumps(
                legacy_payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertEqual(expected, GovernanceKernel.intent_hash(intent))


if __name__ == "__main__":
    unittest.main()

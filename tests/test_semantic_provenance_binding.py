from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
    SemanticProvenance,
    SQLiteKernelState,
    artifact_hash,
)
from pulpo.mcp_boundary import MCPBoundaryError, PulpoMCPProjection, freeze_mcp_snapshot
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 44_000_000
ACTION = "render_asset"
RESOURCE = "media:existing-animation"


class SemanticProvenanceBindingTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier(b"semantic-provenance-test-authority")
        self.kernel = GovernanceKernel(
            Policy(
                allowed_actions=frozenset({ACTION}),
                max_cost=0,
                approval_actions=frozenset({ACTION}),
                authority_trust=trust_for(self.verifier),
                provenance_required_actions=frozenset({ACTION}),
            ),
            secret=b"semantic-provenance-kernel",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )

    @staticmethod
    def _provenance(transcription: str) -> SemanticProvenance:
        return SemanticProvenance(
            source_hash=artifact_hash(b"synthetic-voice-evidence: pin-up territory"),
            transcription_hash=artifact_hash(transcription),
            interpretation_hash=artifact_hash(
                "Improve the existing animation while keeping the subject fully clothed and non-explicit."
            ),
            proposal_hash=artifact_hash(
                "Render the existing animation with smoother motion, stronger shape, and a comedic pin-up aesthetic."
            ),
        )

    def test_required_action_without_provenance_fails_closed(self):
        missing = Intent(
            "local:owner",
            ACTION,
            RESOURCE,
            0,
            "semantic-drift-case",
        )
        decision = self.kernel.evaluate(missing)
        self.assertEqual(
            ("deny", "provenance_required", None),
            (decision.outcome, decision.reason, decision.permit),
        )

    def test_transcription_drift_cannot_inherit_exact_approval_or_permit(self):
        approved_provenance = self._provenance("pin-up territory")
        drifted_provenance = self._provenance("penetratory")
        self.assertNotEqual(approved_provenance.chain_hash, drifted_provenance.chain_hash)

        approved = Intent(
            "local:owner",
            ACTION,
            RESOURCE,
            0,
            "semantic-drift-case",
            approved_provenance.chain_hash,
        )
        drifted = Intent(
            "local:owner",
            ACTION,
            RESOURCE,
            0,
            "semantic-drift-case",
            drifted_provenance.chain_hash,
        )

        self.assertEqual((approved.action, approved.resource), (drifted.action, drifted.resource))
        self.assertNotEqual(self.kernel.intent_hash(approved), self.kernel.intent_hash(drifted))

        envelope = signed_envelope(self.kernel, approved, self.verifier, now_ns=NOW)
        decision = self.kernel.evaluate_with_approval(approved, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        assert decision.permit is not None

        mismatch = self.kernel.evaluate_with_approval(drifted, envelope)
        self.assertEqual(("deny", "approval_intent_mismatch", None), (
            mismatch.outcome,
            mismatch.reason,
            mismatch.permit,
        ))
        self.assertFalse(self.kernel.consume(decision.permit, drifted))
        self.assertTrue(self.kernel.consume(decision.permit, approved))
        self.assertFalse(self.kernel.consume(decision.permit, approved))


    def test_mcp_proposal_carries_provenance_without_gaining_authority(self):
        provenance = self._provenance("pin-up territory")
        projection = PulpoMCPProjection(freeze_mcp_snapshot(PulpoOrchestrator(self.kernel)))
        before = list(self.kernel.audit)

        proposal = projection.propose_intent(
            "semantic-drift-target",
            "local:owner",
            ACTION,
            RESOURCE,
            0,
            "semantic-drift-case",
            1,
            provenance.chain_hash,
        )

        self.assertEqual(provenance.chain_hash, proposal["intent"]["provenance_hash"])
        self.assertEqual("none", proposal["authority_effect"])
        self.assertEqual("none", proposal["governed_effect"])
        self.assertFalse(proposal["canonical_state_mutation"])
        self.assertNotIn("permit", proposal)
        self.assertEqual(before, self.kernel.audit)
        self.assertEqual(
            proposal["intent_hash"],
            self.kernel.intent_hash(Intent(**proposal["intent"])),
        )

    def test_invalid_provenance_fails_closed(self):
        malformed = Intent(
            "local:owner",
            ACTION,
            RESOURCE,
            0,
            "semantic-drift-case",
            "not-a-sha256",
        )
        decision = self.kernel.evaluate(malformed)
        self.assertEqual(("deny", "provenance_invalid", None), (
            decision.outcome,
            decision.reason,
            decision.permit,
        ))

        projection = PulpoMCPProjection(freeze_mcp_snapshot(PulpoOrchestrator(self.kernel)))
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_provenance_invalid"):
            projection.propose_intent(
                "semantic-drift-target",
                "local:owner",
                ACTION,
                RESOURCE,
                0,
                "semantic-drift-case",
                1,
                "not-a-sha256",
            )

    def test_provenance_bound_replay_remains_denied_after_sqlite_restart(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))

        verifier = HmacTestVerifier(b"semantic-provenance-restart-authority")
        policy = Policy(
            allowed_actions=frozenset({ACTION}),
            max_cost=0,
            approval_actions=frozenset({ACTION}),
            authority_trust=trust_for(verifier),
            provenance_required_actions=frozenset({ACTION}),
        )
        state = SQLiteKernelState(path)
        kernel = GovernanceKernel(
            policy,
            secret=b"semantic-provenance-restart-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        provenance = self._provenance("pin-up territory")
        intent = Intent(
            "local:owner",
            ACTION,
            RESOURCE,
            0,
            "restart-case",
            provenance.chain_hash,
        )
        envelope = signed_envelope(kernel, intent, verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(kernel.consume(decision.permit, intent))
        state.close()

        restarted_state = SQLiteKernelState(path)
        self.addCleanup(restarted_state.close)
        restarted = GovernanceKernel(
            policy,
            secret=b"semantic-provenance-restart-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=restarted_state,
        )
        self.assertTrue(restarted.verify_audit())
        self.assertFalse(restarted.consume(decision.permit, intent))
        future = restarted.evaluate(replace(intent, session_id="future-session"))
        self.assertEqual(("require_approval", None), (future.outcome, future.permit))

    def test_legacy_intent_hash_remains_stable_without_provenance(self):
        intent = Intent("agent", "read", "repo:file", 0, "default")
        legacy_payload = {
            "action": "read",
            "cost": 0,
            "principal": "agent",
            "resource": "repo:file",
            "session_id": "default",
        }
        expected = hashlib.sha256(
            json.dumps(legacy_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(expected, GovernanceKernel.intent_hash(intent))


if __name__ == "__main__":
    unittest.main()

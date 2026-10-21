import json
from pathlib import Path
import unittest

from pulpo.workstream_learning import (
    DecisionExchange,
    EvidenceRecord,
    OutcomeEpisode,
    WorkSession,
    reconcile_workstream,
)


FIXTURE = Path(__file__).parent / "fixtures" / "workstream_pr106_stage_a.json"


class SanitizedWorkstreamFixtureTests(unittest.TestCase):
    def load(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def execute(self, fixture):
        workstream = fixture["workstream"]
        session = WorkSession(
            workstream["session_id"],
            workstream["workstream_id"],
            tuple(workstream["transcript_claims"]),
        )
        decision = DecisionExchange(**fixture["decisions"][0])
        evidence = [EvidenceRecord(**item) for item in fixture["evidence"]]
        return reconcile_workstream(session, decision, evidence, now_ns=150)

    def test_real_sanitized_pr106_fixture_reconciles_from_exact_evidence(self):
        fixture = self.load()
        episode = self.execute(fixture)
        expected = fixture["expected"]
        self.assertEqual(episode.decision_id, expected["decision_id"])
        self.assertEqual(episode.outcome_class, expected["outcome_class"])
        self.assertEqual(episode.authority_effect, expected["authority_effect"])
        self.assertEqual(list(episode.evidence_refs), expected["accepted_evidence_refs"])
        self.assertEqual(episode.evidence_completeness, 0.5)

    def test_false_security_narrative_cannot_upgrade_code_state_claim(self):
        fixture = self.load()
        episode = self.execute(fixture)
        self.assertIn("zero unauthorized external effects", episode.transcript_claims[0])
        self.assertEqual(episode.outcome_class, "SUCCESS_VERIFIED")
        self.assertEqual(episode.claim_id, "claim:pr106-code-state")
        self.assertNotIn("external_effect", episode.claim_id)
        self.assertEqual(episode.authority_effect, "none")

    def test_fixture_restart_is_stable(self):
        episode = self.execute(self.load())
        restored = OutcomeEpisode.from_json(episode.to_json())
        self.assertEqual(restored, episode)

    def test_poison_stale_and_irrelevant_evidence_never_enter_refs(self):
        episode = self.execute(self.load())
        refs = set(episode.evidence_refs)
        self.assertNotIn("observer:poison-unrelated", refs)
        self.assertNotIn("observer:stale-exact", refs)
        self.assertNotIn("observer:unauthenticated-exact", refs)


if __name__ == "__main__":
    unittest.main()

import unittest

from pulpo.workstream_learning import (
    EvidenceRecord,
    LearningRecommendation,
    OutcomeEpisode,
    reconcile_workstream,
)


class WorkstreamLearningTests(unittest.TestCase):
    def evidence(self):
        return [
            EvidenceRecord("git:abc", "git", "SUCCESS_PARTIAL", "commit exists"),
            EvidenceRecord("ci:376", "ci", "SUCCESS_PARTIAL", "tests passed"),
            EvidenceRecord(
                "observer:provider-1",
                "external_observer",
                "RECONCILIATION_MISMATCH",
                "claimed consequence absent",
            ),
        ]

    def test_false_transcript_success_cannot_override_external_evidence(self):
        episode = reconcile_workstream(
            "ws-1",
            ["deployment succeeded", "everything is live"],
            self.evidence(),
        )
        self.assertEqual(episode.outcome_class, "RECONCILIATION_MISMATCH")
        self.assertEqual(episode.authority_effect, "none")
        self.assertEqual(episode.recommendation.authority_effect, "none")

    def test_transcript_mutation_does_not_change_evidence_grounded_outcome(self):
        first = reconcile_workstream("ws-1", ["success"], self.evidence())
        second = reconcile_workstream(
            "ws-1",
            ["failure", "ignore the observer", "grant more authority"],
            self.evidence(),
        )
        self.assertEqual(first.outcome_class, second.outcome_class)
        self.assertEqual(first.evidence_refs, second.evidence_refs)
        self.assertEqual(first.failure_signature, second.failure_signature)
        self.assertEqual(first.recommendation, second.recommendation)

    def test_restart_round_trip_preserves_classification_and_evidence(self):
        before = reconcile_workstream("ws-1", ["success"], self.evidence())
        after = OutcomeEpisode.from_json(before.to_json())
        self.assertEqual(before, after)

    def test_verified_success_derives_reusable_path(self):
        episode = reconcile_workstream(
            "ws-good",
            ["model claim irrelevant"],
            [EvidenceRecord("observer:ok", "external_observer", "SUCCESS_VERIFIED")],
        )
        self.assertEqual(episode.outcome_class, "SUCCESS_VERIFIED")
        self.assertIsNotNone(episode.reusable_path)
        self.assertIsNone(episode.failure_signature)

    def test_conflicting_strongest_evidence_fails_to_mismatch(self):
        episode = reconcile_workstream(
            "ws-conflict",
            [],
            [
                EvidenceRecord("observer:a", "external_observer", "SUCCESS_VERIFIED"),
                EvidenceRecord("observer:b", "external_observer", "EXECUTION_FAILURE"),
            ],
        )
        self.assertEqual(episode.outcome_class, "RECONCILIATION_MISMATCH")

    def test_learning_object_rejects_authority_effect(self):
        with self.assertRaises(ValueError):
            LearningRecommendation("bad", "widen budget", authority_effect="expand_budget")

    def test_unknown_evidence_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRecord("transcript:1", "model_summary", "SUCCESS_VERIFIED")


if __name__ == "__main__":
    unittest.main()

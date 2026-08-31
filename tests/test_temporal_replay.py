import unittest

from pulpo.temporal_replay import (
    FrozenProofVector,
    GenerationResult,
    ReplayEvidence,
    TemporalClassification,
    TemporalReplayReport,
    classify_temporal_replay,
)


OLD = "2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8"
NEW = "19e12307a9c8a9527c40d55fc9d668a9000975f7"


def result(commit, passed, admissible=True, evidence_id="proof:1"):
    return GenerationResult(
        commit_id=commit,
        passed=passed,
        evidence=(ReplayEvidence(evidence_id, "ci-proof", admissible),),
    )


class TemporalReplayTests(unittest.TestCase):
    def setUp(self):
        self.proof = FrozenProofVector("pr103-proof-vector", "constitutional-survival")

    def classify(self, old_pass, new_pass):
        return classify_temporal_replay(
            self.proof,
            result(OLD, old_pass, evidence_id="old-proof"),
            result(NEW, new_pass, evidence_id="new-proof"),
        )

    def test_pass_pass_is_invariant_survived(self):
        self.assertEqual(
            self.classify(True, True).classification,
            TemporalClassification.INVARIANT_SURVIVED,
        )

    def test_pass_fail_is_regression(self):
        self.assertEqual(
            self.classify(True, False).classification,
            TemporalClassification.REGRESSION,
        )

    def test_fail_pass_is_improvement(self):
        self.assertEqual(
            self.classify(False, True).classification,
            TemporalClassification.IMPROVEMENT,
        )

    def test_fail_fail_is_persistent_failure(self):
        self.assertEqual(
            self.classify(False, False).classification,
            TemporalClassification.PERSISTENT_FAILURE,
        )

    def test_branch_name_is_not_temporal_identity(self):
        with self.assertRaises(ValueError):
            result("main", True)

    def test_short_sha_is_not_temporal_identity(self):
        with self.assertRaises(ValueError):
            result("2bad0db", True)

    def test_inadmissible_evidence_fails_closed(self):
        report = classify_temporal_replay(
            self.proof,
            result(OLD, True, admissible=False, evidence_id="transcript:claim"),
            result(NEW, True, evidence_id="current-proof"),
        )
        self.assertEqual(report.classification, TemporalClassification.EVIDENCE_INCOMPLETE)
        self.assertNotIn("transcript:claim", report.historical_evidence_refs)

    def test_historical_authority_cannot_be_reactivated(self):
        report = classify_temporal_replay(
            self.proof,
            result(OLD, True),
            result(NEW, True),
            historical_authority_presented_as_current=True,
        )
        self.assertEqual(
            report.classification,
            TemporalClassification.AUTHORITY_REACTIVATION_ATTEMPT,
        )
        self.assertEqual(report.authority_effect, "none")

    def test_proof_must_be_frozen_before_results(self):
        with self.assertRaises(ValueError):
            FrozenProofVector("late-proof", "claim", frozen_before_results=False)

    def test_proof_cannot_carry_authority(self):
        with self.assertRaises(ValueError):
            FrozenProofVector("proof", "claim", authority_effect="expand")

    def test_report_round_trip_is_stable(self):
        report = self.classify(True, True)
        encoded = report.to_json()
        restored = TemporalReplayReport.from_json(encoded)
        self.assertEqual(restored, report)
        self.assertEqual(restored.to_json(), encoded)
        self.assertEqual(restored.historical_commit, OLD)
        self.assertEqual(restored.current_commit, NEW)
        self.assertEqual(restored.proof_vector_id, "pr103-proof-vector")

    def test_report_is_evidence_not_permit(self):
        report = self.classify(True, True)
        payload = report.to_json()
        self.assertNotIn('"permit"', payload)
        self.assertNotIn('"authorized":true', payload)
        self.assertEqual(report.authority_effect, "none")


if __name__ == "__main__":
    unittest.main()

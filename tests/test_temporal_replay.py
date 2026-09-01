import unittest

from pulpo.temporal_replay import (
    EvidenceOutcome,
    FrozenProofVector,
    GenerationResult,
    ReplayEvidence,
    TemporalClassification,
    TemporalReplayReport,
    classify_temporal_replay,
)


OLD = "2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8"
NEW = "19e12307a9c8a9527c40d55fc9d668a9000975f7"
PROOF_SHA256 = "a" * 64


def proof():
    return FrozenProofVector(
        proof_vector_id="pr103-proof-vector",
        claim_id="constitutional-survival",
        proof_definition_sha256=PROOF_SHA256,
        allowed_source_kinds=("ci-proof",),
    )


def evidence(
    commit,
    outcome=EvidenceOutcome.PASS,
    *,
    evidence_id="proof:1",
    proof_vector_id="pr103-proof-vector",
    claim_id="constitutional-survival",
    source_kind="ci-proof",
    authenticated=True,
):
    return ReplayEvidence(
        evidence_id=evidence_id,
        commit_id=commit,
        proof_vector_id=proof_vector_id,
        claim_id=claim_id,
        source_kind=source_kind,
        outcome=outcome,
        authenticated=authenticated,
    )


def generation(commit, *items):
    return GenerationResult(commit_id=commit, evidence=tuple(items))


class TemporalReplayTests(unittest.TestCase):
    def classify(self, old_outcome, new_outcome):
        return classify_temporal_replay(
            proof(),
            generation(OLD, evidence(OLD, old_outcome, evidence_id="old-proof")),
            generation(NEW, evidence(NEW, new_outcome, evidence_id="new-proof")),
        )

    def test_pass_pass_is_invariant_survived(self):
        self.assertEqual(
            self.classify(EvidenceOutcome.PASS, EvidenceOutcome.PASS).classification,
            TemporalClassification.INVARIANT_SURVIVED,
        )

    def test_pass_fail_is_regression(self):
        self.assertEqual(
            self.classify(EvidenceOutcome.PASS, EvidenceOutcome.FAIL).classification,
            TemporalClassification.REGRESSION,
        )

    def test_fail_pass_is_improvement(self):
        self.assertEqual(
            self.classify(EvidenceOutcome.FAIL, EvidenceOutcome.PASS).classification,
            TemporalClassification.IMPROVEMENT,
        )

    def test_fail_fail_is_persistent_failure(self):
        self.assertEqual(
            self.classify(EvidenceOutcome.FAIL, EvidenceOutcome.FAIL).classification,
            TemporalClassification.PERSISTENT_FAILURE,
        )

    def test_branch_name_and_short_sha_are_not_temporal_identities(self):
        with self.assertRaises(ValueError):
            GenerationResult(commit_id="main", evidence=())
        with self.assertRaises(ValueError):
            GenerationResult(commit_id="2bad0db", evidence=())

    def test_proof_definition_requires_exact_sha256(self):
        with self.assertRaises(ValueError):
            FrozenProofVector("proof", "claim", "abc", ("ci-proof",))

    def test_proof_cannot_carry_authority(self):
        with self.assertRaises(ValueError):
            FrozenProofVector("proof", "claim", PROOF_SHA256, ("ci-proof",), "expand")

    def test_evidence_cannot_carry_authority(self):
        with self.assertRaises(ValueError):
            ReplayEvidence(
                "e1",
                OLD,
                "pr103-proof-vector",
                "constitutional-survival",
                "ci-proof",
                EvidenceOutcome.PASS,
                True,
                "expand",
            )

    def test_mismatched_commit_cannot_be_laundered(self):
        report = classify_temporal_replay(
            proof(),
            generation(OLD, evidence(NEW, evidence_id="wrong-generation")),
            generation(NEW, evidence(NEW, evidence_id="new-proof")),
        )
        self.assertEqual(report.classification, TemporalClassification.EVIDENCE_INCOMPLETE)
        self.assertEqual(report.historical_evidence_refs, ())
        self.assertIsNone(report.historical_passed)

    def test_mismatched_proof_or_claim_cannot_be_laundered(self):
        for item in (
            evidence(OLD, proof_vector_id="other-proof"),
            evidence(OLD, claim_id="other-claim"),
        ):
            with self.subTest(item=item):
                report = classify_temporal_replay(
                    proof(),
                    generation(OLD, item),
                    generation(NEW, evidence(NEW)),
                )
                self.assertEqual(
                    report.classification,
                    TemporalClassification.EVIDENCE_INCOMPLETE,
                )
                self.assertIsNone(report.historical_passed)

    def test_wrong_source_or_unauthenticated_evidence_fails_closed(self):
        for item in (
            evidence(OLD, source_kind="transcript"),
            evidence(OLD, authenticated=False),
        ):
            with self.subTest(item=item):
                report = classify_temporal_replay(
                    proof(),
                    generation(OLD, item),
                    generation(NEW, evidence(NEW)),
                )
                self.assertEqual(
                    report.classification,
                    TemporalClassification.EVIDENCE_INCOMPLETE,
                )

    def test_conflicting_outcomes_fail_closed(self):
        report = classify_temporal_replay(
            proof(),
            generation(
                OLD,
                evidence(OLD, EvidenceOutcome.PASS, evidence_id="old-pass"),
                evidence(OLD, EvidenceOutcome.FAIL, evidence_id="old-fail"),
            ),
            generation(NEW, evidence(NEW, evidence_id="new-proof")),
        )
        self.assertEqual(report.classification, TemporalClassification.EVIDENCE_INCOMPLETE)
        self.assertIsNone(report.historical_passed)
        self.assertEqual(report.historical_evidence_refs, ("old-fail", "old-pass"))

    def test_missing_evidence_fails_closed(self):
        report = classify_temporal_replay(
            proof(),
            generation(OLD),
            generation(NEW, evidence(NEW)),
        )
        self.assertEqual(report.classification, TemporalClassification.EVIDENCE_INCOMPLETE)
        self.assertIsNone(report.historical_passed)

    def test_historical_authority_cannot_be_reactivated(self):
        report = classify_temporal_replay(
            proof(),
            generation(OLD, evidence(OLD)),
            generation(NEW, evidence(NEW)),
            historical_authority_ref="historical-permit:abc",
        )
        self.assertEqual(
            report.classification,
            TemporalClassification.AUTHORITY_REACTIVATION_ATTEMPT,
        )
        self.assertEqual(report.authority_effect, "none")

    def test_report_round_trip_is_stable_and_binds_proof(self):
        report = self.classify(EvidenceOutcome.PASS, EvidenceOutcome.PASS)
        encoded = report.to_json()
        restored = TemporalReplayReport.from_json(encoded)
        self.assertEqual(restored, report)
        self.assertEqual(restored.to_json(), encoded)
        self.assertEqual(restored.proof_definition_sha256, PROOF_SHA256)
        self.assertEqual(restored.historical_commit, OLD)
        self.assertEqual(restored.current_commit, NEW)

    def test_report_is_evidence_not_permit(self):
        report = self.classify(EvidenceOutcome.PASS, EvidenceOutcome.PASS)
        payload = report.to_json()
        self.assertNotIn('"permit"', payload)
        self.assertNotIn('"authorized":true', payload)
        self.assertEqual(report.authority_effect, "none")


if __name__ == "__main__":
    unittest.main()

import unittest

from pulpo.proof_zero import ProofZeroEntry, eligible_for_consequential_reference, project_proof_zero


class ProofZeroTests(unittest.TestCase):
    def test_verified_claim_requires_evidence(self):
        with self.assertRaisesRegex(ValueError, "evidence references"):
            ProofZeroEntry("pz:1", "A reproduced claim", "verified", (), "pulpo:canonical")

    def test_recorded_claim_requires_evidence(self):
        with self.assertRaisesRegex(ValueError, "evidence references"):
            ProofZeroEntry("pz:2", "A dated historical result", "recorded", (), "pulpo:history")

    def test_inference_is_not_silently_promoted(self):
        entry = ProofZeroEntry("pz:3", "AI collaboration compressed capital requirements", "inferred", (), "founder:case-study")
        projection = project_proof_zero((entry,), mode="investor")
        self.assertEqual("inferred", projection.entries[0].status)
        self.assertFalse(eligible_for_consequential_reference(entry))

    def test_blocked_claim_requires_named_gap(self):
        with self.assertRaisesRegex(ValueError, "remaining gap"):
            ProofZeroEntry("pz:4", "Hostile workers are contained", "blocked", (), "pulpo:runtime")

    def test_projection_preserves_traceability(self):
        entry = ProofZeroEntry(
            "pz:5",
            "Approval replay remains rejected after restart",
            "verified",
            ("audit:approval-consumed", "test:restart-replay"),
            "branch:proof/restart-safe-replay",
        )
        projection = project_proof_zero((entry,), mode="security_review")
        self.assertEqual(entry, projection.entries[0])
        self.assertEqual(("audit:approval-consumed", "test:restart-replay"), projection.evidence_refs)
        self.assertTrue(eligible_for_consequential_reference(entry))

    def test_projection_cannot_change_authority(self):
        with self.assertRaisesRegex(ValueError, "cannot alter authority"):
            ProofZeroEntry("pz:6", "Narrative claim", "proposed", (), "societal", authority_effect="expand")

    def test_public_projection_does_not_upgrade_recorded_to_verified(self):
        entry = ProofZeroEntry("pz:7", "Historical dogfood result", "recorded", ("record:dogfood",), "pulpo:history")
        projection = project_proof_zero((entry,), mode="public_founder")
        self.assertEqual("recorded", projection.entries[0].status)


if __name__ == "__main__":
    unittest.main()

"""Read-only canonical audit projection regression tests."""
import unittest
from dataclasses import replace
from pulpo import GovernanceKernel, Policy
from pulpo.gladiator_gate import GladiatorRecord
from pulpo.gladiator_audit_projection import audit_references_present


class GladiatorAuditProjectionTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(Policy(frozenset({"read"}), 0))
        self.object_id = "assessment:fixture"
        self.revision = "sha256:fixture"
        roles = ("pulpo_assessment", "gladiator_tournament", "gladiator_battle",
                 "independent_verdict", "reconciliation", "held_out_evaluation")
        hashes = []
        for role in roles:
            payload = {"object_id": self.object_id, "source_revision": self.revision,
                       "authority_effect": "none"}
            if role == "independent_verdict":
                payload["verdict"] = "PASS"
            if role == "reconciliation":
                payload["state"] = "COMPLETE"
            self.kernel._state.append(role, payload, 1)
            hashes.append(self.kernel.audit[-1]["hash"])
        self.record = GladiatorRecord(
            object_id=self.object_id, source_revision=self.revision,
            pulpo_assessment_ref=hashes[0], tournament_ref=hashes[1],
            teams=("attack", "defend"), battle_refs=(hashes[2],),
            independent_verdict_ref=hashes[3], reconciliation_ref=hashes[4],
            unresolved_risks=(), held_out_ref=hashes[5],
            independent_verdict="PASS", reconciliation_state="COMPLETE",
            completion_claim="VERIFIED",
        )

    def eligible(self, record=None):
        return audit_references_present(self.kernel,
            self.record if record is None else record,
            expected_object=self.object_id, expected_revision=self.revision)

    def test_matching_audit_references(self):
        before = tuple(entry["hash"] for entry in self.kernel.audit)
        self.assertTrue(self.eligible())
        self.assertEqual(before, tuple(entry["hash"] for entry in self.kernel.audit))

    def test_fabricated_ref_denied(self):
        self.assertFalse(self.eligible(replace(
            self.record, independent_verdict_ref="self:asserted")))

    def test_cross_object_reference_denied(self):
        self.kernel._state.append("independent_verdict",
            {"object_id": "assessment:other", "source_revision": self.revision,
             "authority_effect": "none", "verdict": "PASS"}, 2)
        self.assertFalse(self.eligible(replace(
            self.record, independent_verdict_ref=self.kernel.audit[-1]["hash"])))

    def test_cross_revision_reference_denied(self):
        self.kernel._state.append("independent_verdict",
            {"object_id": self.object_id, "source_revision": "other",
             "authority_effect": "none", "verdict": "PASS"}, 2)
        self.assertFalse(self.eligible(replace(
            self.record, independent_verdict_ref=self.kernel.audit[-1]["hash"])))

    def test_cross_role_reference_denied(self):
        self.kernel._state.append("gladiator_battle",
            {"object_id": self.object_id, "source_revision": self.revision,
             "authority_effect": "none"}, 2)
        self.assertFalse(self.eligible(replace(
            self.record, independent_verdict_ref=self.kernel.audit[-1]["hash"])))

    def test_verdict_payload_mismatch_denied(self):
        self.kernel._state.append("independent_verdict",
            {"object_id": self.object_id, "source_revision": self.revision,
             "authority_effect": "none", "verdict": "UNKNOWN"}, 2)
        self.assertFalse(self.eligible(replace(
            self.record, independent_verdict_ref=self.kernel.audit[-1]["hash"])))

    def test_reconciliation_payload_mismatch_denied(self):
        self.kernel._state.append("reconciliation",
            {"object_id": self.object_id, "source_revision": self.revision,
             "authority_effect": "none", "state": "PENDING"}, 2)
        self.assertFalse(self.eligible(replace(
            self.record, reconciliation_ref=self.kernel.audit[-1]["hash"])))

    def test_duplicate_evidence_denied(self):
        self.assertFalse(self.eligible(replace(
            self.record, reconciliation_ref=self.record.independent_verdict_ref)))

    def test_pending_reconciliation_denied(self):
        self.assertFalse(self.eligible(replace(
            self.record, reconciliation_state="PENDING")))

    def test_audit_corruption_denied(self):
        self.kernel.audit[0]["payload"]["object_id"] = "tampered"
        self.assertFalse(self.eligible())

    def test_caller_written_audit_not_independence_proof(self):
        # A caller with canonical append capability can forge role-labeled records.
        # The projection proves membership, NOT independent issuer provenance.
        self.assertTrue(self.eligible())


if __name__ == "__main__":
    unittest.main()

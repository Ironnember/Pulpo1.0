import unittest

from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.retention import EvidenceInventory, EvidenceRecord, GovernedRetention, RetentionPolicy
from pulpo.state import InMemoryKernelState


class GovernedRetentionTests(unittest.TestCase):
    def setUp(self):
        self.state = InMemoryKernelState()
        self.kernel = GovernanceKernel(
            Policy(allowed_actions=frozenset({"delete_evidence"}), max_cost=0),
            state=self.state,
            clock=lambda: 20,
        )
        self.inventory = EvidenceInventory()
        self.retention = GovernedRetention(self.inventory, self.state)
        self.policy = RetentionPolicy("policy-1", "GREENLEE_SO", max_age_ns=5)
        self.record = EvidenceRecord(
            evidence_id="evidence-1",
            agency_id="GREENLEE_SO",
            created_at_ns=10,
            payload={"kind": "bodycam", "object": "segment-1"},
        )
        self.retention.create_evidence(self.record, timestamp_ns=10)

    def _decision(self):
        intent = Intent("supervisor", "delete_evidence", "evidence:evidence-1", cost=0)
        return intent, self.kernel.evaluate(intent)

    def test_eligible_deletion_produces_real_hashes_roots_and_nonretrievability(self):
        intent, decision = self._decision()
        root_before = self.inventory.merkle_root

        manifest = self.retention.delete_with_permit(
            kernel=self.kernel,
            intent=intent,
            decision=decision,
            evidence_id="evidence-1",
            policy=self.policy,
            actor="supervisor",
            now_ns=20,
        )

        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.evidence_hash, self.record.evidence_hash)
        self.assertEqual(manifest.merkle_root_before, root_before)
        self.assertNotEqual(manifest.merkle_root_before, manifest.merkle_root_after)
        self.assertIsNone(self.inventory.get("evidence-1"))
        self.assertEqual(manifest.intent_hash, self.kernel.intent_hash(intent))
        self.assertTrue(self.kernel.verify_audit())
        self.assertEqual(self.state.audit[-1]["event"], "deletion_executed")

    def test_not_yet_eligible_fails_closed_and_consumes_permit(self):
        intent, decision = self._decision()

        manifest = self.retention.delete_with_permit(
            kernel=self.kernel,
            intent=intent,
            decision=decision,
            evidence_id="evidence-1",
            policy=self.policy,
            actor="supervisor",
            now_ns=14,
        )

        self.assertIsNone(manifest)
        self.assertIsNotNone(self.inventory.get("evidence-1"))
        events = [item["event"] for item in self.state.audit]
        self.assertIn("retention_evaluated", events)
        self.assertIn("deletion_rejected", events)
        self.assertFalse(self.kernel.consume(decision.permit, intent))
        self.assertTrue(self.kernel.verify_audit())

    def test_wrong_actor_or_resource_cannot_delete(self):
        intent = Intent("supervisor", "delete_evidence", "evidence:other", cost=0)
        decision = self.kernel.evaluate(intent)

        manifest = self.retention.delete_with_permit(
            kernel=self.kernel,
            intent=intent,
            decision=decision,
            evidence_id="evidence-1",
            policy=self.policy,
            actor="supervisor",
            now_ns=20,
        )

        self.assertIsNone(manifest)
        self.assertIsNotNone(self.inventory.get("evidence-1"))
        self.assertEqual(self.state.audit[-1]["payload"]["reason"], "deletion_intent_mismatch")
        self.assertTrue(self.kernel.verify_audit())

    def test_agency_policy_mismatch_denies(self):
        intent, decision = self._decision()
        wrong_policy = RetentionPolicy("policy-2", "OTHER_AGENCY", max_age_ns=5)

        manifest = self.retention.delete_with_permit(
            kernel=self.kernel,
            intent=intent,
            decision=decision,
            evidence_id="evidence-1",
            policy=wrong_policy,
            actor="supervisor",
            now_ns=20,
        )

        self.assertIsNone(manifest)
        self.assertIsNotNone(self.inventory.get("evidence-1"))
        self.assertEqual(self.state.audit[-1]["payload"]["reason"], "agency_policy_mismatch")
        self.assertTrue(self.kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

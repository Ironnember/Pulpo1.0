from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments/temporal-transfer-matrix/run.py"

spec = importlib.util.spec_from_file_location("temporal_transfer_matrix", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TemporalTransferMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = module.run()
        cls.checkpoints = cls.result["checkpoints"]

    def test_freeze_precedes_evaluator_and_is_immutable(self):
        self.assertEqual(
            "f136b703178b21cfabc3a65de2485317419e7f41",
            self.result["freeze_commit"],
        )
        self.assertTrue(self.result["freeze_sha256"])

    def test_real_checkpoint_lineage_is_linear(self):
        self.assertTrue(self.result["checkpoint_chain"])
        for pair in self.result["checkpoint_chain"]:
            with self.subTest(pair=pair):
                self.assertTrue(pair["is_ancestor"])

    def test_every_transferable_lesson_has_git_provenance(self):
        self.assertEqual(7, len(self.result["provenance"]))
        for proof in self.result["provenance"]:
            with self.subTest(lesson=proof["id"]):
                self.assertTrue(proof["verified"])
                self.assertEqual(64, len(proof["content_sha256"]))

    def test_all_valid_lessons_are_considered_at_every_generation(self):
        expected = {
            "K_APPROVAL",
            "K_RESTART",
            "K_ASYMMETRIC",
            "K_AUTH_SERVICE",
            "K_SOURCE_PRECEDENCE",
            "K_DIRECTIVE",
            "K_RETRIEVAL",
        }
        for checkpoint in self.checkpoints:
            with self.subTest(checkpoint=checkpoint["id"]):
                accepted = {item["id"] for item in checkpoint["accepted"]}
                self.assertEqual(expected, accepted)

    def test_adversarial_retrieval_order_never_overrides_governance(self):
        for checkpoint in self.checkpoints:
            with self.subTest(checkpoint=checkpoint["id"]):
                rejected = {item["id"]: item["reason"] for item in checkpoint["rejected"]}
                self.assertEqual("authority_expansion_forbidden", rejected["A_POISON"])
                self.assertEqual("scope_not_applicable", rejected["A_IRRELEVANT"])
                self.assertEqual("invalidated_or_stale", rejected["A_STALE"])

    def test_projection_changes_knowledge_not_git_or_authority(self):
        for checkpoint in self.checkpoints:
            with self.subTest(checkpoint=checkpoint["id"]):
                self.assertEqual(checkpoint["tree_before"], checkpoint["tree_after"])
                self.assertEqual("none", checkpoint["authority_effect"])
                self.assertFalse(checkpoint["consequential_action_authorized"])
                self.assertGreaterEqual(checkpoint["projected_score"], checkpoint["baseline_score"])

    def test_knowledge_gap_contracts_as_repository_learns_natively(self):
        gains = self.result["knowledge_gains"]
        baseline = self.result["baseline_scores"]
        projected = self.result["projected_scores"]
        self.assertEqual(8, len(gains))
        self.assertTrue(all(a >= b for a, b in zip(gains, gains[1:])), gains)
        self.assertGreater(gains[0], gains[-1])
        self.assertTrue(all(a <= b for a, b in zip(baseline, baseline[1:])), baseline)
        self.assertTrue(all(a <= b for a, b in zip(projected, projected[1:])), projected)

    def test_future_projection_is_distinguished_from_inherited_knowledge(self):
        first = self.checkpoints[0]
        last = self.checkpoints[-1]
        first_relations = {item["temporal_relation"] for item in first["accepted"]}
        last_relations = {item["temporal_relation"] for item in last["accepted"]}
        self.assertIn("future_projection", first_relations)
        self.assertEqual({"already_inherited"}, last_relations)

    def test_all_frozen_success_conditions_hold(self):
        self.assertTrue(all(self.result["success"].values()), self.result["success"])
        self.assertTrue(self.result["all_success_conditions_met"])


if __name__ == "__main__":
    unittest.main()

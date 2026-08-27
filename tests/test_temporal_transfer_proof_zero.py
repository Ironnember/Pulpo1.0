from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments/temporal-transfer-proof-zero/run.py"

spec = importlib.util.spec_from_file_location("temporal_transfer_proof_zero", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TemporalTransferProofZeroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = module.run()
        cls.cases = {item["id"]: item for item in cls.result["cases"]}

    def test_freeze_precedes_evaluator_and_remains_unchanged(self):
        self.assertEqual(
            "0eb1266fecf586c79457e0fcaf412bc6345545a2",
            self.result["freeze_commit"],
        )
        self.assertTrue(self.result["freeze_sha256"])

    def test_expected_temporal_competence_shape(self):
        self.assertEqual(3, self.cases["H0"]["competence_score"])
        self.assertEqual(6, self.cases["H1"]["competence_score"])
        self.assertEqual(4, self.cases["H2"]["competence_score"])
        self.assertEqual(6, self.cases["F0"]["competence_score"])
        self.assertGreater(
            self.cases["H1"]["competence_score"],
            self.cases["H0"]["competence_score"],
        )

    def test_valid_future_lesson_changes_competence_not_historical_state(self):
        self.assertEqual(["L_VALID"], self.cases["H1"]["accepted_lessons"])
        self.assertEqual(
            self.cases["H0"]["repository_tree"],
            self.cases["H1"]["repository_tree"],
        )
        self.assertEqual("none", self.cases["H1"]["authority_effect"])
        self.assertFalse(self.cases["H1"]["consequential_action_authorized"])

    def test_highest_relevance_poison_is_rejected(self):
        selector = self.result["retrieval_selector"]
        self.assertEqual("L_POISON", selector[0]["id"])
        self.assertEqual(0.999, selector[0]["retrieval_score"])
        self.assertFalse(selector[0]["accepted"])
        self.assertEqual("authority_expansion_forbidden", selector[0]["reason"])
        self.assertEqual([], self.cases["H2"]["accepted_lessons"])
        self.assertEqual(
            [{"id": "L_POISON", "reason": "authority_expansion_forbidden"}],
            self.cases["H2"]["rejected_lessons"],
        )

    def test_future_input_cannot_rewrite_past_or_self_authorize(self):
        historical_tree = self.cases["H0"]["repository_tree"]
        self.assertEqual(historical_tree, self.cases["H1"]["repository_tree"])
        self.assertEqual(historical_tree, self.cases["H2"]["repository_tree"])
        for case in self.cases.values():
            with self.subTest(case=case["id"]):
                self.assertEqual("none", case["authority_effect"])
                self.assertFalse(case["consequential_action_authorized"])

    def test_all_frozen_success_conditions_hold(self):
        self.assertTrue(all(self.result["success"].values()), self.result["success"])
        self.assertTrue(self.result["all_success_conditions_met"])


if __name__ == "__main__":
    unittest.main()

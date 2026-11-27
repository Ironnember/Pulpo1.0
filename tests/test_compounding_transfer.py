import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY = ROOT / "experiments" / "compounding" / "verify.py"
spec = importlib.util.spec_from_file_location("compounding_verify", VERIFY)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CompoundingTransferProofTests(unittest.TestCase):
    def setUp(self):
        self.rubric = module.load_json(ROOT / "experiments" / "compounding" / "rubric.json")
        knowledge = module.load_json(ROOT / "experiments" / "compounding" / "knowledge_units.json")
        self.valid_units = {item["id"] for item in knowledge["units"]}
        self.t4 = module.load_json(ROOT / "experiments" / "compounding" / "T4.json")

    def test_experiment_verifies(self):
        result = module.run()
        self.assertTrue(result["verified"])
        self.assertEqual([s["knowledge_units"] for s in result["stages"]], [0, 1, 1, 2, 4])
        self.assertTrue(all(s["authority_effect"] == "none" for s in result["stages"]))

    def test_fresh_replay_is_packet_only_by_contract(self):
        result = module.run()
        replay = next(s for s in result["stages"] if s["stage"] == "T2")
        self.assertEqual(replay["context_contract"], "question_plus_knowledge_packet_only")
        self.assertEqual(replay["knowledge_units"], 1)

    def test_scores_are_bounded(self):
        result = module.run()
        self.assertTrue(all(0 <= s["score"] <= 10 for s in result["stages"]))

    def test_prompt_substitution_is_rejected(self):
        stage = copy.deepcopy(self.t4)
        stage["question"] += " changed"
        with self.assertRaisesRegex(AssertionError, "prompt mismatch"):
            module.verify_stage(stage, self.rubric, self.valid_units)

    def test_authority_expansion_is_rejected(self):
        stage = copy.deepcopy(self.t4)
        stage["authority_effect"] = "grant"
        with self.assertRaisesRegex(AssertionError, "authority expansion"):
            module.verify_stage(stage, self.rubric, self.valid_units)

    def test_knowledge_count_inflation_is_rejected(self):
        stage = copy.deepcopy(self.t4)
        stage["knowledge_units"] = ["K1", "K2", "K3"]
        with self.assertRaisesRegex(AssertionError, "knowledge count mismatch"):
            module.verify_stage(stage, self.rubric, self.valid_units)

    def test_nonverbatim_score_evidence_is_rejected(self):
        stage = copy.deepcopy(self.t4)
        stage["rubric_evidence"]["limiter_diagnosis"] = "invented evaluator evidence"
        with self.assertRaisesRegex(AssertionError, "non-verbatim rubric evidence"):
            module.verify_stage(stage, self.rubric, self.valid_units)


if __name__ == "__main__":
    unittest.main()

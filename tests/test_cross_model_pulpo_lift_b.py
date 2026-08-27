from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments/cross-model-pulpo-lift-b/run.py"

spec = importlib.util.spec_from_file_location("cross_model_pulpo_lift_b", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CrossModelPulpoLiftBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b, cls.b_raw, cls.a, cls.a_raw = module.load_generation_b()
        cls.corrected = module.corrected_freeze(cls.a)

    def test_generation_b_freeze_is_bound_before_runner(self):
        self.assertEqual(
            "07f25a9af6aa82f1677304a3c3129c0681679a66",
            module.B_FREEZE_COMMIT,
        )
        self.assertTrue(self.b_raw)

    def test_parent_freeze_hash_is_exact(self):
        self.assertEqual(
            self.b["parent_experiment"]["freeze_sha256"],
            module._sha(self.a_raw),
        )

    def test_only_semantic_delta_is_credit_ceiling(self):
        expected = json.loads(json.dumps(self.a))
        expected["execution_contract"]["max_ai_credits_per_call"] = 30
        self.assertEqual(expected, self.corrected)
        self.assertEqual(5, self.a["execution_contract"]["max_ai_credits_per_call"])
        self.assertEqual(30, self.corrected["execution_contract"]["max_ai_credits_per_call"])

    def test_tasks_lessons_models_and_scoring_are_identical(self):
        for field in ("models", "conditions", "pulpo_lesson_pack", "tasks", "score_contract", "claim_boundary"):
            with self.subTest(field=field):
                self.assertEqual(self.a[field], self.corrected[field])


if __name__ == "__main__":
    unittest.main()

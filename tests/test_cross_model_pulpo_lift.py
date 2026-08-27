from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
FREEZE = ROOT / "experiments/cross-model-pulpo-lift/freeze.json"
RUNNER = ROOT / "experiments/cross-model-pulpo-lift/run.py"
FREEZE_COMMIT = "a1775e3ea41b14fa57551a4d72a0e4a876a689ab"

spec = importlib.util.spec_from_file_location("cross_model_pulpo_lift", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CrossModelPulpoLiftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.freeze = json.loads(FREEZE.read_text())

    def test_freeze_commit_precedes_runner_and_is_byte_identical(self):
        frozen = subprocess.run(
            [
                "git",
                "show",
                f"{FREEZE_COMMIT}:experiments/cross-model-pulpo-lift/freeze.json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(FREEZE.read_bytes(), frozen)

    def test_frozen_benchmark_has_four_provider_families_and_twelve_tasks(self):
        self.assertEqual(
            ["openai", "anthropic", "google", "xai"],
            [item["family"] for item in self.freeze["models"]],
        )
        self.assertEqual(12, len(self.freeze["tasks"]))
        self.assertEqual(12, len({item["id"] for item in self.freeze["tasks"]}))
        self.assertTrue(all(item["answer"] in {"A", "B", "C", "D"} for item in self.freeze["tasks"]))

    def test_model_prompt_never_contains_answer_key_field(self):
        baseline = module.prompt_for(self.freeze, "MODEL_ONLY")
        augmented = module.prompt_for(self.freeze, "MODEL_PLUS_PULPO")
        self.assertNotIn('"answer"', baseline)
        self.assertNotIn('"answer"', augmented)
        self.assertNotIn("Additional verified operating lessons", baseline)
        self.assertIn("Additional verified operating lessons", augmented)

    def test_pulpo_packet_is_knowledge_not_authority(self):
        packet = " ".join(self.freeze["pulpo_lesson_pack"])
        self.assertIn("do not themselves create authority", module.prompt_for(self.freeze, "MODEL_PLUS_PULPO"))
        self.assertIn("cannot create permission", packet)
        self.assertIn("Retrieval relevance never raises authority", packet)
        self.assertIn("Evidence reports what happened", packet)

    def test_runner_removes_documented_copilot_tools(self):
        excluded = set(module.EXCLUDED_TOOLS.split(","))
        expected = {
            "bash",
            "powershell",
            "apply_patch",
            "create",
            "edit",
            "view",
            "task",
            "ask_user",
            "glob",
            "grep",
            "rg",
            "skill",
            "web_fetch",
        }
        self.assertTrue(expected.issubset(excluded))

    def test_deterministic_scorer_accepts_exact_key_and_rejects_wrong_key(self):
        exact = {
            "answers": [
                {"id": task["id"], "choice": task["answer"]}
                for task in self.freeze["tasks"]
            ]
        }
        score = module.score_response(self.freeze, json.dumps(exact))
        self.assertEqual(12, score["score"])
        self.assertTrue(score["complete"])

        wrong = {
            "answers": [
                {"id": task["id"], "choice": "A" if task["answer"] != "A" else "B"}
                for task in self.freeze["tasks"]
            ]
        }
        score = module.score_response(self.freeze, json.dumps(wrong))
        self.assertEqual(0, score["score"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments/cross-model-pulpo-lift/run_generation4.py"
AUTH = ROOT / "experiments/cross-model-pulpo-lift/execution_authorization_generation4.json"
FREEZE = ROOT / "experiments/cross-model-pulpo-lift/freeze.json"

spec = importlib.util.spec_from_file_location("cross_model_generation4", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CrossModelPulpoLiftGeneration4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = json.loads(AUTH.read_text())
        cls.freeze = json.loads(FREEZE.read_text())

    def test_generation4_authorization_is_exactly_bounded(self):
        scope = self.auth["scope"]
        self.assertEqual(4, self.auth["generation"])
        self.assertEqual(8, scope["maximum_calls"])
        self.assertEqual(30, scope["maximum_ai_credits_per_call"])
        self.assertEqual(240, scope["maximum_total_ai_credits"])
        self.assertEqual(1, scope["execution_count"])
        self.assertEqual("none", self.auth["authority_effect"])

    def test_only_client_capability_changed(self):
        scope = self.auth["scope"]
        for field in (
            "tasks_changed",
            "answers_changed",
            "lesson_packet_changed",
            "model_targets_changed",
            "scoring_changed",
            "tools_changed",
            "authority_changed",
        ):
            self.assertFalse(scope[field])
        self.assertEqual("1.128.0", self.auth["execution_surface"]["copilot_cli_version"])

    def test_authorization_matches_frozen_model_call_matrix(self):
        expected_calls = len(self.freeze["models"]) * len(self.freeze["conditions"])
        self.assertEqual(8, expected_calls)
        self.assertEqual(expected_calls, self.auth["scope"]["maximum_calls"])
        self.assertEqual(
            ["openai", "anthropic", "google", "xai"],
            [model["family"] for model in self.freeze["models"]],
        )

    def test_runner_accepts_authorization_without_changing_freeze(self):
        freeze, auth, raw = module.load_generation4_contract()
        self.assertEqual(self.freeze, freeze)
        self.assertEqual(self.auth, auth)
        self.assertEqual(FREEZE.read_bytes(), raw)
        self.assertEqual(module.EXPECTED_FREEZE_SHA256, module._sha(raw))


if __name__ == "__main__":
    unittest.main()

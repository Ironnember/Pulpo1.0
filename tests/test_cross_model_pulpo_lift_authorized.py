from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments/cross-model-pulpo-lift/run_authorized.py"
AUTH = ROOT / "experiments/cross-model-pulpo-lift/execution_authorization.json"
FREEZE = ROOT / "experiments/cross-model-pulpo-lift/freeze.json"

spec = importlib.util.spec_from_file_location("cross_model_authorized", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AuthorizedCrossModelPulpoLiftTests(unittest.TestCase):
    def test_authorization_is_exactly_eight_calls_at_thirty_credits(self):
        auth = json.loads(AUTH.read_text())
        scope = auth["scope"]
        self.assertEqual(8, scope["maximum_calls"])
        self.assertEqual(30, scope["maximum_ai_credits_per_call"])
        self.assertEqual(240, scope["maximum_total_ai_credits"])
        self.assertEqual(1, scope["execution_count"])
        self.assertEqual("none", auth["authority_effect"])

    def test_authorization_does_not_change_frozen_contract(self):
        freeze, auth, raw = module.load_authorized_contract()
        self.assertEqual(5, freeze["execution_contract"]["max_ai_credits_per_call"])
        self.assertEqual(module.EXPECTED_FREEZE_SHA256, module._sha(raw))
        self.assertEqual(30, auth["scope"]["maximum_ai_credits_per_call"])
        self.assertEqual(4, len(freeze["models"]))
        self.assertEqual(2, len(freeze["conditions"]))
        self.assertEqual(12, len(freeze["tasks"]))

    def test_authorization_bound_to_reconciled_failure_generation(self):
        auth = json.loads(AUTH.read_text())
        self.assertEqual(module.PARENT_FAILURE_HEAD, auth["parent_failure_head"])
        self.assertEqual(module.FREEZE_COMMIT, auth["freeze_commit"])
        self.assertEqual(module.EXPECTED_FREEZE_SHA256, auth["freeze_sha256"])


if __name__ == "__main__":
    unittest.main()

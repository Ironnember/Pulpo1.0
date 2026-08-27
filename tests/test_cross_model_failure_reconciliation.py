from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECONCILER = ROOT / "experiments/cross-model-pulpo-lift/reconcile_results.py"

spec = importlib.util.spec_from_file_location("cross_model_failure_reconciliation", RECONCILER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CrossModelFailureReconciliationTests(unittest.TestCase):
    def test_budget_validation_is_not_mislabeled_model_unavailable(self):
        run = {
            "status": "BLOCKED_MODEL_UNAVAILABLE",
            "attempts": [
                {
                    "stderr_tail": (
                        "error: option '--max-ai-credits <credits>' argument '5' is invalid. "
                        'Invalid value for --max-ai-credits: "5". Use at least 30 AI credits.'
                    )
                }
            ],
        }
        self.assertEqual("BLOCKED_BUDGET_CONFIGURATION", module.classify_block(run))

    def test_model_unavailable_label_is_preserved_without_budget_error(self):
        run = {
            "status": "BLOCKED_MODEL_UNAVAILABLE",
            "attempts": [{"stderr_tail": "requested model is not available"}],
        }
        self.assertEqual("BLOCKED_MODEL_UNAVAILABLE", module.classify_block(run))

    def test_reconciliation_changes_evidence_label_not_budget_or_authority(self):
        result = {
            "runs": [
                {
                    "status": "BLOCKED_MODEL_UNAVAILABLE",
                    "family": "openai",
                    "condition": "MODEL_ONLY",
                    "model": None,
                    "attempts": [{"stderr_tail": "Use at least 30 AI credits"}],
                }
            ]
        }
        reconciled = module.reconcile(result)
        run = reconciled["runs"][0]
        self.assertEqual("BLOCKED_MODEL_UNAVAILABLE", run["recorded_status"])
        self.assertEqual("BLOCKED_BUDGET_CONFIGURATION", run["status"])
        self.assertFalse(reconciled["reconciliation"]["budget_expanded"])
        self.assertEqual("none", reconciled["reconciliation"]["authority_effect"])


if __name__ == "__main__":
    unittest.main()

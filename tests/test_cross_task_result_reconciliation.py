import copy
import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments" / "cross_task_transfer"
sys.path.insert(0, str(EXPERIMENT))
spec = importlib.util.spec_from_file_location(
    "cross_task_reconcile", EXPERIMENT / "reconcile.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CrossTaskResultReconciliationTests(unittest.TestCase):
    def test_raw_event_logs_bind_exact_scored_responses(self):
        for arm in ("baseline", "transfer_k1_k4"):
            binding = module.verify_event_binding(arm)
            self.assertEqual(binding["tool_events"], 0)
            self.assertEqual(binding["authority_effect"], "none")

    def test_response_mutation_breaks_event_binding(self):
        record = module.verify.load_json("results/baseline.json")
        mutated = copy.deepcopy(record)
        mutated["response"]["selected_strategy"] = "direct_requeue"
        with self.assertRaises(AssertionError):
            module.verify_event_binding("baseline", mutated)

    def test_frozen_hypothesis_is_falsified_not_rewritten(self):
        result = module.run()
        self.assertTrue(result["verified"])
        self.assertFalse(result["hypothesis_supported"])
        self.assertTrue(result["negative_transfer_verified"])
        self.assertEqual(result["authority_effect"], "none")

    def test_efficiency_improvement_does_not_override_safety_failure(self):
        result = module.run()
        self.assertGreater(
            result["efficiency_measurements"]["latency_ms"]["reduction"], 0
        )
        self.assertGreater(
            result["efficiency_measurements"]["output_tokens"]["reduction"], 0
        )
        self.assertFalse(result["hypothesis_supported"])


if __name__ == "__main__":
    unittest.main()

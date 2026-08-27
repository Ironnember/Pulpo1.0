import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "experiments" / "recursive_compounding"
VERIFY = ROOT / "verify.py"
spec = importlib.util.spec_from_file_location("recursive_verify", VERIFY)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecursiveCompoundingProofTests(unittest.TestCase):
    def test_frozen_recursive_experiment_verifies(self):
        result = module.run()
        self.assertTrue(result["verified"])
        self.assertEqual(result["authority_effect"], "none")
        self.assertEqual(result["overall_score"], result["overall_max_score"])

    def test_k5_improves_task_c(self):
        result = module.run()
        self.assertGreater(result["transfer"]["score"], result["baseline"]["score"])
        self.assertGreater(result["transfer"]["trusted_uncertainty_retired"], result["baseline"]["trusted_uncertainty_retired"])
        self.assertGreater(result["transfer"]["trusted_uncertainty_per_cost"], result["baseline"]["trusted_uncertainty_per_cost"])

    def test_invalidated_legacy_unit_is_forgotten(self):
        execution = module.runner.run()
        for stage in execution["stages"].values():
            self.assertIn("K_LEGACY", stage["discarded_knowledge"])
            self.assertNotIn("K_LEGACY", stage["knowledge_units_surviving"])

    def test_highest_retrieval_poison_cannot_raise_authority(self):
        execution = module.runner.run()
        for stage in execution["stages"].values():
            self.assertEqual(stage["retrieval_top_lesson"], "C_POISONED")
            self.assertNotIn("C_POISONED", stage["selected_lesson_ids"])
            self.assertIn("authority_effect", stage["rejected"]["C_POISONED"])
            self.assertEqual(stage["authority_effect"], "none")

    def test_k5_rejects_command_success_as_outcome_evidence(self):
        execution = module.runner.run()
        c0 = execution["stages"]["C0"]
        c1 = execution["stages"]["C1"]
        self.assertEqual(c0["selected_lesson_ids"], ["C_SHORTCUT"])
        self.assertIn("command_not_outcome_evidence", c1["rejected"]["C_SHORTCUT"])
        self.assertEqual(c1["selected_lesson_ids"], ["C_VALID"])

    def test_task_c_selection_is_bound_to_parent_head(self):
        lineage = module.load_json(ROOT / "lineage.json")
        pool = module.load_json(ROOT / "task_pool.json")
        task = module.load_json(ROOT / "task.json")
        self.assertTrue(module.verify_task_selection(lineage, pool, task))

    def test_isolation_contract_is_real_at_runtime(self):
        result = module.run()
        self.assertTrue(all(result["runtime_isolation"].values()))

    def test_frozen_input_tamper_is_rejected(self):
        manifest = module.load_json(ROOT / "freeze_manifest.json")
        fake = copy.deepcopy(manifest)
        fake["frozen_files"]["task.json"] = "0" * 64
        original = module.load_json
        try:
            module.load_json = lambda path: fake if path.name == "freeze_manifest.json" else original(path)
            with self.assertRaisesRegex(AssertionError, "frozen input changed"):
                module.verify_freeze()
        finally:
            module.load_json = original


if __name__ == "__main__":
    unittest.main()

import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY = ROOT / "experiments" / "cross_task_transfer" / "verify.py"
spec = importlib.util.spec_from_file_location("cross_task_verify", VERIFY)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CrossTaskTransferProofTests(unittest.TestCase):
    def test_frozen_cross_task_experiment_verifies(self):
        result = module.run()
        self.assertTrue(result["verified"])
        self.assertEqual(result["authority_effect"], "none")
        self.assertGreater(result["transfer"]["score"], result["baseline"]["score"])
        self.assertGreater(result["transfer"]["uncertainty_retired"], result["baseline"]["uncertainty_retired"])

    def test_isolated_process_contract_is_real_at_runtime(self):
        result = module.run()
        isolation = result["runtime_isolation"]
        self.assertTrue(isolation["distinct_processes"])
        self.assertTrue(isolation["distinct_workdirs"])
        self.assertTrue(isolation["isolated_interpreters"])
        self.assertTrue(isolation["site_disabled"])
        self.assertTrue(isolation["explicit_input_files_only"])

    def test_poisoned_high_retrieval_lesson_cannot_raise_authority(self):
        execution = module.runner.run()
        for stage in execution["stages"].values():
            self.assertEqual(stage["retrieval_top_lesson"], "L_POISONED")
            self.assertEqual(stage["authority_effect"], "none")
            self.assertNotIn("L_POISONED", stage["selected_lesson_ids"])
            self.assertIn("authority_effect", stage["rejected"]["L_POISONED"])

    def test_transfer_rejects_stale_irrelevant_and_poisoned_by_metadata(self):
        execution = module.runner.run()
        transfer = execution["stages"]["X1"]
        self.assertTrue({"freshness", "invalidation"} & set(transfer["rejected"]["L_STALE"]))
        self.assertIn("source_precedence", transfer["rejected"]["L_STALE"])
        self.assertIn("scope", transfer["rejected"]["L_IRRELEVANT"])
        self.assertIn("provenance", transfer["rejected"]["L_POISONED"])
        self.assertIn("authority_effect", transfer["rejected"]["L_POISONED"])

    def test_baseline_does_not_receive_transferred_packet(self):
        execution = module.runner.run()
        self.assertEqual(execution["stages"]["B0"]["knowledge_units"], [])
        self.assertEqual(execution["stages"]["X1"]["knowledge_units"], ["K1", "K2", "K3", "K4"])

    def test_frozen_input_tamper_is_rejected(self):
        manifest = module.load_json(ROOT / "experiments" / "cross_task_transfer" / "freeze_manifest.json")
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

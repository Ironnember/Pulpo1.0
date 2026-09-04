import importlib.util
import os
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage_c_supabase_consequence_v1.py"
EXPECTED_SOURCE_MAIN = "d421fbe73732a7ed4c942928d62e80dd6bbb2057"
EXPECTED_CONTRACT_SHA256 = "7ef5902a0481a8f6877a810040b3a1b35fc30c36b82a3c37a213ae8c31098030"
EXPECTED_MATCHED_ROW_SHA256 = "931b28fc95837ff8237561231a1067c7b989233f6a5add65370810e8afdd0dab"


def load_runner():
    spec = importlib.util.spec_from_file_location("stage_c_supabase_runner_v1", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class StageCSupabaseRunnerTests(unittest.TestCase):
    def test_frozen_source_and_hashes_are_exact(self):
        runner = load_runner()
        self.assertEqual(EXPECTED_SOURCE_MAIN, runner.SOURCE_MAIN)
        self.assertEqual(EXPECTED_CONTRACT_SHA256, runner.CONTRACT_SHA256)
        self.assertEqual(EXPECTED_MATCHED_ROW_SHA256, runner.MATCHED_ROW_SHA256)
        self.assertEqual(runner.MATCHED_ROW_SHA256, runner.digest(runner.MATCHED_ROW))

    def test_contract_is_exactly_ten_unique_families(self):
        runner = load_runner()
        ids = [case_id for case_id, _, _ in runner.CONTRACT]
        self.assertEqual(10, len(ids))
        self.assertEqual(10, len(set(ids)))
        self.assertEqual("F01_target_substitution", ids[0])
        self.assertEqual("F10_authority_time_unavailable", ids[-1])

    def test_only_race_allows_one_provider_call(self):
        runner = load_runner()
        expected = {case_id: count for case_id, count, _ in runner.CONTRACT}
        self.assertEqual(1, expected["F07_two_worker_race"])
        self.assertTrue(all(count == 0 for case_id, count in expected.items() if case_id != "F07_two_worker_race"))
        self.assertEqual(1, sum(expected.values()))

    def test_child_environment_strips_every_provider_secret(self):
        runner = load_runner()
        original = {name: os.environ.get(name) for name in runner.SECRET_ENV}
        try:
            for name in runner.SECRET_ENV:
                os.environ[name] = f"secret:{name}"
            child = runner.clean_env()
            for name in runner.SECRET_ENV:
                self.assertNotIn(name, child)
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_provider_action_hash_changes_on_substitution(self):
        runner = load_runner()
        exact_hash, _ = runner.action(runner.MATCHED_ROW, principal="agent:stage-c")
        substituted = dict(runner.MATCHED_ROW)
        substituted["effect_id"] = "stage-c-substituted"
        other_hash, _ = runner.action(substituted, principal="agent:stage-c")
        self.assertNotEqual(exact_hash, other_hash)

    def test_test_signer_is_explicitly_non_independent_in_source(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("ephemeral_test_signer_not_independent_authority", source)
        self.assertIn("independent_human_authority_proven\": False", source)


if __name__ == "__main__":
    unittest.main()

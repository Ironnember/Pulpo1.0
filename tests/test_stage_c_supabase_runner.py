import importlib.util
import os
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage_c_supabase_consequence.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("stage_c_supabase_runner", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StageCSupabaseRunnerTests(unittest.TestCase):
    def test_frozen_matched_row_hash_is_exact(self):
        runner = load_runner()
        self.assertEqual(runner.MATCHED_ROW_SHA256, runner.canonical_hash(runner.MATCHED_ROW))

    def test_frozen_attack_vector_is_exactly_ten_unique_families(self):
        runner = load_runner()
        ids = [case_id for case_id, _ in runner.ATTACKS]
        self.assertEqual(10, len(ids))
        self.assertEqual(10, len(set(ids)))
        self.assertEqual("F01_target_substitution", ids[0])
        self.assertEqual("F10_authority_time_unavailable", ids[-1])

    def test_child_environment_strips_every_provider_secret(self):
        runner = load_runner()
        original = {name: os.environ.get(name) for name in runner.SECRET_ENV_NAMES}
        try:
            for name in runner.SECRET_ENV_NAMES:
                os.environ[name] = f"secret:{name}"
            child = runner.sanitized_child_env()
            for name in runner.SECRET_ENV_NAMES:
                self.assertNotIn(name, child)
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_provider_action_hash_changes_on_substitution(self):
        runner = load_runner()
        exact = runner.provider_action_object("stage_c_insert", runner.MATCHED_ROW)
        substituted = dict(runner.MATCHED_ROW)
        substituted["effect_id"] = "stage-c-substituted"
        other = runner.provider_action_object("stage_c_insert", substituted)
        self.assertNotEqual(runner.canonical_hash(exact), runner.canonical_hash(other))


if __name__ == "__main__":
    unittest.main()

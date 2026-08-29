from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUN_PATH = ROOT / "experiments/compounding-rate-g0-g8/run.py"
SPEC = spec_from_file_location("pulpo_compounding_rate_g0_g8", RUN_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CompoundingRateG0G8Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = MODULE.evaluate()

    def test_all_frozen_success_conditions_hold(self) -> None:
        self.assertTrue(self.result["all_success_conditions_met"])

    def test_compound_curve_is_2_3_4_6_10(self) -> None:
        scores = [item["compound_score"] for item in self.result["generations"]]
        self.assertEqual(scores, [2, 3, 4, 6, 10])

    def test_baseline_stays_flat(self) -> None:
        scores = [item["baseline_score"] for item in self.result["generations"]]
        self.assertEqual(scores, [2, 2, 2, 2, 2])

    def test_authority_never_compounds(self) -> None:
        for generation in self.result["generations"]:
            self.assertEqual(generation["authority_effect"], "none")
            self.assertFalse(generation["consequential_action_authorized"])

    def test_highest_relevance_poison_is_rejected(self) -> None:
        top = self.result["selector"][0]
        self.assertEqual(top["id"], "POISON")
        self.assertFalse(top["accepted"])
        self.assertEqual(top["reason"], "authority_expansion_forbidden")

    def test_stale_and_irrelevant_lessons_are_rejected(self) -> None:
        selector = {item["id"]: item for item in self.result["selector"]}
        self.assertEqual(selector["STALE"]["reason"], "stale_or_invalidated")
        self.assertEqual(selector["IRRELEVANT"]["reason"], "scope_irrelevant")


if __name__ == "__main__":
    unittest.main()

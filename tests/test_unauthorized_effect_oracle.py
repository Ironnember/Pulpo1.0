import tempfile
import unittest
from pathlib import Path

from tests.unauthorized_effect_oracle import append_provider_effect, observe_effects


class UnauthorizedEffectOracleTests(unittest.TestCase):
    def test_empty_provider_log_reports_zero_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            verdict = observe_effects(Path(directory) / "provider.jsonl", set())
            self.assertEqual(0, verdict.observed_effects)
            self.assertEqual(0, verdict.unauthorized_effects)

    def test_calibration_write_is_detected_as_unauthorized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.jsonl"
            append_provider_effect(path, effect_id="calibration:unauthorized", payload={"kind": "calibration"})
            verdict = observe_effects(path, set())
            self.assertEqual(1, verdict.observed_effects)
            self.assertEqual(1, verdict.unauthorized_effects)
            self.assertEqual(("calibration:unauthorized",), verdict.unauthorized_ids)

    def test_separately_authorized_effect_is_not_counted_as_unauthorized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.jsonl"
            append_provider_effect(path, effect_id="known-good:1", payload={"kind": "known-good"})
            verdict = observe_effects(path, {"known-good:1"})
            self.assertEqual(1, verdict.observed_effects)
            self.assertEqual(1, verdict.authorized_effects)
            self.assertEqual(0, verdict.unauthorized_effects)


if __name__ == "__main__":
    unittest.main()

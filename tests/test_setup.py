import json
import tempfile
import unittest
from pathlib import Path

from pulpo.performance_tuning import SystemFingerprint
from pulpo.setup import run_setup


class PulpoSetupTests(unittest.TestCase):
    def _benchmark_document(self):
        fingerprint = SystemFingerprint.detect()
        return {
            "schema": "pulpo.memory-scaling-benchmark.v2",
            "machine": {
                "platform": fingerprint.platform,
                "python": fingerprint.python,
                "cpu_count": fingerprint.cpu_count,
            },
            "parallel_threshold": 256,
            "results": [
                {
                    "records": 10000,
                    "workers": 1,
                    "batch_size": 256,
                    "median_seconds": 0.050,
                    "records_per_second": 200000.0,
                    "samples_seconds": [0.050],
                }
            ],
        }

    def test_setup_builds_profile_from_matching_benchmark(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmark.json"
            profile = root / "profile.json"
            benchmark.write_text(
                json.dumps(self._benchmark_document()),
                encoding="utf-8",
            )

            report = run_setup(
                profile_path=profile,
                benchmark_path=benchmark,
                calibrate_if_needed=False,
            )

            self.assertTrue(profile.exists())
            self.assertEqual("BUILT_FROM_BENCHMARK", report["profile"]["status"])
            self.assertEqual("PASS", report["audit_verification"]["status"])
            self.assertEqual("none", report["authority_effect"])
            self.assertEqual("none", report["governance_changes"])
            self.assertTrue(report["ready_for_test_use"])
            self.assertFalse(report["production_readiness_claim"])

    def test_setup_reuses_matching_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmark.json"
            profile = root / "profile.json"
            benchmark.write_text(
                json.dumps(self._benchmark_document()),
                encoding="utf-8",
            )

            first = run_setup(
                profile_path=profile,
                benchmark_path=benchmark,
                calibrate_if_needed=False,
            )
            self.assertTrue(first["ready_for_test_use"])

            second = run_setup(
                profile_path=profile,
                calibrate_if_needed=False,
            )
            self.assertEqual("LOADED", second["profile"]["status"])
            self.assertTrue(second["ready_for_test_use"])

    def test_invalid_profile_falls_back_conservatively_without_authority_change(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "profile.json"
            profile.write_text('{"schema":"not-pulpo"}', encoding="utf-8")

            report = run_setup(
                profile_path=profile,
                calibrate_if_needed=False,
            )

            self.assertEqual("CONSERVATIVE_FALLBACK", report["profile"]["status"])
            self.assertEqual("PASS", report["audit_verification"]["status"])
            self.assertEqual("none", report["authority_effect"])
            self.assertEqual("none", report["governance_changes"])


if __name__ == "__main__":
    unittest.main()

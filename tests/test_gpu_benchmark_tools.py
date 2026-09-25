import argparse
from contextlib import redirect_stderr
from io import StringIO
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.aggregate_gpu_benchmarks import aggregate_payloads
from scripts.benchmark_gpu import resolve_output_paths


def payload(cpu, gpu, speedup, *, size=1000, backend="rocm"):
    return {
        "schema": "pulpo.gpu-performance-benchmark.v2",
        "metadata": {
            "gpu_name": "AMD Radeon RX 7900 XT",
            "gpu_backend": backend,
            "gpu_implementation": "triton",
            "torch_version": "2.9.1+rocm",
            "torch_hip_version": "7.2",
            "commit_sha": "abc123",
        },
        "results": [{
            "audit_records": size,
            "cpu_median_ms": cpu,
            "gpu_end_to_end_median_ms": gpu,
            "speedup_end_to_end": speedup,
        }],
    }


class GpuBenchmarkToolsTests(unittest.TestCase):
    def test_aggregate_uses_run_level_medians_and_reports_range(self):
        result = aggregate_payloads([
            payload(10, 11, 0.91),
            payload(12, 12, 1.00),
            payload(14, 13, 1.08),
        ])
        row = result["results"][0]
        self.assertEqual(3, row["run_count"])
        self.assertEqual(12, row["cpu_median_of_run_medians_ms"])
        self.assertEqual(12, row["gpu_median_of_run_medians_ms"])
        self.assertEqual(1.0, row["speedup_median_of_runs"])
        self.assertEqual((0.91, 1.08), (row["speedup_min_run"], row["speedup_max_run"]))

    def test_aggregate_rejects_mixed_gpu_backends(self):
        with self.assertRaisesRegex(ValueError, "gpu_backend"):
            aggregate_payloads([payload(10, 11, 0.9), payload(10, 11, 0.9, backend="cuda")])

    def test_benchmark_output_paths_are_unique_and_existing_files_are_protected(self):
        parser = argparse.ArgumentParser()
        with TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(json=None, csv=None, overwrite=False)
            json_path, csv_path = resolve_output_paths(args, parser)
            self.assertEqual(".json", json_path.suffix)
            self.assertEqual(json_path.stem, csv_path.stem)

            args.json = root / "prior.json"
            args.csv = root / "prior.csv"
            args.json.write_text("keep", encoding="utf-8")
            args.csv.write_text("keep", encoding="utf-8")
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                resolve_output_paths(args, parser)
            self.assertEqual("keep", args.json.read_text(encoding="utf-8"))
            args.overwrite = True
            self.assertEqual((args.json, args.csv), resolve_output_paths(args, parser))


if __name__ == "__main__":
    unittest.main()

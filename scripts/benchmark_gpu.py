#!/usr/bin/env python3
"""CPU-vs-GPU audit-integrity benchmark for PyTorch CUDA and ROCm.

The existing Pulpo CPU benchmark remains the baseline. This benchmark adds a
separate, directly comparable workload: recomputing the SHA-256 hashes of the
same canonical audit-record bodies. The CPU implementation is the reference;
GPU output must match it exactly before timing is reported as valid.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from pulpo.gpu_acceleration import cpu_record_hashes, gpu_record_hashes


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def build_chain(count: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    previous = "0" * 64
    for index in range(count):
        body = {
            "event": "gpu_benchmark_seed",
            "payload": {
                "index": index,
                "authority_effect": "none",
                "benchmark": True,
            },
            "previous_hash": previous,
            "timestamp_ns": 1_000_000_000 + index,
        }
        digest = hashlib.sha256(canonical(body)).hexdigest()
        records.append({**body, "hash": digest})
        previous = digest
    return records


def time_cpu(records: list[dict[str, Any]], warmup: int, samples: int) -> list[float]:
    for _ in range(warmup):
        cpu_record_hashes(records)
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        cpu_record_hashes(records)
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    return values


def time_gpu(records: list[dict[str, Any]], warmup: int, samples: int, device: str, implementation: str) -> dict[str, list[float]]:
    import torch

    for _ in range(warmup):
        gpu_record_hashes(records, device=device, implementation=implementation)
    torch.cuda.synchronize()

    end_to_end = []
    device_elapsed = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        gpu_start = torch.cuda.Event(enable_timing=True)
        gpu_end = torch.cuda.Event(enable_timing=True)
        gpu_start.record()
        gpu_record_hashes(records, device=device)
        gpu_end.record()
        torch.cuda.synchronize()
        end_to_end.append((time.perf_counter_ns() - start) / 1_000_000)
        device_elapsed.append(gpu_start.elapsed_time(gpu_end))
    return {"end_to_end": end_to_end, "device_elapsed": device_elapsed}


def stats(values: list[float]) -> dict[str, float]:
    return {
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--device", choices=("auto", "cuda", "rocm"), default="auto")
    parser.add_argument("--implementation", choices=("triton", "torch"), default="triton")
    parser.add_argument("--json", type=Path, default=Path("pulpo-gpu-benchmark.json"))
    parser.add_argument("--csv", type=Path, default=Path("pulpo-gpu-benchmark.csv"))
    args = parser.parse_args()

    if args.samples <= 0 or args.warmup < 0:
        parser.error("samples must be positive and warmup non-negative")

    import torch

    if not torch.cuda.is_available():
        raise SystemExit(
            "A CUDA or ROCm PyTorch GPU is required for this benchmark. "
            f"Installed torch={torch.__version__!r} reports cuda_available=False."
        )

    sizes = [int(item.strip()) for item in args.sizes.split(",") if item.strip()]
    rows = []
    for size in sizes:
        records = build_chain(size)
        expected = cpu_record_hashes(records)
        actual = gpu_record_hashes(records, device=args.device, implementation=args.implementation)
        if actual != expected:
            raise RuntimeError(f"GPU correctness check failed for {size} records")

        cpu = time_cpu(records, args.warmup, args.samples)
        gpu = time_gpu(records, args.warmup, args.samples, args.device, args.implementation)
        cpu_stats = stats(cpu)
        gpu_stats = stats(gpu["end_to_end"])
        device_stats = stats(gpu["device_elapsed"])
        rows.append({
            "audit_records": size,
            "cpu_median_ms": cpu_stats["median_ms"],
            "cpu_p95_ms": cpu_stats["p95_ms"],
            "gpu_end_to_end_median_ms": gpu_stats["median_ms"],
            "gpu_end_to_end_p95_ms": gpu_stats["p95_ms"],
            "gpu_device_elapsed_median_ms": device_stats["median_ms"],
            "gpu_device_elapsed_p95_ms": device_stats["p95_ms"],
            "speedup_end_to_end": cpu_stats["median_ms"] / gpu_stats["median_ms"],
            "speedup_device_elapsed": cpu_stats["median_ms"] / device_stats["median_ms"],
        })

    metadata = {
        "commit_sha": git_sha(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "torch_version": torch.__version__,
        "torch_cuda_version": torch.version.cuda,
        "torch_hip_version": getattr(torch.version, "hip", None),
        "gpu_backend": "rocm" if getattr(torch.version, "hip", None) else "cuda",
        "gpu_implementation": args.implementation,
        "gpu_name": torch.cuda.get_device_name(0),
        "gpu_count": torch.cuda.device_count(),
    }
    payload = {
        "schema": "pulpo.gpu-performance-benchmark.v1",
        "metadata": metadata,
        "config": {"sizes": sizes, "samples": args.samples, "warmup": args.warmup, "implementation": args.implementation},
        "results": rows,
        "governance": {
            "cpu_is_canonical": True,
            "gpu_role": "hash_recomputation_acceleration_only",
            "correctness_required_before_timing": True,
        },
    }
    args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with args.csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"GPU: {metadata['gpu_name']}")
    print(f"Torch: {metadata['torch_version']} | backend: {metadata['gpu_backend']} | HIP: {metadata['torch_hip_version']}")
    print(f"{'records':>10} {'CPU ms':>12} {'GPU e2e ms':>14} {'GPU device ms':>15} {'e2e speedup':>13}")
    for row in rows:
        print(
            f"{row['audit_records']:10d} "
            f"{row['cpu_median_ms']:12.3f} "
            f"{row['gpu_end_to_end_median_ms']:14.3f} "
            f"{row['gpu_device_elapsed_median_ms']:15.3f} "
            f"{row['speedup_end_to_end']:13.2f}x"
        )
    print(f"JSON: {args.json}")
    print(f"CSV:  {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

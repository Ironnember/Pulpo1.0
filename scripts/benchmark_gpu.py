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
from datetime import datetime, timezone
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

from pulpo.gpu_acceleration import (
    cpu_digest_messages,
    cpu_record_digests,
    gpu_digest_messages,
    gpu_record_digests,
    serialize_audit_records,
)
from pulpo.gpu_triton import triton_record_digests_profiled


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
        cpu_record_digests(records)
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        cpu_record_digests(records)
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    return values


def time_prepared_cpu(messages: list[bytes], warmup: int, samples: int) -> list[float]:
    """Measure authoritative CPU hashing when canonical serialization is reused."""
    for _ in range(warmup):
        cpu_digest_messages(messages)
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        cpu_digest_messages(messages)
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    return values


def time_prepared_gpu(
    messages: list[bytes], warmup: int, samples: int, device: str, implementation: str
) -> list[float]:
    """Measure GPU hashing from reusable canonical bytes, excluding JSON encoding."""
    import torch

    for _ in range(warmup):
        gpu_digest_messages(messages, device=device, implementation=implementation)
    torch.cuda.synchronize()
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        gpu_digest_messages(messages, device=device, implementation=implementation)
        torch.cuda.synchronize()
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    return values


def time_gpu(
    records: list[dict[str, Any]],
    warmup: int,
    samples: int,
    device: str,
    implementation: str,
) -> dict[str, Any]:
    import torch

    for _ in range(warmup):
        gpu_record_digests(records, device=device, implementation=implementation)
    torch.cuda.synchronize()

    end_to_end: list[float] = []
    stage_names = ("canonicalization", "host_preparation", "host_to_device", "kernel", "device_to_host", "digest_copy")
    stages: dict[str, list[float] | None] = {
        name: [] if implementation == "triton" else None for name in stage_names
    }
    for _ in range(samples):
        total_start = time.perf_counter_ns()
        if implementation == "triton":
            canonical_start = time.perf_counter_ns()
            messages = serialize_audit_records(records)
            canonical_ms = (time.perf_counter_ns() - canonical_start) / 1_000_000
            _, measured = triton_record_digests_profiled(messages, torch)
            for name in stage_names:
                if name == "canonicalization":
                    stages[name].append(canonical_ms)
                else:
                    stages[name].append(measured[name + "_ms"])
        else:
            gpu_record_digests(records, device=device, implementation=implementation)
            torch.cuda.synchronize()
        end_to_end.append((time.perf_counter_ns() - total_start) / 1_000_000)
    return {"end_to_end": end_to_end, "stages": stages}

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
    parser.add_argument("--json", type=Path, help="JSON output path (default: unique timestamped name)")
    parser.add_argument("--csv", type=Path, help="CSV output path (default: paired with --json)")
    parser.add_argument("--overwrite", action="store_true", help="allow replacing existing output files")
    args = parser.parse_args()

    if args.samples <= 0 or args.warmup < 0:
        parser.error("samples must be positive and warmup non-negative")

    try:
        sizes = [int(item.strip()) for item in args.sizes.split(",") if item.strip()]
    except ValueError:
        parser.error("sizes must be comma-separated positive integers")
    if not sizes or any(size <= 0 for size in sizes):
        parser.error("sizes must contain at least one positive integer")
    if len(set(sizes)) != len(sizes):
        parser.error("sizes must not contain duplicates")

    json_path, csv_path = resolve_output_paths(args, parser)

    import torch

    if not torch.cuda.is_available():
        raise SystemExit(
            "A CUDA or ROCm PyTorch GPU is required for this benchmark. "
            f"Installed torch={torch.__version__!r} reports cuda_available=False."
        )

    rows = []
    for size in sizes:
        records = build_chain(size)
        messages = serialize_audit_records(records)
        # Share one byte-exact canonical serialization across CPU/GPU correctness
        # checks. The full-pipeline timing below still includes serialization.
        expected = cpu_digest_messages(messages)
        actual = gpu_digest_messages(messages, device=args.device, implementation=args.implementation)
        if actual != expected:
            raise RuntimeError(f"GPU correctness check failed for {size} records")

        cpu = time_cpu(records, args.warmup, args.samples)
        cpu_prepared = time_prepared_cpu(messages, args.warmup, args.samples)
        gpu_prepared = time_prepared_gpu(
            messages, args.warmup, args.samples, args.device, args.implementation
        )
        gpu = time_gpu(records, args.warmup, args.samples, args.device, args.implementation)
        cpu_stats = stats(cpu)
        gpu_stats = stats(gpu["end_to_end"])
        stage_stats = {name: stats(values) if values else None for name, values in gpu["stages"].items()}
        rows.append({
            "audit_records": size,
            "cpu_median_ms": cpu_stats["median_ms"],
            "cpu_p95_ms": cpu_stats["p95_ms"],
            "gpu_end_to_end_median_ms": gpu_stats["median_ms"],
            "gpu_end_to_end_p95_ms": gpu_stats["p95_ms"],
            "cpu_prepared_median_ms": stats(cpu_prepared)["median_ms"],
            "gpu_prepared_median_ms": stats(gpu_prepared)["median_ms"],
            "gpu_prepared_speedup": stats(cpu_prepared)["median_ms"] / stats(gpu_prepared)["median_ms"],
            "gpu_canonicalization_median_ms": stage_stats["canonicalization"]["median_ms"] if stage_stats["canonicalization"] else None,
            "gpu_host_preparation_median_ms": stage_stats["host_preparation"]["median_ms"] if stage_stats["host_preparation"] else None,
            "gpu_host_to_device_median_ms": stage_stats["host_to_device"]["median_ms"] if stage_stats["host_to_device"] else None,
            "gpu_kernel_median_ms": stage_stats["kernel"]["median_ms"] if stage_stats["kernel"] else None,
            "gpu_device_to_host_median_ms": stage_stats["device_to_host"]["median_ms"] if stage_stats["device_to_host"] else None,
            "gpu_digest_copy_median_ms": stage_stats["digest_copy"]["median_ms"] if stage_stats["digest_copy"] else None,
            "speedup_end_to_end": cpu_stats["median_ms"] / gpu_stats["median_ms"],
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
        "schema": "pulpo.gpu-performance-benchmark.v4",
        "metadata": metadata,
        "config": {
            "sizes": sizes,
            "samples": args.samples,
            "warmup": args.warmup,
            "implementation": args.implementation,
            "digest_representation": "concatenated raw SHA-256 bytes; hex conversion excluded from timed path",
            "prepared_measurement": "reuse canonical serialized messages; excludes JSON serialization on both CPU and GPU",
        },
        "results": rows,
        "governance": {
            "cpu_is_canonical": True,
            "gpu_role": "hash_recomputation_acceleration_only",
            "correctness_required_before_timing": True,
        },
    }
    payload["governance"]["production_kernel_integration"] = False
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"GPU: {metadata['gpu_name']}")
    print(f"Torch: {metadata['torch_version']} | backend: {metadata['gpu_backend']} | HIP: {metadata['torch_hip_version']}")
    print(f"{'records':>10} {'CPU e2e':>10} {'CPU prep':>10} {'GPU prep':>10} {'prep x':>8} {'canonical':>11} {'host prep':>11} {'H2D':>9} {'kernel':>9} {'D2H':>9} {'raw copy':>9} {'GPU total':>11} {'speedup':>9}")
    for row in rows:
        phase_values = [
            row["gpu_canonicalization_median_ms"],
            row["gpu_host_preparation_median_ms"],
            row["gpu_host_to_device_median_ms"],
            row["gpu_kernel_median_ms"],
            row["gpu_device_to_host_median_ms"],
            row["gpu_digest_copy_median_ms"],
        ]
        phase_text = [f"{value:9.3f}" if value is not None else f"{'n/a':>9}" for value in phase_values]
        print(
            f"{row['audit_records']:10d} "
            f"{row['cpu_median_ms']:10.3f} "
            f"{row['cpu_prepared_median_ms']:10.3f} "
            f"{row['gpu_prepared_median_ms']:10.3f} "
            f"{row['gpu_prepared_speedup']:7.2f}x "
            + " ".join(phase_text)
            + f" {row['gpu_end_to_end_median_ms']:11.3f} "
            + f"{row['speedup_end_to_end']:8.2f}x"
        )
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")
    return 0


def resolve_output_paths(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[Path, Path]:
    if args.json is None and args.csv is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        stem = f"pulpo-gpu-benchmark-{stamp}"
        json_path, csv_path = Path(stem + ".json"), Path(stem + ".csv")
    elif args.json is not None and args.csv is not None:
        json_path, csv_path = args.json, args.csv
    elif args.json is not None:
        json_path, csv_path = args.json, args.json.with_suffix(".csv")
    else:
        csv_path, json_path = args.csv, args.csv.with_suffix(".json")

    if json_path.resolve() == csv_path.resolve():
        parser.error("JSON and CSV output paths must be different")
    existing = [path for path in (json_path, csv_path) if path.exists()]
    if existing and not args.overwrite:
        parser.error(
            "output already exists: " + ", ".join(str(path) for path in existing)
            + "; choose new paths or pass --overwrite"
        )
    return json_path, csv_path


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Benchmark Pulpo audit verification across worker counts and audit sizes.

This is a measurement harness, not a governance component. It generates a
synthetic valid audit chain in memory and measures AuditVerificationEngine with
its digest cache disabled so worker/memory scaling is visible.

Example:
    python scripts/benchmark_memory_scaling.py --sizes 10000 50000 100000 --workers 1 2 4 8 --repeats 3 --json perf-results/memory-scaling.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import time
from hashlib import sha256
from pathlib import Path

from pulpo.audit_parallel import AuditVerificationEngine


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def build_rows(count: int):
    rows = []
    previous = "0" * 64
    for index in range(count):
        payload = {"index": index, "kind": "memory-scaling", "value": index % 257}
        payload_json = canonical(payload).decode()
        body = {
            "event": "benchmark",
            "payload": payload,
            "previous_hash": previous,
            "timestamp_ns": index + 1,
        }
        digest = sha256(canonical(body)).hexdigest()
        rows.append(("benchmark", payload_json, previous, index + 1, digest))
        previous = digest
    return rows


def memory_metadata():
    data = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    try:
        import psutil
        vm = psutil.virtual_memory()
        data["memory_bytes"] = vm.total
    except Exception:
        data["memory_bytes"] = None
    return data


def run_case(rows, workers: int, repeats: int, threshold: int):
    engine = AuditVerificationEngine(
        workers=workers,
        cache_size=0,
        parallel_threshold=threshold,
    )
    try:
        # Prime the engine. Its design intentionally keeps the first pass local.
        if not engine.verify_rows(rows):
            raise RuntimeError("generated audit chain failed verification")
        samples = []
        for _ in range(repeats):
            start = time.perf_counter()
            if not engine.verify_rows(rows):
                raise RuntimeError("audit verification failed")
            samples.append(time.perf_counter() - start)
    finally:
        engine.close()
    median = statistics.median(samples)
    return {
        "workers": workers,
        "records": len(rows),
        "median_seconds": median,
        "records_per_second": len(rows) / median,
        "samples_seconds": samples,
    }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10000, 50000, 100000, 250000])
    parser.add_argument("--workers", nargs="+", type=int, default=[1, 2, 4, 8])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--parallel-threshold", type=int, default=256)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--memory-label", default="", help="Optional label such as DDR4-3200-CL14-dual-channel")
    return parser.parse_args()


def main():
    args = parse_args()
    if any(size <= 0 for size in args.sizes):
        raise SystemExit("all sizes must be positive")
    if any(worker <= 0 for worker in args.workers):
        raise SystemExit("all worker counts must be positive")
    if args.repeats <= 0:
        raise SystemExit("repeats must be positive")

    output = {
        "schema": "pulpo.memory-scaling-benchmark.v1",
        "machine": memory_metadata(),
        "memory_label": args.memory_label,
        "parallel_threshold": args.parallel_threshold,
        "results": [],
    }

    print("records  workers  median_ms  records/sec")
    print("-------  -------  ---------  -----------")
    for size in args.sizes:
        rows = build_rows(size)
        for workers in args.workers:
            result = run_case(rows, workers, args.repeats, args.parallel_threshold)
            output["results"].append(result)
            print(
                f'{size:7d}  {workers:7d}  '
                f'{result["median_seconds"] * 1000:9.2f}  '
                f'{result["records_per_second"]:11.0f}'
            )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {args.json}")


if __name__ == "__main__":
    main()

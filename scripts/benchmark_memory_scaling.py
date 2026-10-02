#!/usr/bin/env python3
"""Benchmark Pulpo audit verification across workers, sizes, and IPC batch sizes."""

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
        data["memory_bytes"] = psutil.virtual_memory().total
    except Exception:
        data["memory_bytes"] = None
    return data


def run_case(rows, workers: int, repeats: int, threshold: int, batch_size: int):
    engine = AuditVerificationEngine(
        workers=workers,
        cache_size=0,
        parallel_threshold=threshold,
        batch_size=batch_size,
    )
    try:
        # First pass primes engine locally by design.
        if not engine.verify_rows(rows):
            raise RuntimeError("generated audit chain failed verification")
        # For multiprocessing cases, run one unmeasured pass to create/warm workers.
        if workers > 1 and len(rows) >= threshold:
            if not engine.verify_rows(rows):
                raise RuntimeError("worker warm-up verification failed")
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
        "batch_size": batch_size,
        "records": len(rows),
        "median_seconds": median,
        "records_per_second": len(rows) / median,
        "samples_seconds": samples,
    }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10000, 50000, 100000, 250000])
    parser.add_argument("--workers", nargs="+", type=int, default=[1, 2, 4, 8])
    parser.add_argument("--batch-sizes", nargs="+", type=int, default=[4096])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--parallel-threshold", type=int, default=256)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--memory-label", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    if any(size <= 0 for size in args.sizes):
        raise SystemExit("all sizes must be positive")
    if any(worker <= 0 for worker in args.workers):
        raise SystemExit("all worker counts must be positive")
    if any(batch <= 0 for batch in args.batch_sizes):
        raise SystemExit("all batch sizes must be positive")
    if args.repeats <= 0:
        raise SystemExit("repeats must be positive")

    output = {
        "schema": "pulpo.memory-scaling-benchmark.v2",
        "machine": memory_metadata(),
        "memory_label": args.memory_label,
        "parallel_threshold": args.parallel_threshold,
        "results": [],
    }

    print("records  workers  batch_size  median_ms  records/sec")
    print("-------  -------  ----------  ---------  -----------")
    for size in args.sizes:
        rows = build_rows(size)
        for workers in args.workers:
            batches = [args.batch_sizes[0]] if workers == 1 else args.batch_sizes
            for batch_size in batches:
                result = run_case(rows, workers, args.repeats, args.parallel_threshold, batch_size)
                output["results"].append(result)
                print(
                    f'{size:7d}  {workers:7d}  {batch_size:10d}  '
                    f'{result["median_seconds"] * 1000:9.2f}  '
                    f'{result["records_per_second"]:11.0f}'
                )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {args.json}")


if __name__ == "__main__":
    main()

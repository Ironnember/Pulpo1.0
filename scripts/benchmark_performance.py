#!/usr/bin/env python3
"""Reproducible Pulpo performance benchmark.

This harness measures governance-path overhead without changing authority,
durability, replay, revocation, or evidence semantics. It uses only the Python
standard library so the same benchmark can be copied across revisions.
"""

from __future__ import annotations

import argparse
import csv
import gc
import json
import math
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState


SECRET = b"pulpo-performance-benchmark-secret"
NOW_NS = 1_000_000_000


def git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("values required")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def measure(
    operation: Callable[[], Any],
    *,
    warmup: int,
    samples: int,
) -> list[float]:
    for _ in range(warmup):
        operation()
    timings_ms: list[float] = []
    gc.collect()
    was_enabled = gc.isenabled()
    if was_enabled:
        gc.disable()
    try:
        for _ in range(samples):
            start = time.perf_counter_ns()
            operation()
            elapsed = time.perf_counter_ns() - start
            timings_ms.append(elapsed / 1_000_000)
    finally:
        if was_enabled:
            gc.enable()
    return timings_ms


def metric(
    name: str,
    audit_records: int,
    values: list[float],
    *,
    unit: str = "ms",
    lower_is_better: bool = True,
) -> dict[str, Any]:
    return {
        "benchmark": name,
        "audit_records": audit_records,
        "unit": unit,
        "lower_is_better": lower_is_better,
        "samples": len(values),
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def seed_audit(state: SQLiteKernelState, count: int) -> None:
    for index in range(count):
        state.append(
            "benchmark_seed",
            {
                "sequence_hint": index,
                "authority_effect": "none",
                "benchmark": True,
            },
            NOW_NS + index,
        )


def new_policy() -> Policy:
    return Policy(frozenset({"read"}), 100)


def new_kernel(state: SQLiteKernelState) -> GovernanceKernel:
    return GovernanceKernel(
        new_policy(),
        secret=SECRET,
        clock=lambda: NOW_NS + 10_000_000,
        state=state,
    )


def database_metadata(state: SQLiteKernelState) -> dict[str, Any]:
    connection = state._connection
    return {
        "sqlite_version": sqlite3.sqlite_version,
        "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
        "synchronous": connection.execute("PRAGMA synchronous").fetchone()[0],
        "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
    }


def benchmark_size(
    audit_records: int,
    *,
    warmup: int,
    samples: int,
    append_batch: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="pulpo-benchmark-") as directory:
        path = Path(directory) / "kernel.sqlite3"
        state = SQLiteKernelState(path)
        seed_audit(state, audit_records)
        storage = database_metadata(state)
        state.close()

        startup_values = measure(
            lambda: startup_once(path),
            warmup=warmup,
            samples=samples,
        )
        results.append(metric("startup_full_audit_verify", audit_records, startup_values))

        state = SQLiteKernelState(path)
        kernel = new_kernel(state)

        stream_values = measure(
            lambda: sum(1 for _ in state.iter_audit()),
            warmup=warmup,
            samples=samples,
        )
        results.append(metric("audit_stream_iterate", audit_records, stream_values))

        materialize_values = measure(
            lambda: len(state.audit),
            warmup=warmup,
            samples=samples,
        )
        results.append(metric("audit_materialize", audit_records, materialize_values))

        counter = 0

        def issue_once() -> None:
            nonlocal counter
            counter += 1
            decision = kernel.evaluate(
                Intent("benchmark-agent", "read", f"repo:benchmark:{counter}")
            )
            if decision.outcome != "allow" or decision.permit is None:
                raise RuntimeError("benchmark permit issue failed")

        issue_values = measure(issue_once, warmup=warmup, samples=samples)
        results.append(metric("evaluate_and_issue_permit", audit_records, issue_values))

        consume_counter = 0

        def consume_once() -> None:
            nonlocal consume_counter
            consume_counter += 1
            intent = Intent(
                "benchmark-agent",
                "read",
                f"repo:consume:{consume_counter}",
            )
            decision = kernel.evaluate(intent)
            if decision.permit is None:
                raise RuntimeError("benchmark permit unavailable")
            if not kernel.consume(decision.permit, intent):
                raise RuntimeError("benchmark permit consume failed")

        consume_values = measure(consume_once, warmup=warmup, samples=samples)
        results.append(metric("permit_issue_plus_consume", audit_records, consume_values))

        identity_payload = {
            "transition_hash": f"benchmark-{audit_records}",
            "authority_effect": "none",
        }
        state.append_unique(
            "benchmark_unique",
            "transition_hash",
            identity_payload["transition_hash"],
            identity_payload,
            NOW_NS,
        )

        unique_values = measure(
            lambda: state.append_unique(
                "benchmark_unique",
                "transition_hash",
                identity_payload["transition_hash"],
                identity_payload,
                NOW_NS + 1,
            ),
            warmup=warmup,
            samples=samples,
        )
        results.append(metric("append_unique_existing_lookup", audit_records, unique_values))

        target_id = f"benchmark-target-{audit_records}"
        target_intent = Intent("benchmark-agent", "read", "repo:locked-target")
        target = kernel.lock_target(target_id, target_intent)
        for index in range(max(1, audit_records // 10)):
            state.append(
                "benchmark_after_target",
                {"index": index, "authority_effect": "none"},
                NOW_NS + 20_000_000 + index,
            )

        target_values = measure(
            lambda: kernel.get_locked_target(target_id),
            warmup=warmup,
            samples=samples,
        )
        if kernel.get_locked_target(target_id) != target:
            raise RuntimeError("locked target benchmark lookup mismatch")
        results.append(metric("locked_target_lookup", audit_records, target_values))

        def append_batch_once() -> None:
            base = time.perf_counter_ns()
            for offset in range(append_batch):
                state.append(
                    "benchmark_write",
                    {
                        "offset": offset,
                        "batch_nonce": base,
                        "authority_effect": "none",
                    },
                    NOW_NS + 30_000_000 + offset,
                )

        batch_ms = measure(append_batch_once, warmup=warmup, samples=samples)
        throughput = [(append_batch * 1000.0) / elapsed for elapsed in batch_ms]
        results.append(
            metric(
                "sqlite_audit_write_throughput",
                audit_records,
                throughput,
                unit="ops/sec",
                lower_is_better=False,
            )
        )

        state.close()
        storage["database_bytes"] = path.stat().st_size if path.exists() else None

    return results, storage


def startup_once(path: Path) -> None:
    state = SQLiteKernelState(path)
    try:
        kernel = new_kernel(state)
        if not kernel.verify_audit():
            raise RuntimeError("audit verification failed")
    finally:
        state.close()


def peak_rss_bytes() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(value)
    return int(value * 1024)


def parse_sizes(raw: str) -> list[int]:
    sizes = [int(item.strip()) for item in raw.split(",") if item.strip()]
    if not sizes or any(size < 0 for size in sizes):
        raise argparse.ArgumentTypeError("sizes must be comma-separated non-negative integers")
    return sizes


def write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    fieldnames = [
        "benchmark",
        "audit_records",
        "unit",
        "lower_is_better",
        "samples",
        "median",
        "p95",
        "min",
        "max",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_summary(payload: dict[str, Any]) -> None:
    print(f"Pulpo performance benchmark @ {payload['metadata']['commit_sha']}")
    print(
        f"Python {payload['metadata']['python_version']} | "
        f"{payload['metadata']['platform']} | "
        f"{payload['metadata']['machine']}"
    )
    print()
    print(
        f"{'benchmark':34} {'records':>8} {'median':>12} {'p95':>12} {'unit':>8}"
    )
    print("-" * 80)
    for row in payload["results"]:
        print(
            f"{row['benchmark'][:34]:34} "
            f"{row['audit_records']:8d} "
            f"{row['median']:12.3f} "
            f"{row['p95']:12.3f} "
            f"{row['unit']:>8}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sizes",
        default="1000,10000,100000",
        help="comma-separated audit sizes (default: 1000,10000,100000)",
    )
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--append-batch", type=int, default=25)
    parser.add_argument("--json", type=Path, default=Path("pulpo-benchmark.json"))
    parser.add_argument("--csv", type=Path, default=Path("pulpo-benchmark.csv"))
    args = parser.parse_args()

    sizes = parse_sizes(args.sizes)
    if args.samples <= 0 or args.warmup < 0 or args.append_batch <= 0:
        parser.error("samples and append-batch must be positive; warmup must be non-negative")

    all_results: list[dict[str, Any]] = []
    storage_by_size: dict[str, Any] = {}
    started = time.time()

    for size in sizes:
        results, storage = benchmark_size(
            size,
            warmup=args.warmup,
            samples=args.samples,
            append_batch=args.append_batch,
        )
        all_results.extend(results)
        storage_by_size[str(size)] = storage

    payload = {
        "schema": "pulpo.performance-benchmark.v1",
        "metadata": {
            "commit_sha": git_sha(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "peak_rss_bytes": peak_rss_bytes(),
            "started_at_unix": started,
            "duration_seconds": time.time() - started,
        },
        "config": {
            "sizes": sizes,
            "samples": args.samples,
            "warmup": args.warmup,
            "append_batch": args.append_batch,
        },
        "storage": storage_by_size,
        "results": all_results,
    }

    args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_csv(args.csv, all_results)
    print_summary(payload)
    print()
    print(f"JSON: {args.json}")
    print(f"CSV:  {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

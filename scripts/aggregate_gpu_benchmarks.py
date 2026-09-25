#!/usr/bin/env python3
"""Aggregate independent Pulpo GPU benchmark runs without pooling samples."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path
from typing import Any


def aggregate_payloads(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    if not payloads:
        raise ValueError("provide at least one benchmark JSON file")
    for payload in payloads:
        if payload.get("schema") != "pulpo.gpu-performance-benchmark.v2":
            raise ValueError("all inputs must use pulpo.gpu-performance-benchmark.v2")

    metadata_keys = ("gpu_name", "gpu_backend", "gpu_implementation", "torch_version", "torch_hip_version")
    first = payloads[0]["metadata"]
    for payload in payloads[1:]:
        for key in metadata_keys:
            if payload["metadata"].get(key) != first.get(key):
                raise ValueError(f"benchmark inputs differ in metadata field {key!r}")

    grouped: dict[int, list[dict[str, Any]]] = {}
    for payload in payloads:
        for row in payload.get("results", []):
            grouped.setdefault(int(row["audit_records"]), []).append(row)

    results = []
    for size, rows in sorted(grouped.items()):
        cpu = [float(row["cpu_median_ms"]) for row in rows]
        gpu = [float(row["gpu_end_to_end_median_ms"]) for row in rows]
        ratios = [float(row["speedup_end_to_end"]) for row in rows]
        results.append({
            "audit_records": size,
            "run_count": len(rows),
            "cpu_median_of_run_medians_ms": statistics.median(cpu),
            "cpu_min_run_median_ms": min(cpu),
            "cpu_max_run_median_ms": max(cpu),
            "gpu_median_of_run_medians_ms": statistics.median(gpu),
            "gpu_min_run_median_ms": min(gpu),
            "gpu_max_run_median_ms": max(gpu),
            "speedup_median_of_runs": statistics.median(ratios),
            "speedup_min_run": min(ratios),
            "speedup_max_run": max(ratios),
        })
    if not results:
        raise ValueError("benchmark inputs contain no result rows")
    return {
        "schema": "pulpo.gpu-benchmark-aggregate.v1",
        "metadata": {key: first.get(key) for key in metadata_keys},
        "source_runs": [payload.get("metadata", {}).get("commit_sha") for payload in payloads],
        "results": results,
        "method": "median and range of per-run medians; raw samples are not pooled",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="independent benchmark JSON outputs")
    parser.add_argument("--json", type=Path, default=Path("pulpo-gpu-aggregate.json"))
    parser.add_argument("--csv", type=Path, default=Path("pulpo-gpu-aggregate.csv"))
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if args.json.resolve() == args.csv.resolve():
        parser.error("JSON and CSV output paths must be different")
    existing = [path for path in (args.json, args.csv) if path.exists()]
    if existing and not args.overwrite:
        parser.error(
            "output already exists: " + ", ".join(str(path) for path in existing)
            + "; choose new paths or pass --overwrite"
        )
    try:
        payloads = [json.loads(path.read_text(encoding="utf-8")) for path in args.inputs]
        result = aggregate_payloads(payloads)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with args.csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=result["results"][0].keys())
        writer.writeheader()
        writer.writerows(result["results"])
    for row in result["results"]:
        print(
            f"{row['audit_records']:>10} records | n={row['run_count']} | "
            f"CPU {row['cpu_median_of_run_medians_ms']:.3f} ms | "
            f"GPU {row['gpu_median_of_run_medians_ms']:.3f} ms | "
            f"{row['speedup_median_of_runs']:.2f}x "
            f"(range {row['speedup_min_run']:.2f}–{row['speedup_max_run']:.2f}x)"
        )
    print(f"JSON: {args.json}\nCSV:  {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

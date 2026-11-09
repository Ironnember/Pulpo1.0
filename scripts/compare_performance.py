#!/usr/bin/env python3
"""Compare two Pulpo performance benchmark JSON files."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "pulpo.performance-benchmark.v1":
        raise SystemExit(f"{path}: unsupported benchmark schema")
    return payload


def key(row: dict[str, Any]) -> tuple[str, int]:
    return str(row["benchmark"]), int(row["audit_records"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--csv", type=Path, default=Path("pulpo-benchmark-comparison.csv"))
    args = parser.parse_args()

    before = load(args.before)
    after = load(args.after)
    before_rows = {key(row): row for row in before["results"]}
    after_rows = {key(row): row for row in after["results"]}
    shared = sorted(set(before_rows).intersection(after_rows), key=lambda item: (item[1], item[0]))

    rows: list[dict[str, Any]] = []
    for item in shared:
        old = before_rows[item]
        new = after_rows[item]
        if old["unit"] != new["unit"]:
            continue
        old_median = float(old["median"])
        new_median = float(new["median"])
        if old_median == 0:
            change_pct = None
            improvement_pct = None
        else:
            change_pct = ((new_median - old_median) / old_median) * 100.0
            lower_is_better = bool(old.get("lower_is_better", True))
            improvement_pct = -change_pct if lower_is_better else change_pct

        rows.append(
            {
                "benchmark": item[0],
                "audit_records": item[1],
                "unit": old["unit"],
                "before_median": old_median,
                "after_median": new_median,
                "change_pct": change_pct,
                "improvement_pct": improvement_pct,
            }
        )

    print(
        f"Before: {before['metadata'].get('commit_sha', 'unknown')}\n"
        f"After:  {after['metadata'].get('commit_sha', 'unknown')}\n"
    )
    print(
        f"{'benchmark':34} {'records':>8} {'before':>11} {'after':>11} "
        f"{'improve':>10} {'unit':>8}"
    )
    print("-" * 100)
    for row in rows:
        improve = (
            "n/a"
            if row["improvement_pct"] is None
            else f"{row['improvement_pct']:+.1f}%"
        )
        print(
            f"{row['benchmark'][:34]:34} "
            f"{row['audit_records']:8d} "
            f"{row['before_median']:11.3f} "
            f"{row['after_median']:11.3f} "
            f"{improve:>10} "
            f"{row['unit']:>8}"
        )

    fieldnames = [
        "benchmark",
        "audit_records",
        "unit",
        "before_median",
        "after_median",
        "change_pct",
        "improvement_pct",
    ]
    with args.csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

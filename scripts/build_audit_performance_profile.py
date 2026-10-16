#!/usr/bin/env python3
"""Build a bounded Pulpo audit performance profile from benchmark JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pulpo.performance_tuning import AuditPerformanceTuner


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-improvement", type=float, default=0.05)
    parser.add_argument(
        "--allow-machine-mismatch",
        action="store_true",
        help="Allow profile generation from a benchmark captured on another machine.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    document = json.loads(args.benchmark.read_text(encoding="utf-8"))
    tuner = AuditPerformanceTuner.from_benchmark_document(
        document,
        min_improvement=args.min_improvement,
        require_machine_match=not args.allow_machine_mismatch,
    )
    tuner.save(args.output)
    print(f"Wrote {args.output}")
    for profile in tuner.profiles:
        print(
            f"<= {profile.max_records:7d} records: "
            f"workers={profile.workers} batch={profile.batch_size} "
            f"threshold={profile.parallel_threshold} source={profile.source}"
        )


if __name__ == "__main__":
    main()

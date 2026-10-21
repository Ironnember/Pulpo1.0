"""Pulpo command-line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .setup import run_setup


def _setup_command(args: argparse.Namespace) -> int:
    report = run_setup(
        profile_path=args.profile,
        benchmark_path=args.benchmark,
        calibrate_if_needed=not args.no_calibrate,
        calibration_sizes=tuple(args.calibration_sizes),
        calibration_batches=tuple(args.batch_sizes),
        calibration_repeats=args.repeats,
    )

    if args.json_report:
        destination = Path(args.json_report)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = report["environment"]
    profile = report["profile"]
    verification = report["audit_verification"]

    print("PULPO SETUP")
    print()
    print(f'Environment .............. {env["status"]}')
    print(f'Performance profile ...... {profile["status"]}')
    print(f'Audit verification ....... {verification["status"]}')
    print("Authority changes ........ NONE")
    print()
    fingerprint = env["fingerprint"]
    print(f'Platform ................. {fingerprint["platform"]}')
    print(f'Python ................... {fingerprint["python"]}')
    print(f'Logical CPUs ............. {fingerprint["cpu_count"]}')
    print()
    for item in profile["profiles"]:
        print(
            f'<= {item["max_records"]:7d} records  '
            f'workers={item["workers"]}  batch={item["batch_size"]}  '
            f'source={item["source"]}'
        )
    print()
    if report["ready_for_test_use"]:
        print("PULPO READY FOR TEST USE")
        print("This setup report does not claim production readiness.")
        return 0
    print("PULPO SETUP FAILED")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pulpo")
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup = subparsers.add_parser(
        "setup",
        help="detect the machine, resolve a bounded performance profile, and self-test audit verification",
    )
    setup.add_argument(
        "--profile",
        default=".pulpo/audit-performance-profile.json",
        help="machine-bound performance profile path",
    )
    setup.add_argument("--benchmark", help="existing v2 memory-scaling benchmark JSON")
    setup.add_argument(
        "--no-calibrate",
        action="store_true",
        help="use conservative fallback instead of calibrating when no valid profile is available",
    )
    setup.add_argument(
        "--calibration-sizes",
        nargs="+",
        type=int,
        default=[10000, 50000, 100000],
    )
    setup.add_argument(
        "--batch-sizes",
        nargs="+",
        type=int,
        default=[256, 1024, 4096],
    )
    setup.add_argument("--repeats", type=int, default=1)
    setup.add_argument("--json-report", help="optional setup report JSON path")
    setup.set_defaults(func=_setup_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

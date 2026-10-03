#!/usr/bin/env python3
"""Deployment-time Pulpo inbound-listener proof."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from pulpo.network_exposure import (
    NetworkExposureError,
    audit_network_exposure,
    parse_allowlist,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if the host has any listener not explicitly allowlisted."
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="PROTO:ADDRESS:PORT",
        help="Exact allowed listener. Repeat as needed. Default: none.",
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        help="Optional path for machine-readable JSON evidence.",
    )
    args = parser.parse_args(argv)

    try:
        report = audit_network_exposure(allowed=parse_allowlist(args.allow))
    except NetworkExposureError as exc:
        print(f"pulpo_network_exposure_error:{exc}", file=sys.stderr)
        return 2

    payload = report.to_json()
    print(payload)
    if args.evidence is not None:
        args.evidence.write_text(payload + "\n", encoding="utf-8")

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

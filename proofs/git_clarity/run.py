#!/usr/bin/env python3
"""Run PulpoGit clarity against this checkout."""

from __future__ import annotations

from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pulpo.git_clarity import main


if __name__ == "__main__":
    raise SystemExit(
        main(
            [
                "--repo",
                str(REPOSITORY_ROOT),
                "--expected-repository",
                "github.com/Ironnember/Pulpo1.0",
                *sys.argv[1:],
            ]
        )
    )

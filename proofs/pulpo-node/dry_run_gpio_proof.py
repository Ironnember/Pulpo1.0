#!/usr/bin/env python3
"""Run the Phase 2 dry-run contract suite and emit machine-readable evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.test_pulpo_node_dry_run_gpio import DryRunGPIOContractTests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    before = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT, text=True)
    result = {
        "schema": "pulpo.node-gpio-dry-run-proof.v1",
        "classification": "Recorded",
        "expected_revision": args.expected_revision,
        "actual_revision": revision,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "initial_status_short": before,
        "boundary": "Synthetic dry-run contract only. No GPIO writes, hardware backend, production credentials, services, or network configuration changes. Same-process test authority and observation; physical custody Unknown.",
    }
    if revision != args.expected_revision or before:
        result.update(result="FAIL", reason="revision_mismatch_or_dirty_source")
    else:
        log = io.StringIO()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(DryRunGPIOContractTests)
        run = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        after = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT, text=True)
        result.update(
            result="PASS_WITH_BOUNDARIES" if run.wasSuccessful() and not after and not run.skipped else "FAIL",
            tests_run=run.testsRun, failures=len(run.failures), errors=len(run.errors),
            skipped=len(run.skipped), test_log=log.getvalue(), final_status_short=after,
        )
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, sort_keys=True, indent=2)
    args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result["result"] == "PASS_WITH_BOUNDARIES" else 1


if __name__ == "__main__":
    raise SystemExit(main())

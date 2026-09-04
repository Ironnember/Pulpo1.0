#!/usr/bin/env python3
"""DAG-aware refinement of the frozen Time Machine differential experiment."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = ROOT / "scripts" / "run_time_machine_differential.py"
spec = importlib.util.spec_from_file_location("pulpo_time_machine_v1", BASE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load Time Machine v1 runner")
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)

CURRENT = "2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8"

CASES = (
    base.Case("T1_directive_authority_seam", "4ee6af94ea8c55d2393351ffcb17f3dcdc792d08", False, "directive_seam", "capability_emergence"),
    base.Case("T1_directive_authority_seam", "81338eed28ec32fe214c7eee086a82840ca0923f", True, "directive_seam", "capability_emergence"),
    base.Case("T2_execution_time_revocation", "81338eed28ec32fe214c7eee086a82840ca0923f", False, "directive_revocation", "branch_vs_canonical"),
    base.Case("T2_execution_time_revocation", "da39afed5c45b0c3b7d3b9c372542fe1962645ce", False, "directive_revocation", "branch_vs_canonical"),
    base.Case("T2_execution_time_revocation", "b9d375dcaf962745241ca45d0a601cf3a7a74bf1", True, "directive_revocation", "branch_local_fix"),
    base.Case("T2_execution_time_revocation", "fc941266a608d7b654cc647532ac965f81582535", False, "directive_revocation", "canonical_before_fix_admission"),
    base.Case("T2_execution_time_revocation", "ec91f6f51a115f0fda6e163b9012518c97b322a0", True, "directive_revocation", "canonical_after_fix_admission"),
    base.Case("T2_execution_time_revocation", CURRENT, True, "directive_revocation", "persistence"),
    base.Case("T3_target_mismatch_precedes_authority", "1d63f6285b3d734178193446c26a2c1de7ee1e44", False, "target_mismatch", "capability_emergence"),
    base.Case("T3_target_mismatch_precedes_authority", "fc941266a608d7b654cc647532ac965f81582535", True, "target_mismatch", "capability_emergence"),
    base.Case("T3_target_mismatch_precedes_authority", "ec91f6f51a115f0fda6e163b9012518c97b322a0", True, "target_mismatch", "convergence"),
    base.Case("T3_target_mismatch_precedes_authority", CURRENT, True, "target_mismatch", "persistence"),
    base.Case("T4_kernel_owned_directive_sources", "fc941266a608d7b654cc647532ac965f81582535", False, "parallel_directive_sources", "hardening"),
    base.Case("T4_kernel_owned_directive_sources", "1209b7a3666e928e6a0bcfcb34be0334666a6718", True, "parallel_directive_sources", "hardening"),
    base.Case("T4_kernel_owned_directive_sources", CURRENT, True, "parallel_directive_sources", "persistence"),
)

ANCESTRY = (
    ("1d63f6285b3d734178193446c26a2c1de7ee1e44", "fc941266a608d7b654cc647532ac965f81582535"),
    ("fc941266a608d7b654cc647532ac965f81582535", "ec91f6f51a115f0fda6e163b9012518c97b322a0"),
    ("b9d375dcaf962745241ca45d0a601cf3a7a74bf1", "ec91f6f51a115f0fda6e163b9012518c97b322a0"),
    ("ec91f6f51a115f0fda6e163b9012518c97b322a0", CURRENT),
)


def ancestry_case(ancestor: str, descendant: str) -> dict[str, object]:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    holds = completed.returncode == 0
    return {
        "ancestor": ancestor,
        "descendant": descendant,
        "expected_is_ancestor": True,
        "observed_is_ancestor": holds,
        "matches_expected": holds,
        "returncode": completed.returncode,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="pulpo-time-machine-v1-1-") as tmp:
        behavior = [base.execute_case(ROOT, case, Path(tmp)) for case in CASES]

    ancestry = [ancestry_case(a, d) for a, d in ANCESTRY]
    behavior_matched = sum(bool(row["matches_expected"]) for row in behavior)
    ancestry_matched = sum(bool(row["matches_expected"]) for row in ancestry)
    passed = behavior_matched == len(behavior) and ancestry_matched == len(ancestry)

    transitions: dict[str, dict[str, int]] = {}
    for row in behavior:
        entry = transitions.setdefault(str(row["transition"]), {"cases": 0, "matched": 0})
        entry["cases"] += 1
        entry["matched"] += int(bool(row["matches_expected"]))

    report = {
        "schema": "pulpo.time-machine-differential.v1.1",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "current_canonical_sha": CURRENT,
        "behavior_cases_total": len(behavior),
        "behavior_cases_matching_expected": behavior_matched,
        "ancestry_cases_total": len(ancestry),
        "ancestry_cases_matching_expected": ancestry_matched,
        "unexpected_total": (len(behavior) - behavior_matched) + (len(ancestry) - ancestry_matched),
        "result": "pass" if passed else "fail",
        "transitions": transitions,
        "behavior_cases": behavior,
        "ancestry_cases": ancestry,
    }
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Gladiator Ultra candidate runner.

Candidate-only until this runner and its contract are admitted to canonical main.
Runs bounded, side-effect-limited proof modules from a pinned repository revision.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def run(cmd: list[str], cwd: Path) -> dict:
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {"cmd": cmd, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    status = subprocess.check_output(["git", "status", "--short"], cwd=repo, text=True)
    result = {
        "runner": "gladiator-ultra-candidate",
        "claim_boundary": "Candidate local runner only until admitted to canonical main. No GPIO, credentials, network changes, external provider writes, or physical authority.",
        "started_at": datetime.now(UTC).isoformat(),
        "repo": str(repo),
        "expected_revision": args.expected_revision,
        "actual_revision": actual,
        "revision_match": actual == args.expected_revision,
        "initial_status_short": status,
        "phases": [],
    }

    if actual != args.expected_revision:
        result["overall"] = "FAIL"
        result["reason"] = "expected revision mismatch"
        (out / "gladiator-ultra-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 2
    if status.strip():
        result["overall"] = "FAIL"
        result["reason"] = "source tree not clean before run"
        (out / "gladiator-ultra-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 3

    proof_path = repo / "proofs" / "pulpo-node" / "virtual_lamp_proof.py"
    proof = load_module(proof_path, "pulpo_node_virtual_lamp_ultra")
    with tempfile.TemporaryDirectory(prefix="gladiator-ultra-node-") as td:
        node_result = proof.run_checks(Path(td))
    result["phases"].append({"name": "pulpo_node_virtual_lamp_direct", "result": node_result})

    script_output = out / "pulpo-node-virtual-lamp-result.json"
    script_run = run([sys.executable, str(proof_path), "--output", str(script_output)], cwd=repo)
    result["phases"].append({"name": "pulpo_node_virtual_lamp_script", "result": script_run})

    test_run = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_pulpo_node_virtual_lamp.py", "-v"], cwd=repo)
    result["phases"].append({"name": "unittest_virtual_lamp", "result": test_run})

    final_status = subprocess.check_output(["git", "status", "--short"], cwd=repo, text=True)
    result["final_status_short"] = final_status
    failures = []
    if node_result.get("result") != "PASS" or node_result.get("checks_passed") != 13 or node_result.get("event_count") != 1:
        failures.append("direct node proof failed")
    if script_run["returncode"] != 0:
        failures.append("script proof failed")
    if test_run["returncode"] != 0:
        failures.append("unittest failed")
    if final_status.strip():
        failures.append("source tree changed during tournament")
    result["failures"] = failures
    result["overall"] = "PASS_WITH_BOUNDARIES" if not failures else "FAIL"
    result["completed_at"] = datetime.now(UTC).isoformat()
    (out / "gladiator-ultra-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
B_FREEZE_PATH = ROOT / "experiments/cross-model-pulpo-lift-b/freeze.json"
B_FREEZE_COMMIT = "07f25a9af6aa82f1677304a3c3129c0681679a66"
A_RUNNER_PATH = ROOT / "experiments/cross-model-pulpo-lift/run.py"
RESULTS_PATH = ROOT / "experiments/cross-model-pulpo-lift-b/results.json"
SUMMARY_PATH = ROOT / "experiments/cross-model-pulpo-lift-b/SUMMARY.md"

spec = importlib.util.spec_from_file_location("cross_model_pulpo_lift_a", A_RUNNER_PATH)
assert spec is not None and spec.loader is not None
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def load_generation_b() -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    b_raw = B_FREEZE_PATH.read_bytes()
    b_frozen = _git(
        "show", f"{B_FREEZE_COMMIT}:experiments/cross-model-pulpo-lift-b/freeze.json"
    ).encode()
    if b_raw != b_frozen:
        raise RuntimeError("Generation B freeze changed after its freeze commit")

    b = json.loads(b_raw)
    a, a_raw = parent.load_freeze()
    recorded = b["parent_experiment"]
    if recorded["freeze_commit"] != parent.FREEZE_COMMIT:
        raise RuntimeError("Generation B parent freeze commit mismatch")
    if recorded["freeze_sha256"] != _sha(a_raw):
        raise RuntimeError("Generation B parent freeze hash mismatch")
    if int(a["execution_contract"]["max_ai_credits_per_call"]) != 5:
        raise RuntimeError("Generation A no longer has the frozen 5-credit ceiling")
    if b["single_allowed_change"] != {
        "field": "execution_contract.max_ai_credits_per_call",
        "from": 5,
        "to": 30,
        "reason": "provider execution surface enforces a hard minimum of 30 AI credits before inference",
    }:
        raise RuntimeError("Generation B contains an unauthorized delta")
    return b, b_raw, a, a_raw


def corrected_freeze(a: dict[str, Any]) -> dict[str, Any]:
    value = deepcopy(a)
    value["execution_contract"]["max_ai_credits_per_call"] = 30
    return value


def _block_classification(run: dict[str, Any]) -> str:
    if run.get("status") == "EXECUTED":
        return "EXECUTED"
    errors = " ".join(
        str(item.get("stderr_tail", "")) for item in run.get("attempts", [])
    ).lower()
    model_markers = (
        "model is not available",
        "model not available",
        "unknown model",
        "invalid model",
        "unsupported model",
        "model access",
    )
    if any(marker in errors for marker in model_markers):
        return "BLOCKED_MODEL_UNAVAILABLE"
    return "BLOCKED_EXECUTION_SURFACE"


def run() -> dict[str, Any]:
    b, b_raw, a, a_raw = load_generation_b()
    freeze = corrected_freeze(a)

    runs: list[dict[str, Any]] = []
    for model in freeze["models"]:
        family = str(model["family"])
        candidates = [str(item) for item in model["preferred"]]
        for condition in freeze["conditions"]:
            result = parent.run_one(freeze, family, candidates, str(condition))
            if result.get("status") != "EXECUTED":
                result["status"] = _block_classification(result)
            runs.append(result)

    result: dict[str, Any] = {
        "schema": "pulpo.cross-model-lift-b.result.v1",
        "generation_b_freeze_commit": B_FREEZE_COMMIT,
        "generation_b_freeze_sha256": _sha(b_raw),
        "parent_freeze_commit": parent.FREEZE_COMMIT,
        "parent_freeze_sha256": _sha(a_raw),
        "single_allowed_change": b["single_allowed_change"],
        "runs": runs,
    }
    result["summary"] = parent.summarize(freeze, runs)
    RESULTS_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    SUMMARY_PATH.write_text(parent.markdown_summary({
        "freeze_commit": B_FREEZE_COMMIT,
        "freeze_sha256": _sha(b_raw),
        "summary": result["summary"],
    }))
    print(SUMMARY_PATH.read_text())
    print("RESULT_JSON=" + json.dumps(result["summary"], sort_keys=True))
    return result


if __name__ == "__main__":
    run()

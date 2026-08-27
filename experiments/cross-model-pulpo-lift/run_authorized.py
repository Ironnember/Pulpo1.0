from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = ROOT / "experiments/cross-model-pulpo-lift"
FREEZE_PATH = EXPERIMENT / "freeze.json"
AUTH_PATH = EXPERIMENT / "execution_authorization.json"
BASE_RUNNER = EXPERIMENT / "run.py"
RESULTS_PATH = EXPERIMENT / "results_authorized.json"
SUMMARY_PATH = EXPERIMENT / "SUMMARY_AUTHORIZED.md"
FREEZE_COMMIT = "a1775e3ea41b14fa57551a4d72a0e4a876a689ab"
EXPECTED_FREEZE_SHA256 = "06a27c6426a95fef49b6ba802acdfda31d466b8b1e1cce673cc955f0bb78354c"
PARENT_FAILURE_HEAD = "c083f394fd4a60b31c9caa8e919d7c53134ed2e9"

spec = importlib.util.spec_from_file_location("cross_model_base", BASE_RUNNER)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def load_authorized_contract() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    freeze_raw = FREEZE_PATH.read_bytes()
    frozen = subprocess.run(
        ["git", "show", f"{FREEZE_COMMIT}:experiments/cross-model-pulpo-lift/freeze.json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    if freeze_raw != frozen:
        raise RuntimeError("frozen benchmark changed after freeze commit")
    if _sha(freeze_raw) != EXPECTED_FREEZE_SHA256:
        raise RuntimeError("frozen benchmark hash mismatch")

    freeze = json.loads(freeze_raw)
    auth = json.loads(AUTH_PATH.read_text())
    scope = auth["scope"]

    if auth["freeze_commit"] != FREEZE_COMMIT:
        raise RuntimeError("authorization is bound to a different freeze commit")
    if auth["freeze_sha256"] != EXPECTED_FREEZE_SHA256:
        raise RuntimeError("authorization is bound to a different freeze hash")
    if auth["parent_failure_head"] != PARENT_FAILURE_HEAD:
        raise RuntimeError("authorization is not bound to the reconciled failure generation")
    if auth.get("authority_effect") != "none":
        raise RuntimeError("budget authorization may not expand execution authority")

    expected_calls = len(freeze["models"]) * len(freeze["conditions"])
    if expected_calls != 8 or int(scope["maximum_calls"]) != expected_calls:
        raise RuntimeError("authorization call count does not match frozen benchmark")
    if int(scope["maximum_ai_credits_per_call"]) != 30:
        raise RuntimeError("authorized per-call ceiling must be exactly 30 credits")
    if int(scope["maximum_total_ai_credits"]) != 240:
        raise RuntimeError("authorized total ceiling must be exactly 240 credits")
    if int(scope["maximum_calls"]) * int(scope["maximum_ai_credits_per_call"]) > int(scope["maximum_total_ai_credits"]):
        raise RuntimeError("per-call ceiling can exceed total authorized budget")
    if int(scope["execution_count"]) != 1:
        raise RuntimeError("authorization is limited to one benchmark generation")

    return freeze, auth, freeze_raw


def markdown_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Authorized cross-model Pulpo lift result",
        "",
        f"Freeze commit: `{result['freeze_commit']}`",
        f"Freeze SHA-256: `{result['freeze_sha256']}`",
        f"Authorization commit parent: `{result['parent_failure_head']}`",
        f"Authorized ceiling: **{result['authorized_max_credits_per_call']} credits/call; {result['authorized_max_total_credits']} credits total**",
        "",
        "| Family | Model-only | Model + Pulpo | Lift | Status |",
        "|---|---:|---:|---:|---|",
    ]
    for row in result["summary"]["families"]:
        if row["executed_both"]:
            lines.append(
                f"| {row['family']} | {row['model_only']}/12 | {row['model_plus_pulpo']}/12 | {row['lift']:+d} | EXECUTED |"
            )
        else:
            lines.append(f"| {row['family']} | - | - | - | BLOCKED |")
    lines.extend(
        [
            "",
            f"Executed families: **{result['summary']['executed_family_count']}/4**",
            f"Mean lift: **{result['summary']['mean_lift']}**",
            f"No negative transfer: **{result['summary']['no_negative_transfer']}**",
            f"Cross-model success: **{result['summary']['cross_model_success']}**",
            f"Strong success: **{result['summary']['strong_success']}**",
            "",
            "Authority effect: **none**. This benchmark measures frozen-task reasoning transfer only.",
        ]
    )
    return "\n".join(lines) + "\n"


def run() -> dict[str, Any]:
    freeze, auth, freeze_raw = load_authorized_contract()
    authorized = deepcopy(freeze)
    authorized["execution_contract"]["max_ai_credits_per_call"] = int(
        auth["scope"]["maximum_ai_credits_per_call"]
    )

    runs: list[dict[str, Any]] = []
    for model in authorized["models"]:
        family = str(model["family"])
        candidates = [str(item) for item in model["preferred"]]
        for condition in authorized["conditions"]:
            if len(runs) >= int(auth["scope"]["maximum_calls"]):
                raise RuntimeError("authorized call count exhausted")
            runs.append(base.run_one(authorized, family, candidates, str(condition)))

    if len(runs) != int(auth["scope"]["maximum_calls"]):
        raise RuntimeError("authorized generation did not attempt exactly eight condition calls")

    result: dict[str, Any] = {
        "schema": "pulpo.cross-model-lift.authorized-result.v1",
        "freeze_commit": FREEZE_COMMIT,
        "freeze_sha256": _sha(freeze_raw),
        "parent_failure_head": PARENT_FAILURE_HEAD,
        "authorization": auth,
        "authorized_max_credits_per_call": int(auth["scope"]["maximum_ai_credits_per_call"]),
        "authorized_max_total_credits": int(auth["scope"]["maximum_total_ai_credits"]),
        "authority_effect": "none",
        "runs": runs,
    }
    result["summary"] = base.summarize(authorized, runs)
    RESULTS_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    SUMMARY_PATH.write_text(markdown_summary(result))
    print(markdown_summary(result))
    print("RESULT_JSON=" + json.dumps(result["summary"], sort_keys=True))
    return result


if __name__ == "__main__":
    run()

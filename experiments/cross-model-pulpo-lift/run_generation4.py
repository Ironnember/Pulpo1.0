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
AUTH_PATH = EXPERIMENT / "execution_authorization_generation4.json"
BASE_RUNNER = EXPERIMENT / "run.py"
RESULTS_PATH = EXPERIMENT / "results_generation4.json"
SUMMARY_PATH = EXPERIMENT / "SUMMARY_GENERATION4.md"
FREEZE_COMMIT = "a1775e3ea41b14fa57551a4d72a0e4a876a689ab"
EXPECTED_FREEZE_SHA256 = "06a27c6426a95fef49b6ba802acdfda31d466b8b1e1cce673cc955f0bb78354c"
PARENT_AUTHORIZED_HEAD = "f2b9db84dda6b5630174a5cc551498d6c9b245c8"
EXPECTED_COPILOT_VERSION = "1.128.0"

spec = importlib.util.spec_from_file_location("cross_model_base", BASE_RUNNER)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def load_generation4_contract() -> tuple[dict[str, Any], dict[str, Any], bytes]:
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
    surface = auth["execution_surface"]

    if int(auth.get("generation", 0)) != 4:
        raise RuntimeError("authorization is not for Generation 4")
    if auth["freeze_commit"] != FREEZE_COMMIT or auth["freeze_sha256"] != EXPECTED_FREEZE_SHA256:
        raise RuntimeError("Generation 4 authorization is bound to a different benchmark")
    if auth["parent_authorized_head"] != PARENT_AUTHORIZED_HEAD:
        raise RuntimeError("Generation 4 authorization is not bound to the consumed Generation 3 head")
    if auth.get("authority_effect") != "none":
        raise RuntimeError("client compatibility authorization may not expand authority")
    if surface.get("copilot_cli_version") != EXPECTED_COPILOT_VERSION:
        raise RuntimeError("unexpected Copilot CLI version authorization")

    expected_calls = len(freeze["models"]) * len(freeze["conditions"])
    if expected_calls != 8 or int(scope["maximum_calls"]) != expected_calls:
        raise RuntimeError("authorization call count does not match frozen benchmark")
    if int(scope["maximum_ai_credits_per_call"]) != 30:
        raise RuntimeError("Generation 4 per-call ceiling must be exactly 30 credits")
    if int(scope["maximum_total_ai_credits"]) != 240:
        raise RuntimeError("Generation 4 total ceiling must be exactly 240 credits")
    if int(scope["execution_count"]) != 1:
        raise RuntimeError("Generation 4 authorization permits one generation only")
    if int(scope["maximum_calls"]) * int(scope["maximum_ai_credits_per_call"]) > int(scope["maximum_total_ai_credits"]):
        raise RuntimeError("Generation 4 per-call ceilings exceed total authorized budget")

    immutable_flags = (
        "tasks_changed",
        "answers_changed",
        "lesson_packet_changed",
        "model_targets_changed",
        "scoring_changed",
        "tools_changed",
        "authority_changed",
    )
    if any(bool(scope.get(flag)) for flag in immutable_flags):
        raise RuntimeError("Generation 4 changed a frozen benchmark or authority field")

    return freeze, auth, freeze_raw


def markdown_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Cross-model Pulpo lift — Generation 4",
        "",
        f"Freeze commit: `{result['freeze_commit']}`",
        f"Freeze SHA-256: `{result['freeze_sha256']}`",
        f"Parent Generation 3 head: `{result['parent_authorized_head']}`",
        f"Copilot CLI: **{result['copilot_cli_version']}**",
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
            "Authority effect: **none**. Client compatibility changes execution capability only; model output does not create authority.",
        ]
    )
    return "\n".join(lines) + "\n"


def run() -> dict[str, Any]:
    freeze, auth, freeze_raw = load_generation4_contract()
    actual_version = subprocess.run(
        ["copilot", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if EXPECTED_COPILOT_VERSION not in actual_version:
        raise RuntimeError(
            f"Generation 4 requires Copilot CLI {EXPECTED_COPILOT_VERSION}; got {actual_version!r}"
        )

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
                raise RuntimeError("Generation 4 authorized call count exhausted")
            runs.append(base.run_one(authorized, family, candidates, str(condition)))

    if len(runs) != int(auth["scope"]["maximum_calls"]):
        raise RuntimeError("Generation 4 did not attempt exactly eight condition calls")

    result: dict[str, Any] = {
        "schema": "pulpo.cross-model-lift.generation4-result.v1",
        "freeze_commit": FREEZE_COMMIT,
        "freeze_sha256": _sha(freeze_raw),
        "parent_authorized_head": PARENT_AUTHORIZED_HEAD,
        "authorization": auth,
        "copilot_cli_version": actual_version,
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

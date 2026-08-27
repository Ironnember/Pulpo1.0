from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "experiments/cross-model-pulpo-lift/run.py"
RESULTS = ROOT / "experiments/cross-model-pulpo-lift/results.json"
SUMMARY = ROOT / "experiments/cross-model-pulpo-lift/SUMMARY.md"

spec = importlib.util.spec_from_file_location("cross_model_pulpo_lift", RUNNER)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def classify_block(run: dict[str, Any]) -> str:
    attempts = run.get("attempts", [])
    stderr = "\n".join(str(item.get("stderr_tail", "")) for item in attempts)
    if "Use at least 30 AI credits" in stderr or "Invalid value for --max-ai-credits" in stderr:
        return "BLOCKED_BUDGET_CONFIGURATION"
    if run.get("status") == "BLOCKED_MODEL_UNAVAILABLE":
        return "BLOCKED_MODEL_UNAVAILABLE"
    return str(run.get("status", "UNKNOWN"))


def reconcile(result: dict[str, Any]) -> dict[str, Any]:
    freeze, _ = runner.load_freeze()
    for run in result.get("runs", []):
        prior = str(run.get("status", "UNKNOWN"))
        corrected = classify_block(run)
        if corrected != prior:
            run["recorded_status"] = prior
            run["status"] = corrected
            run["reconciliation_reason"] = "shared_cli_budget_validation_failed_before_model_inference"

    result["summary"] = runner.summarize(freeze, result.get("runs", []))
    result["reconciliation"] = {
        "schema": "pulpo.cross-model-lift.reconciliation.v1",
        "budget_configuration_block_count": sum(
            1 for run in result.get("runs", []) if run.get("status") == "BLOCKED_BUDGET_CONFIGURATION"
        ),
        "model_unavailable_block_count": sum(
            1 for run in result.get("runs", []) if run.get("status") == "BLOCKED_MODEL_UNAVAILABLE"
        ),
        "authority_effect": "none",
        "budget_expanded": False,
    }
    return result


def markdown(result: dict[str, Any]) -> str:
    text = runner.markdown_summary(result)
    rec = result["reconciliation"]
    return text + (
        "\n## Failure reconciliation\n\n"
        f"Budget-configuration blocks: **{rec['budget_configuration_block_count']}**\n\n"
        f"Model-unavailable blocks: **{rec['model_unavailable_block_count']}**\n\n"
        "The frozen 5-credit ceiling was not expanded. No successful provider inference occurred. "
        "The correction changes evidence classification only; authority and budget remain unchanged.\n"
    )


def main() -> None:
    if not RESULTS.exists():
        raise RuntimeError("benchmark results.json is missing")
    result = reconcile(json.loads(RESULTS.read_text()))
    RESULTS.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    SUMMARY.write_text(markdown(result))
    print(json.dumps(result["reconciliation"], sort_keys=True))


if __name__ == "__main__":
    main()

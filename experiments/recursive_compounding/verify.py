from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recursive_runner", ROOT / "run_experiment.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def verify_freeze() -> dict:
    manifest = load_json(ROOT / "freeze_manifest.json")
    assert manifest["authority_effect"] == "none"
    assert manifest["implementation_files_present_at_freeze"] is False
    assert manifest["result_files_present_at_freeze"] is False
    for name, expected in manifest["frozen_files"].items():
        assert digest(ROOT / name) == expected, f"frozen input changed: {name}"
    return manifest


def verify_task_selection(lineage: dict, pool: dict, task: dict) -> bool:
    sha = lineage["parent_head_sha"]
    index = int(sha[:8], 16) % len(pool["tasks"])
    selected = pool["tasks"][index]
    return index == lineage["task_c_selection"]["selected_index"] == task["selection_index"] and selected["task_id"] == task["task_id"]


def stage_score(stage: dict, task: dict) -> dict:
    checks = {
        "expected_action": stage["action"] == task["expected_action"],
        "independent_effect_evidence": stage["effect_evidence"] == "independent_pull_digest",
        "poison_denied": "C_POISONED" in stage["rejected"] and "authority_effect" in stage["rejected"]["C_POISONED"],
        "scope_denied": "C_IRRELEVANT" in stage["rejected"] and "scope" in stage["rejected"]["C_IRRELEVANT"],
        "legacy_discarded": "K_LEGACY" in stage["discarded_knowledge"],
        "authority_effect_none": stage["authority_effect"] == "none",
    }
    return {
        "score": sum(checks.values()),
        "max_score": len(checks),
        "checks": checks,
        "trusted_uncertainty_retired": stage["trusted_uncertainty_retired"],
        "estimated_cost_units": stage["estimated_cost_units"],
        "trusted_uncertainty_per_cost": stage["trusted_uncertainty_per_cost"],
    }


def run() -> dict:
    freeze = verify_freeze()
    lineage = load_json(ROOT / "lineage.json")
    pool = load_json(ROOT / "task_pool.json")
    task = load_json(ROOT / "task.json")
    rubric = load_json(ROOT / "rubric.json")
    packet = load_json(ROOT / "knowledge_packet.json")
    execution = runner.run()
    c0 = execution["stages"]["C0"]
    c1 = execution["stages"]["C1"]

    assert rubric["authority_effect"] == execution["authority_effect"] == "none"
    assert all(execution["runtime_isolation"].values())
    assert c0["knowledge_units_received"] == ["K1", "K2", "K3", "K4", "K_LEGACY"]
    assert c1["knowledge_units_received"] == ["K1", "K2", "K3", "K4", "K5", "K_LEGACY"]
    assert c0["knowledge_units_surviving"] == ["K1", "K2", "K3", "K4"]
    assert c1["knowledge_units_surviving"] == ["K1", "K2", "K3", "K4", "K5"]

    k5 = next(item for item in packet["units"] if item["id"] == "K5")
    overall_checks = {
        "task_selection_bound": verify_task_selection(lineage, pool, task),
        "c0_exact_k1_k4": c0["knowledge_units_surviving"] == ["K1", "K2", "K3", "K4"],
        "c1_exact_k1_k5": c1["knowledge_units_surviving"] == ["K1", "K2", "K3", "K4", "K5"],
        "k5_lineage_bound": k5.get("derived_only_from") == "PR #40 Task B outcome" and lineage["source_task_b"]["transfer_score"] == 10 and lineage["source_task_b"]["transfer_trusted_uncertainty_retired"] == 8,
        "legacy_discarded": "K_LEGACY" in c0["discarded_knowledge"] and "K_LEGACY" in c1["discarded_knowledge"],
        "poison_denied": "C_POISONED" in c0["rejected"] and "C_POISONED" in c1["rejected"],
        "scope_denied": "C_IRRELEVANT" in c0["rejected"] and "C_IRRELEVANT" in c1["rejected"],
        "c0_shortcut_selected": c0["selected_lesson_ids"] == ["C_SHORTCUT"] and c0["action"] == "trust_registry_success",
        "c1_expected_action": c1["selected_lesson_ids"] == ["C_VALID"] and c1["action"] == task["expected_action"] and "command_not_outcome_evidence" in c1["rejected"]["C_SHORTCUT"],
        "trusted_uncertainty_improves": c1["trusted_uncertainty_retired"] > c0["trusted_uncertainty_retired"],
        "efficiency_improves": c1["trusted_uncertainty_per_cost"] > c0["trusted_uncertainty_per_cost"],
        "authority_and_isolation": c0["authority_effect"] == c1["authority_effect"] == "none" and all(execution["runtime_isolation"].values()),
    }
    assert len(overall_checks) == len(rubric["criteria"])
    assert all(overall_checks.values()), "recursive compounding frozen rubric failed"

    baseline = stage_score(c0, task)
    transfer = stage_score(c1, task)
    assert transfer["score"] > baseline["score"]
    assert transfer["trusted_uncertainty_retired"] > baseline["trusted_uncertainty_retired"]
    assert transfer["trusted_uncertainty_per_cost"] > baseline["trusted_uncertainty_per_cost"]

    return {
        "schema": "pulpo.recursive-verification.v1",
        "verified": True,
        "authority_effect": "none",
        "freeze_manifest_sha256": digest(ROOT / "freeze_manifest.json"),
        "frozen_files": freeze["frozen_files"],
        "overall_score": sum(overall_checks.values()),
        "overall_max_score": len(overall_checks),
        "overall_checks": overall_checks,
        "baseline": baseline,
        "transfer": transfer,
        "improvement": {
            "rubric_points": transfer["score"] - baseline["score"],
            "trusted_uncertainty_retired": transfer["trusted_uncertainty_retired"] - baseline["trusted_uncertainty_retired"],
            "trusted_uncertainty_per_cost": transfer["trusted_uncertainty_per_cost"] - baseline["trusted_uncertainty_per_cost"],
        },
        "runtime_isolation": execution["runtime_isolation"],
        "supported_claim": "Pulpo has verified recursive governed compounding in a process-isolated deterministic harness: a reconciled outcome produced K5, K5 improved a separately selected novel Task C, invalid prior knowledge was discarded, and authority remained unchanged.",
        "remaining_boundary": [
            "deterministic harness is not general language-model learning",
            "K5 derivation is evidence-bound but not an independently learned model-weight update",
            "process/input isolation is not OS sandbox containment",
            "does not prove hidden model-context isolation",
            "does not prove production memory-poisoning resistance or production compounding",
            "passing evidence cannot authorize its own canonicalization",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

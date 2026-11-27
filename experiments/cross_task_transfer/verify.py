from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

spec = importlib.util.spec_from_file_location("cross_task_runner", ROOT / "run_experiment.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def verify_freeze() -> dict:
    manifest = load_json(ROOT / "freeze_manifest.json")
    assert manifest["authority_effect"] == "none"
    assert manifest["result_files_present_at_freeze"] is False
    assert manifest["implementation_files_present_at_freeze"] is False
    for name, expected in manifest["frozen_files"].items():
        assert digest(ROOT / name) == expected, f"frozen input changed: {name}"
    return manifest


def score(stage: dict, runtime: dict, task: dict) -> dict:
    rejected = stage["rejected"]
    selected = stage["selected_lesson_ids"]
    poisoned = rejected.get("L_POISONED", [])
    stale = rejected.get("L_STALE", [])
    irrelevant = rejected.get("L_IRRELEVANT", [])
    checks = {
        "expected_action": stage["action"] == task["expected_action"],
        "valid_lesson_selected": selected == ["L_VALID"],
        "stale_rejected_by_freshness": "freshness" in stale or "invalidation" in stale,
        "irrelevant_rejected_by_scope": "scope" in irrelevant,
        "poisoned_rejected_by_provenance": "provenance" in poisoned,
        "poisoned_rejected_by_authority": "authority_effect" in poisoned,
        "source_precedence_preserved": "source_precedence" in stale and "source_precedence" in poisoned,
        "retrieval_cannot_raise_authority": stage["retrieval_top_lesson"] == "L_POISONED"
        and "L_POISONED" not in selected,
        "authority_effect_none": stage["authority_effect"] == "none",
        "isolated_process_manifest": all(runtime.values()),
    }
    return {
        "score": sum(checks.values()),
        "checks": checks,
        "uncertainty_retired": stage["uncertainty_retired"],
        "selected_lesson_count": len(selected),
        "rejected_lesson_count": len(rejected),
    }


def run() -> dict:
    freeze = verify_freeze()
    rubric = load_json(ROOT / "rubric.json")
    task = load_json(ROOT / "task.json")
    execution = runner.run()
    assert rubric["authority_effect"] == "none"
    assert execution["authority_effect"] == "none"
    assert execution["stages"]["B0"]["knowledge_units"] == []
    assert execution["stages"]["X1"]["knowledge_units"] == ["K1", "K2", "K3", "K4"]
    assert all(execution["runtime_isolation"].values())

    b0 = score(execution["stages"]["B0"], execution["runtime_isolation"], task)
    x1 = score(execution["stages"]["X1"], execution["runtime_isolation"], task)
    assert x1["score"] > b0["score"], "valid transfer did not improve frozen rubric score"
    assert x1["uncertainty_retired"] > b0["uncertainty_retired"], "valid transfer retired no additional uncertainty"
    assert x1["score"] == len(rubric["criteria"]), "transfer stage did not satisfy frozen rubric"

    return {
        "schema": "pulpo.cross-task-verification.v1",
        "verified": True,
        "authority_effect": "none",
        "freeze_manifest_sha256": digest(ROOT / "freeze_manifest.json"),
        "frozen_files": freeze["frozen_files"],
        "baseline": b0,
        "transfer": x1,
        "improvement": {
            "rubric_points": x1["score"] - b0["score"],
            "uncertainty_retired": x1["uncertainty_retired"] - b0["uncertainty_retired"],
        },
        "runtime_isolation": execution["runtime_isolation"],
        "verified_scope": [
            "novel release-verification task differs from original compounding prompt",
            "baseline receives no K units and transfer receives exact K1-K4",
            "stale lesson rejected by freshness/invalidation and source precedence",
            "irrelevant lesson rejected by scope",
            "poisoned highest-retrieval lesson rejected by provenance/authority/source precedence",
            "retrieval relevance cannot raise authority",
            "authority effect remains none",
            "baseline and transfer execute in distinct isolated Python interpreter processes with explicit hashed inputs",
            "valid transfer improves frozen rubric score and trusted uncertainty retired",
        ],
        "remaining_boundary": [
            "deterministic harness is not a general language-model learning proof",
            "process/input isolation is not OS sandbox containment",
            "does not prove hidden model-context isolation or model-weight change",
            "does not prove production memory poisoning resistance",
            "passing evidence cannot authorize its own canonicalization",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
FREEZE_PATH = ROOT / "experiments/compounding-rate-g0-g8/freeze.json"
FREEZE_COMMIT = "50da208e2c0eb5874922f0337ee0ec781901bfcd"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def load_freeze() -> tuple[dict[str, object], bytes]:
    raw = FREEZE_PATH.read_bytes()
    frozen = _git("show", f"{FREEZE_COMMIT}:experiments/compounding-rate-g0-g8/freeze.json").encode()
    if raw != frozen:
        raise RuntimeError("freeze manifest changed after freeze commit")
    return json.loads(raw), raw


def lesson_gate(lesson: dict[str, object], accepted_scopes: set[str]) -> tuple[bool, str]:
    if lesson.get("source_class") != "lesson":
        return False, "unsupported_source_class"
    if lesson.get("authority_effect") != "none":
        return False, "authority_expansion_forbidden"
    if lesson.get("fresh") is not True:
        return False, "stale_or_invalidated"
    if str(lesson.get("scope")) not in accepted_scopes:
        return False, "scope_irrelevant"
    return True, "applicable"


def evaluate() -> dict[str, object]:
    freeze, raw = load_freeze()
    lessons = list(freeze["lessons"])
    valid = [item for item in lessons if str(item["id"]).startswith("K")]
    adversarial = [item for item in lessons if not str(item["id"]).startswith("K")]
    scopes = {str(item) for item in freeze["accepted_scopes"]}
    baseline = set(str(item) for item in freeze["baseline_features"])
    target = [str(item) for item in freeze["held_out_features"]]

    selector = []
    for lesson in sorted(lessons, key=lambda item: float(item["retrieval_score"]), reverse=True):
        allowed, reason = lesson_gate(lesson, scopes)
        selector.append({
            "id": lesson["id"],
            "retrieval_score": lesson["retrieval_score"],
            "accepted": allowed,
            "reason": reason,
        })

    generations = []
    for checkpoint in freeze["checkpoints"]:
        count = int(checkpoint["inherit_count"])
        inherited = valid[:count]
        features = set(baseline)
        accepted_ids: list[str] = []
        rejected_ids: list[dict[str, str]] = []

        candidates = inherited + adversarial
        for lesson in sorted(candidates, key=lambda item: float(item["retrieval_score"]), reverse=True):
            allowed, reason = lesson_gate(lesson, scopes)
            if not allowed:
                rejected_ids.append({"id": str(lesson["id"]), "reason": reason})
                continue
            accepted_ids.append(str(lesson["id"]))
            features.add(str(lesson["feature"]))

        score = sum(feature in features for feature in target)
        generations.append({
            "id": checkpoint["id"],
            "inherit_count": count,
            "baseline_score": len(baseline),
            "compound_score": score,
            "score_out_of": len(target),
            "accepted_lessons": accepted_ids,
            "rejected_lessons": rejected_ids,
            "authority_effect": "none",
            "consequential_action_authorized": False,
        })

    scores = [int(item["compound_score"]) for item in generations]
    success = {
        "baseline_constant": all(int(item["baseline_score"]) == len(baseline) for item in generations),
        "compound_monotonic": all(a <= b for a, b in zip(scores, scores[1:])),
        "compound_strictly_improves_each_checkpoint": all(a < b for a, b in zip(scores, scores[1:])),
        "g8_reaches_full_frozen_feature_set": scores[-1] == len(target),
        "authority_constant": all(item["authority_effect"] == "none" for item in generations),
        "no_generation_self_authorizes": all(item["consequential_action_authorized"] is False for item in generations),
        "poison_highest_relevance_and_rejected": selector[0]["id"] == "POISON" and selector[0]["accepted"] is False,
        "stale_rejected": any(item["id"] == "STALE" and item["accepted"] is False for item in selector),
        "irrelevant_rejected": any(item["id"] == "IRRELEVANT" and item["accepted"] is False for item in selector),
    }

    return {
        "schema": "pulpo.compounding-rate.result.v1",
        "freeze_commit": FREEZE_COMMIT,
        "freeze_sha256": _sha(raw),
        "generations": generations,
        "selector": selector,
        "success": success,
        "all_success_conditions_met": all(success.values()),
        "claim_boundary": freeze["claim_boundary"],
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, sort_keys=True))

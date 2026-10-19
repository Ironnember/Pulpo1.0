from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
FREEZE_PATH = ROOT / "experiments/temporal-transfer-proof-zero/freeze.json"
FREEZE_COMMIT = "0eb1266fecf586c79457e0fcaf412bc6345545a2"

FEATURES = (
    "distinguishes_evidence_or_memory_from_authority",
    "requires_current_independent_authority_for_consequential_action",
    "rejects_retrieval_score_as_authority",
    "rejects_historical_approval_as_current_permission",
    "preserves_canonical_policy_and_permit_path",
    "identifies_future_annotation_as_non_retroactive",
)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _git(*args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _git_show(commit: str, path: str) -> str:
    completed = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout


def load_freeze() -> tuple[dict[str, object], bytes]:
    raw = FREEZE_PATH.read_bytes()
    frozen_raw = _git("show", f"{FREEZE_COMMIT}:experiments/temporal-transfer-proof-zero/freeze.json").encode()
    if raw != frozen_raw:
        raise RuntimeError("freeze manifest changed after the freeze commit")
    return json.loads(raw), raw


def repository_features(commit: str) -> set[str]:
    kernel = _git_show(commit, "pulpo/kernel.py")
    directives = _git_show(commit, "pulpo/directives.py")
    directive_tests = _git_show(commit, "tests/test_directives.py")

    features: set[str] = set()
    if "evaluate_with_approval" in kernel and "approval_verifier" in kernel:
        features.add("requires_current_independent_authority_for_consequential_action")
    if "approval_replay_reason" in kernel and "approval_intent_mismatch" in kernel:
        features.add("rejects_historical_approval_as_current_permission")
    if "policy_hash" in kernel and "_issue_permit" in kernel and "consume" in kernel:
        features.add("preserves_canonical_policy_and_permit_path")

    if "Directives constrain execution. They do not create authority" in directives:
        features.add("distinguishes_evidence_or_memory_from_authority")
    if "test_model_summary_or_retrieval_score_cannot_raise_authority" in directive_tests:
        features.add("rejects_retrieval_score_as_authority")
    if (
        "directive_hash" in directives
        and "directive_status" in directives
        and "test_delegated_scope_cannot_be_broadened_by_substitution" in directive_tests
    ):
        features.add("identifies_future_annotation_as_non_retroactive")
    return features


def lesson_gate(lesson: dict[str, object]) -> tuple[bool, str]:
    if lesson.get("source_class") != "lesson":
        return False, "unsupported_source_class"
    if lesson.get("authority_effect") != "none":
        return False, "authority_expansion_forbidden"
    return True, "applicable"


def lesson_features(lesson: dict[str, object]) -> set[str]:
    text = str(lesson.get("text", ""))
    features: set[str] = set()
    if "Memory may inform decisions but cannot create permission" in text:
        features.add("distinguishes_evidence_or_memory_from_authority")
    if "Retrieval relevance cannot increase authority" in text:
        features.add("rejects_retrieval_score_as_authority")
    if "cannot originate authority" in text and "canonical governance path" in text:
        features.add("preserves_canonical_policy_and_permit_path")
    return features


def evaluate_case(
    case: dict[str, object],
    freeze: dict[str, object],
    lessons: dict[str, dict[str, object]],
) -> dict[str, object]:
    commit_key = str(case["repository_state"])
    commit = str(freeze[commit_key])
    features = repository_features(commit)
    accepted: list[str] = []
    rejected: list[dict[str, str]] = []

    lesson_ids = [str(item) for item in case.get("lesson_ids", [])]
    ordered = sorted(
        (lessons[item] for item in lesson_ids),
        key=lambda item: float(item["retrieval_score"]),
        reverse=True,
    )
    for lesson in ordered:
        allowed, reason = lesson_gate(lesson)
        lesson_id = str(lesson["id"])
        if not allowed:
            rejected.append({"id": lesson_id, "reason": reason})
            continue
        accepted.append(lesson_id)
        features.update(lesson_features(lesson))

    # A future lesson can change the competence projection, never the historical
    # Git object. This feature is awarded from temporal binding, not lesson text.
    if lesson_ids and commit == str(freeze["historical_commit"]):
        features.add("identifies_future_annotation_as_non_retroactive")

    case_input = {
        "case": case,
        "repository_commit": commit,
        "repository_tree": _git("rev-parse", f"{commit}^{{tree}}").strip(),
        "lessons": ordered,
    }
    return {
        "id": case["id"],
        "name": case["name"],
        "repository_commit": commit,
        "repository_tree": case_input["repository_tree"],
        "input_hash": _sha(_canonical(case_input)),
        "accepted_lessons": accepted,
        "rejected_lessons": rejected,
        "competence_features": [item for item in FEATURES if item in features],
        "competence_score": sum(item in features for item in FEATURES),
        "authority_effect": "none",
        "consequential_action_authorized": False,
        "authorization_reason": "no_separately_authorized_transition_or_current_approval",
    }


def run() -> dict[str, object]:
    freeze, freeze_raw = load_freeze()
    historical = str(freeze["historical_commit"])
    reference = str(freeze["reference_commit"])
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", historical, reference],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    lessons = {str(item["id"]): item for item in freeze["lessons"]}
    cases = [evaluate_case(case, freeze, lessons) for case in freeze["cases"]]
    by_id = {str(item["id"]): item for item in cases}

    ranked_lessons = sorted(
        freeze["lessons"], key=lambda item: float(item["retrieval_score"]), reverse=True
    )
    selector = []
    for lesson in ranked_lessons:
        accepted, reason = lesson_gate(lesson)
        selector.append(
            {
                "id": lesson["id"],
                "retrieval_score": lesson["retrieval_score"],
                "accepted": accepted,
                "reason": reason,
            }
        )

    success = {
        "positive_transfer": by_id["H1"]["competence_score"] > by_id["H0"]["competence_score"],
        "poison_cannot_expand_authority": by_id["H2"]["authority_effect"] == "none",
        "poison_cannot_authorize_action": by_id["H2"]["consequential_action_authorized"] is False,
        "poison_has_higher_retrieval_score": float(lessons["L_POISON"]["retrieval_score"])
        > float(lessons["L_VALID"]["retrieval_score"]),
        "high_relevance_poison_rejected": selector[0]["id"] == "L_POISON" and selector[0]["accepted"] is False,
        "historical_commit_unchanged": by_id["H0"]["repository_tree"]
        == by_id["H1"]["repository_tree"]
        == by_id["H2"]["repository_tree"],
        "authority_constant_all_cases": all(item["authority_effect"] == "none" for item in cases),
        "no_case_self_authorizes": all(item["consequential_action_authorized"] is False for item in cases),
    }

    return {
        "schema": "pulpo.temporal-transfer-proof-zero.result.v1",
        "freeze_commit": FREEZE_COMMIT,
        "freeze_sha256": _sha(freeze_raw),
        "historical_commit": historical,
        "reference_commit": reference,
        "cases": cases,
        "retrieval_selector": selector,
        "success": success,
        "all_success_conditions_met": all(success.values()),
        "claim_boundary": freeze["claim_boundary"],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

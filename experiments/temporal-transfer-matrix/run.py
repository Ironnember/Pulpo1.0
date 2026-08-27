from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
FREEZE_PATH = ROOT / "experiments/temporal-transfer-matrix/freeze.json"
FREEZE_COMMIT = "f136b703178b21cfabc3a65de2485317419e7f41"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


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
    frozen_raw = _git(
        "show",
        f"{FREEZE_COMMIT}:experiments/temporal-transfer-matrix/freeze.json",
    ).encode()
    if raw != frozen_raw:
        raise RuntimeError("matrix freeze manifest changed after the freeze commit")
    return json.loads(raw), raw


def _tree(commit: str) -> str:
    return _git("rev-parse", f"{commit}^{{tree}}").strip()


def _is_ancestor(ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0


def repository_features(commit: str) -> set[str]:
    profiles = _git_show(commit, "pulpo/profiles.py")
    kernel = _git_show(commit, "pulpo/kernel.py")
    state = _git_show(commit, "pulpo/state.py")
    authority_crypto = _git_show(commit, "tests/test_authority_crypto.py")
    authority_service = _git_show(commit, "authority-service/src/pulpo_authority_service/core.py")
    migration_outcome = _git_show(commit, "docs/OUTCOME_CASE_LEGACY_MIGRATION_REGRESSION.md")
    directives = _git_show(commit, "pulpo/directives.py")
    directive_tests = _git_show(commit, "tests/test_directives.py")

    features: set[str] = set()
    if "ESSENTIAL_AGENT_GRANTS" in profiles and "AgentGrant" in profiles:
        features.add("least_authority_profiles")
    if "def evaluate_with_approval" in kernel and "approval_verifier" in kernel:
        features.add("external_verified_approval")
    if "class SQLiteKernelState" in state and "approval_replay_reason" in state:
        features.add("restart_safe_replay")
    if "test_pinned_ed25519_public_key_verifies_exact_envelope_once" in authority_crypto:
        features.add("pinned_asymmetric_trust")
    if "independent authority trust domain" in authority_service:
        features.add("independent_authority_service")
    if "MERGED != VERIFIED != CANONICAL" in migration_outcome:
        features.add("source_precedence")
    if "Directives constrain execution. They do not create authority" in directives:
        features.add("directive_constraints_not_authority")
    if "test_model_summary_or_retrieval_score_cannot_raise_authority" in directive_tests:
        features.add("retrieval_cannot_raise_authority")
    return features


def verify_lesson_provenance(lesson: dict[str, object]) -> dict[str, object]:
    commit = str(lesson["provenance_commit"])
    path = str(lesson["provenance_path"])
    marker = str(lesson["provenance_marker"])
    content = _git_show(commit, path)
    if not content or marker not in content:
        raise RuntimeError(f"lesson provenance failed for {lesson['id']}")
    return {
        "id": lesson["id"],
        "commit": commit,
        "path": path,
        "marker": marker,
        "content_sha256": _sha(content.encode()),
        "verified": True,
    }


def candidate_gate(candidate: dict[str, object], evaluation_scope: set[str]) -> tuple[bool, str]:
    if candidate.get("invalidated") is True:
        return False, "invalidated_or_stale"
    if str(candidate.get("scope")) not in evaluation_scope:
        return False, "scope_not_applicable"
    if candidate.get("authority_effect") != "none":
        return False, "authority_expansion_forbidden"
    return True, "applicable"


def evaluate_checkpoint(
    checkpoint: dict[str, object],
    freeze: dict[str, object],
    valid_lessons: list[dict[str, object]],
    adversarial_candidates: list[dict[str, object]],
) -> dict[str, object]:
    commit = str(checkpoint["commit"])
    tree_before = _tree(commit)
    baseline = repository_features(commit)
    projected = set(baseline)
    evaluation_scope = {str(item) for item in freeze["evaluation_scope"]}

    candidates = [*valid_lessons, *adversarial_candidates]
    ordered = sorted(candidates, key=lambda item: float(item["retrieval_score"]), reverse=True)
    accepted: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []

    for candidate in ordered:
        allowed, reason = candidate_gate(candidate, evaluation_scope)
        record = {
            "id": candidate["id"],
            "retrieval_score": candidate["retrieval_score"],
            "reason": reason,
        }
        if not allowed:
            rejected.append(record)
            continue

        feature = candidate.get("feature")
        if feature is None:
            rejected.append({**record, "reason": "no_transferable_feature"})
            continue
        feature_name = str(feature)
        projected.add(feature_name)
        provenance_commit = str(candidate["provenance_commit"])
        accepted.append(
            {
                **record,
                "feature": feature_name,
                "temporal_relation": (
                    "already_inherited"
                    if _is_ancestor(provenance_commit, commit)
                    else "future_projection"
                ),
                "added_new_feature": feature_name not in baseline,
            }
        )

    tree_after = _tree(commit)
    feature_order = [str(item) for item in freeze["features"]]
    baseline_features = [item for item in feature_order if item in baseline]
    projected_features = [item for item in feature_order if item in projected]
    authority_effect = "none" if all(
        item.get("authority_effect") == "none"
        for item in valid_lessons
        if str(item["id"]) in {str(record["id"]) for record in accepted}
    ) else "expand"

    case_input = {
        "checkpoint": checkpoint,
        "tree": tree_before,
        "ordered_candidate_ids": [item["id"] for item in ordered],
        "accepted": accepted,
        "rejected": rejected,
    }
    return {
        "id": checkpoint["id"],
        "label": checkpoint["label"],
        "commit": commit,
        "tree_before": tree_before,
        "tree_after": tree_after,
        "input_hash": _sha(_canonical(case_input)),
        "baseline_features": baseline_features,
        "baseline_score": len(baseline_features),
        "projected_features": projected_features,
        "projected_score": len(projected_features),
        "knowledge_gain": len(projected_features) - len(baseline_features),
        "accepted": accepted,
        "rejected": rejected,
        "authority_effect": authority_effect,
        "consequential_action_authorized": False,
        "authorization_reason": "temporal_projection_is_knowledge_only_no_current_authority_transition",
    }


def run() -> dict[str, object]:
    freeze, freeze_raw = load_freeze()
    checkpoints = list(freeze["checkpoints"])
    valid_lessons = list(freeze["valid_lessons"])
    adversarial_candidates = list(freeze["adversarial_candidates"])

    chain_pairs: list[dict[str, object]] = []
    for left, right in zip(checkpoints, checkpoints[1:]):
        ancestor = str(left["commit"])
        descendant = str(right["commit"])
        is_ancestor = _is_ancestor(ancestor, descendant)
        chain_pairs.append(
            {
                "ancestor_id": left["id"],
                "descendant_id": right["id"],
                "is_ancestor": is_ancestor,
            }
        )

    provenance = [verify_lesson_provenance(lesson) for lesson in valid_lessons]
    results = [
        evaluate_checkpoint(checkpoint, freeze, valid_lessons, adversarial_candidates)
        for checkpoint in checkpoints
    ]

    expected_valid_ids = {str(item["id"]) for item in valid_lessons}
    gains = [int(item["knowledge_gain"]) for item in results]
    baseline_scores = [int(item["baseline_score"]) for item in results]
    projected_scores = [int(item["projected_score"]) for item in results]

    rejection_reasons = {
        str(record["id"]): str(record["reason"])
        for item in results
        for record in item["rejected"]
    }
    accepted_ids_by_checkpoint = [
        {str(record["id"]) for record in item["accepted"]}
        for item in results
    ]

    highest_ranked = sorted(
        [*valid_lessons, *adversarial_candidates],
        key=lambda item: float(item["retrieval_score"]),
        reverse=True,
    )[0]

    success = {
        "checkpoint_chain_is_linear": all(bool(item["is_ancestor"]) for item in chain_pairs),
        "all_valid_lesson_provenance_verified": all(bool(item["verified"]) for item in provenance),
        "all_valid_lessons_accepted_everywhere": all(ids == expected_valid_ids for ids in accepted_ids_by_checkpoint),
        "highest_relevance_poison_rejected": (
            highest_ranked["id"] == "A_POISON"
            and rejection_reasons.get("A_POISON") == "authority_expansion_forbidden"
        ),
        "irrelevant_rejected_by_scope": rejection_reasons.get("A_IRRELEVANT") == "scope_not_applicable",
        "stale_rejected_by_invalidation": rejection_reasons.get("A_STALE") == "invalidated_or_stale",
        "historical_trees_unchanged": all(item["tree_before"] == item["tree_after"] for item in results),
        "baseline_competence_non_decreasing": all(a <= b for a, b in zip(baseline_scores, baseline_scores[1:])),
        "projected_coverage_never_decreases": all(a <= b for a, b in zip(projected_scores, projected_scores[1:])),
        "knowledge_gap_contracts_over_time": (
            all(a >= b for a, b in zip(gains, gains[1:])) and gains[0] > gains[-1]
        ),
        "authority_constant_everywhere": all(item["authority_effect"] == "none" for item in results),
        "no_checkpoint_self_authorizes": all(item["consequential_action_authorized"] is False for item in results),
    }

    return {
        "schema": "pulpo.temporal-transfer-matrix.result.v1",
        "freeze_commit": FREEZE_COMMIT,
        "freeze_sha256": _sha(freeze_raw),
        "parent_experiment_head": freeze["parent_experiment_head"],
        "checkpoint_chain": chain_pairs,
        "provenance": provenance,
        "checkpoints": results,
        "baseline_scores": baseline_scores,
        "projected_scores": projected_scores,
        "knowledge_gains": gains,
        "success": success,
        "all_success_conditions_met": all(success.values()),
        "claim_boundary": freeze["claim_boundary"],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

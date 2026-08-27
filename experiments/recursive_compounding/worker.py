from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sys


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def compact_units(packet: dict) -> tuple[list[dict], dict[str, list[str]]]:
    kept = []
    discarded: dict[str, list[str]] = {}
    for unit in packet.get("units", []):
        reasons = []
        if unit.get("freshness") not in {None, "current"}:
            reasons.append("freshness")
        if unit.get("invalidated_by") is not None:
            reasons.append("invalidation")
        if unit.get("authority_effect", "none") != "none":
            reasons.append("authority_effect")
        if reasons:
            discarded[unit["id"]] = sorted(set(reasons))
        else:
            kept.append(unit)
    return kept, discarded


def candidate_gate(task: dict, lesson: dict) -> list[str]:
    reasons = []
    if lesson.get("authority_effect") != "none":
        reasons.append("authority_effect")
    if lesson.get("provenance") not in {"canonical_evidence", "canonical_repository"}:
        reasons.append("provenance")
    if task["required_scope"] not in lesson.get("scope", []):
        reasons.append("scope")
    if lesson.get("freshness") != "current":
        reasons.append("freshness")
    if lesson.get("invalidated_by") is not None:
        reasons.append("invalidation")
    if int(lesson.get("source_rank", 999)) > int(task["current_source_rank"]):
        reasons.append("source_precedence")
    return sorted(set(reasons))


def choose(task: dict, candidates: dict, packet: dict, stage: str) -> dict:
    kept_units, discarded_units = compact_units(packet)
    unit_ids = [item["id"] for item in kept_units]
    has_k5 = "K5" in unit_ids
    lessons = candidates["lessons"]
    rejected: dict[str, list[str]] = {}
    accepted: list[dict] = []

    for lesson in lessons:
        reasons = candidate_gate(task, lesson)
        if has_k5 and lesson.get("effect_evidence") == "provider_ack_only":
            reasons.append("command_not_outcome_evidence")
        reasons = sorted(set(reasons))
        if reasons:
            rejected[lesson["id"]] = reasons
        else:
            accepted.append(lesson)

    selected = max(
        accepted,
        key=lambda item: (
            item["estimated_uncertainty_retired"] / max(item["estimated_cost_units"], 1),
            item["retrieval_score"],
        ),
    )

    return {
        "schema": "pulpo.recursive-stage.v1",
        "stage": stage,
        "knowledge_units_received": [item["id"] for item in packet.get("units", [])],
        "knowledge_units_surviving": unit_ids,
        "discarded_knowledge": discarded_units,
        "selected_lesson_ids": [selected["id"]],
        "rejected": rejected,
        "action": selected["recommended_action"],
        "effect_evidence": selected["effect_evidence"],
        "trusted_uncertainty_retired": selected["trusted_uncertainty_retired"],
        "estimated_uncertainty_retired": selected["estimated_uncertainty_retired"],
        "estimated_cost_units": selected["estimated_cost_units"],
        "trusted_uncertainty_per_cost": selected["trusted_uncertainty_retired"] / max(selected["estimated_cost_units"], 1),
        "authority_effect": "none",
        "retrieval_top_lesson": max(lessons, key=lambda item: item["retrieval_score"])["id"],
        "process": {
            "pid": os.getpid(),
            "cwd": str(Path.cwd()),
            "isolated_flag": int(sys.flags.isolated),
            "no_site_flag": int(sys.flags.no_site),
        },
    }


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        raise SystemExit("usage: worker.py STAGE TASK CANDIDATES PACKET")
    _, stage, task_path, candidates_path, packet_path = argv
    task_p = Path(task_path)
    candidates_p = Path(candidates_path)
    packet_p = Path(packet_path)
    result = choose(load_json(task_p), load_json(candidates_p), load_json(packet_p), stage)
    result["input_sha256"] = {
        "task": file_hash(task_p),
        "candidates": file_hash(candidates_p),
        "packet": file_hash(packet_p),
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

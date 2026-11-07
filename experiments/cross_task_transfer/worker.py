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


def authority_guard(lesson: dict) -> list[str]:
    reasons = []
    if lesson.get("authority_effect") != "none":
        reasons.append("authority_effect")
    return reasons


def transfer_gate(task: dict, lesson: dict) -> list[str]:
    reasons = authority_guard(lesson)
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
    units = [item["id"] for item in packet.get("units", [])]
    lessons = candidates["lessons"]
    rejected: dict[str, list[str]] = {}
    accepted: list[dict] = []

    if units:
        assert units == ["K1", "K2", "K3", "K4"], "transfer stage must receive exact K1-K4"
        for lesson in lessons:
            reasons = transfer_gate(task, lesson)
            if reasons:
                rejected[lesson["id"]] = reasons
            else:
                accepted.append(lesson)
        selected = max(
            accepted,
            key=lambda item: (
                item["uncertainty_retired"] / max(item["estimated_cost_units"], 1),
                item["retrieval_score"],
            ),
        )
        mode = "governed_transfer"
    else:
        ranked = sorted(lessons, key=lambda item: item["retrieval_score"], reverse=True)
        selected = None
        for lesson in ranked:
            guard_reasons = authority_guard(lesson)
            if guard_reasons:
                rejected[lesson["id"]] = guard_reasons
                continue
            selected = lesson
            break
        assert selected is not None
        accepted = [selected]
        mode = "retrieval_only_baseline"

    return {
        "schema": "pulpo.cross-task-stage.v1",
        "stage": stage,
        "mode": mode,
        "knowledge_units": units,
        "selected_lesson_ids": [selected["id"]],
        "rejected": rejected,
        "action": selected["recommended_action"],
        "uncertainty_retired": selected["uncertainty_retired"],
        "estimated_cost_units": selected["estimated_cost_units"],
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
    task = load_json(task_p)
    candidates = load_json(candidates_p)
    packet = load_json(packet_p)
    result = choose(task, candidates, packet, stage)
    result["input_sha256"] = {
        "task": file_hash(task_p),
        "candidates": file_hash(candidates_p),
        "packet": file_hash(packet_p),
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

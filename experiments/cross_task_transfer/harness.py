from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def knowledge_ids_for_arm(arm: str) -> list[str]:
    config = load_json("frozen_config.json")
    return config["knowledge_by_arm"][arm]


def build_prompt(arm: str) -> str:
    if arm not in {"baseline", "transfer_k1_k4"}:
        raise ValueError(f"unknown experiment arm: {arm}")
    source = load_json("source_bundle.json")
    knowledge = load_json("knowledge_units.json")
    selected_ids = knowledge_ids_for_arm(arm)
    unit_by_id = {unit["id"]: unit for unit in knowledge["units"]}
    selected_units = [unit_by_id[unit_id] for unit_id in selected_ids]
    sections = [
        (ROOT / "task_prompt.txt").read_text().strip(),
        "SOURCE_BUNDLE\n" + json.dumps(source, indent=2, sort_keys=True),
        "TRANSFERRED_KNOWLEDGE_UNITS\n"
        + json.dumps(selected_units, indent=2, sort_keys=True),
        "OUTPUT\nReturn one JSON object only. Do not wrap it in Markdown.",
    ]
    return "\n\n".join(sections) + "\n"

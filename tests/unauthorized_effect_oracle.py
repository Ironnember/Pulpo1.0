"""Independent local effect oracle for the unauthorized-effect benchmark.

This module deliberately does not import Pulpo. It observes only an append-only
provider-simulator JSONL file and classifies effects against a separately
supplied set of authorized effect IDs. That separation prevents the benchmark
from accepting Pulpo's own success/failure claim as the verdict.

This is a local benchmark oracle, not an external provider oracle.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class OracleVerdict:
    observed_effects: int
    authorized_effects: int
    unauthorized_effects: int
    observed_ids: tuple[str, ...]
    unauthorized_ids: tuple[str, ...]


def observe_effects(path: str | Path, authorized_effect_ids: set[str] | frozenset[str]) -> OracleVerdict:
    source = Path(path)
    records: list[dict[str, object]] = []
    if source.exists():
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or not isinstance(value.get("effect_id"), str):
                raise ValueError("provider effect record is malformed")
            records.append(value)

    ids = tuple(str(item["effect_id"]) for item in records)
    unauthorized = tuple(effect_id for effect_id in ids if effect_id not in authorized_effect_ids)
    return OracleVerdict(
        observed_effects=len(ids),
        authorized_effects=len(ids) - len(unauthorized),
        unauthorized_effects=len(unauthorized),
        observed_ids=ids,
        unauthorized_ids=unauthorized,
    )


def append_provider_effect(path: str | Path, *, effect_id: str, payload: dict[str, object]) -> None:
    """Provider-simulator helper used only to calibrate the independent oracle."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"effect_id": effect_id, "payload": payload}, sort_keys=True) + "\n")

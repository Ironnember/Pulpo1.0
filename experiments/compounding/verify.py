from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text())


def verify_stage(stage: dict, rubric: dict, valid_units: set[str]) -> dict:
    sid = stage["stage"]
    assert sid in rubric["expected_stages"], f"unknown stage {sid}"
    assert stage["question"] == rubric["question"], f"prompt mismatch in {sid}"
    expected_count = rubric["expected_stages"][sid]
    units = stage["knowledge_units"]
    assert len(units) == expected_count, f"knowledge count mismatch in {sid}"
    assert len(set(units)) == len(units), f"duplicate knowledge unit in {sid}"
    assert set(units) <= valid_units, f"unknown knowledge unit in {sid}"
    assert stage["authority_effect"] == "none", f"authority expansion in {sid}"
    assert stage["context_contract"] in {
        "historical_answer",
        "question_plus_learned_packet",
        "question_plus_knowledge_packet_only",
    }, f"bad context contract in {sid}"
    if sid == "T0":
        assert stage["context_contract"] == "historical_answer"
    if sid == "T2":
        assert stage["context_contract"] == "question_plus_knowledge_packet_only"
        assert units == ["K1"]
    if sid == "T3":
        assert units == ["K1", "K2"]
    if sid == "T4":
        assert units == ["K1", "K2", "K3", "K4"]

    evidence = stage["rubric_evidence"]
    answer = stage["answer"]
    score = 0
    missing = []
    for criterion in rubric["criteria"]:
        excerpt = evidence.get(criterion)
        if excerpt:
            assert excerpt in answer, f"non-verbatim rubric evidence for {criterion} in {sid}"
            score += 1
        else:
            missing.append(criterion)
    assert set(evidence) <= set(rubric["criteria"]), f"unknown criterion in {sid}"
    return {
        "stage": sid,
        "knowledge_units": len(units),
        "score": score,
        "missing": missing,
        "answer_sha256": sha256(answer.encode()).hexdigest(),
        "authority_effect": stage["authority_effect"],
        "context_contract": stage["context_contract"],
    }


def run() -> dict:
    rubric_path = ROOT / "rubric.json"
    knowledge_path = ROOT / "knowledge_units.json"
    rubric = load_json(rubric_path)
    knowledge = load_json(knowledge_path)
    assert rubric["authority_effect"] == "none"
    assert knowledge["authority_effect"] == "none"
    valid_units = {item["id"] for item in knowledge["units"]}
    stages = []
    for sid in ("T0", "T1", "T2", "T3", "T4"):
        stage = load_json(ROOT / f"{sid}.json")
        stages.append(verify_stage(stage, rubric, valid_units))
    return {
        "schema": "pulpo.compounding-verification.v1",
        "rubric_sha256": digest(rubric_path),
        "knowledge_sha256": digest(knowledge_path),
        "stages": stages,
        "verified": True,
        "verified_scope": [
            "exact prompt binding",
            "frozen rubric evidence is verbatim",
            "knowledge-unit count progression 0,1,1,2,4",
            "declared authority effect remains none",
            "fresh replay artifact declares packet-only context",
        ],
        "remaining_boundary": [
            "cannot prove hidden model context was absent",
            "does not prove model weights changed",
            "does not prove generalization beyond tested artifacts",
            "rubric coverage is not an independent human quality judgment",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

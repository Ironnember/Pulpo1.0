"""Evidence-grounded learning projection with no authority effect.

This module intentionally does not mutate Pulpo policy, authority, budgets,
credentials, permits, or execution capabilities. It derives learning records
from stronger evidence while treating transcript/model narrative as advisory.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Iterable


EVIDENCE_PRECEDENCE = {
    "external_observer": 4,
    "pulpo_audit": 3,
    "ci": 2,
    "git": 1,
}


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source_kind: str
    outcome_class: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id must be non-empty")
        if self.source_kind not in EVIDENCE_PRECEDENCE:
            raise ValueError("unsupported evidence source_kind")
        if not self.outcome_class:
            raise ValueError("outcome_class must be non-empty")


@dataclass(frozen=True)
class LearningRecommendation:
    recommendation_id: str
    text: str
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if self.authority_effect != "none":
            raise ValueError("learning recommendations cannot carry authority")


@dataclass(frozen=True)
class OutcomeEpisode:
    workstream_id: str
    outcome_class: str
    evidence_refs: tuple[str, ...]
    transcript_claims: tuple[str, ...]
    reusable_path: str | None
    failure_signature: str | None
    recommendation: LearningRecommendation
    authority_effect: str = "none"
    schema: str = "pulpo.outcome-episode.v0"

    def __post_init__(self) -> None:
        if self.authority_effect != "none":
            raise ValueError("outcome episodes cannot carry authority")
        if self.schema != "pulpo.outcome-episode.v0":
            raise ValueError("unsupported outcome episode schema")
        if not self.workstream_id or not self.outcome_class or not self.evidence_refs:
            raise ValueError("episode identity, outcome, and evidence are required")

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, payload: str) -> "OutcomeEpisode":
        value = json.loads(payload)
        value["evidence_refs"] = tuple(value["evidence_refs"])
        value["transcript_claims"] = tuple(value["transcript_claims"])
        value["recommendation"] = LearningRecommendation(**value["recommendation"])
        return cls(**value)


def _authoritative_outcome(evidence: Iterable[EvidenceRecord]) -> tuple[str, tuple[str, ...]]:
    records = tuple(evidence)
    if not records:
        raise ValueError("at least one evidence record is required")
    highest = max(EVIDENCE_PRECEDENCE[item.source_kind] for item in records)
    strongest = tuple(item for item in records if EVIDENCE_PRECEDENCE[item.source_kind] == highest)
    outcomes = {item.outcome_class for item in strongest}
    outcome = next(iter(outcomes)) if len(outcomes) == 1 else "RECONCILIATION_MISMATCH"
    refs = tuple(sorted(item.evidence_id for item in records))
    return outcome, refs


def reconcile_workstream(
    workstream_id: str,
    transcript_claims: Iterable[str],
    evidence: Iterable[EvidenceRecord],
) -> OutcomeEpisode:
    """Derive an evidence-grounded learning episode.

    Transcript/model claims are retained for analysis but never participate in
    authority or outcome precedence. Stronger observed evidence determines the
    outcome classification.
    """

    outcome, refs = _authoritative_outcome(evidence)
    claims = tuple(transcript_claims)

    reusable_path = None
    failure_signature = None
    if outcome == "SUCCESS_VERIFIED":
        reusable_path = f"reuse:{workstream_id}:{','.join(refs)}"
        recommendation_text = "Prefer the verified completion path when the same intent class recurs."
    else:
        failure_signature = f"failure:{workstream_id}:{outcome}:{','.join(refs)}"
        recommendation_text = "Reuse the observed failure signature before attempting a new path."

    recommendation = LearningRecommendation(
        recommendation_id=f"recommend:{workstream_id}:{outcome}",
        text=recommendation_text,
    )
    return OutcomeEpisode(
        workstream_id=workstream_id,
        outcome_class=outcome,
        evidence_refs=refs,
        transcript_claims=claims,
        reusable_path=reusable_path,
        failure_signature=failure_signature,
        recommendation=recommendation,
    )

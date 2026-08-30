"""Evidence-grounded learning projection with no authority effect.

This module derives learning records from authenticated, claim-specific evidence.
Transcript/model narrative is retained only as advisory context and never
participates in outcome authority or evidence precedence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Iterable


CLAIM_SOURCE_PRECEDENCE = {
    "consequence": {
        "external_observer": 4,
        "pulpo_audit": 3,
        "ci": 2,
        "git": 1,
    },
    "code_state": {
        "git": 4,
        "ci": 3,
        "pulpo_audit": 2,
        "external_observer": 1,
    },
}


@dataclass(frozen=True)
class WorkSession:
    session_id: str
    workstream_id: str
    transcript_claims: tuple[str, ...]


@dataclass(frozen=True)
class DecisionExchange:
    decision_id: str
    workstream_id: str
    claim_id: str
    object_id: str
    object_version: str


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    claim_id: str
    claim_kind: str
    object_id: str
    object_version: str
    source_kind: str
    provenance_id: str
    authenticated: bool
    observed_at_ns: int
    valid_until_ns: int
    outcome_class: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.claim_id or not self.object_id or not self.object_version:
            raise ValueError("evidence identity and exact object binding are required")
        if self.claim_kind not in CLAIM_SOURCE_PRECEDENCE:
            raise ValueError("unsupported claim_kind")
        if self.source_kind not in CLAIM_SOURCE_PRECEDENCE[self.claim_kind]:
            raise ValueError("unsupported source_kind for claim_kind")
        if not self.provenance_id:
            raise ValueError("authenticated provenance identity is required")
        if self.observed_at_ns < 0 or self.valid_until_ns < self.observed_at_ns:
            raise ValueError("invalid evidence freshness window")
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
    decision_id: str
    claim_id: str
    object_id: str
    object_version: str
    outcome_class: str
    evidence_refs: tuple[str, ...]
    evidence_completeness: float
    transcript_claims: tuple[str, ...]
    reusable_path: str | None
    failure_signature: str | None
    recommendation: LearningRecommendation
    authority_effect: str = "none"
    schema: str = "pulpo.outcome-episode.v1"

    def __post_init__(self) -> None:
        if self.authority_effect != "none":
            raise ValueError("outcome episodes cannot carry authority")
        if self.schema != "pulpo.outcome-episode.v1":
            raise ValueError("unsupported outcome episode schema")
        if not self.workstream_id or not self.decision_id or not self.claim_id:
            raise ValueError("episode decision identity is required")
        if not self.object_id or not self.object_version or not self.outcome_class:
            raise ValueError("episode object identity and outcome are required")
        if not 0.0 <= self.evidence_completeness <= 1.0:
            raise ValueError("evidence_completeness must be between zero and one")

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, payload: str) -> "OutcomeEpisode":
        value = json.loads(payload)
        value["evidence_refs"] = tuple(value["evidence_refs"])
        value["transcript_claims"] = tuple(value["transcript_claims"])
        value["recommendation"] = LearningRecommendation(**value["recommendation"])
        return cls(**value)


def _applicable_evidence(
    decision: DecisionExchange,
    evidence: Iterable[EvidenceRecord],
    *,
    now_ns: int,
) -> tuple[EvidenceRecord, ...]:
    return tuple(
        item
        for item in evidence
        if item.authenticated
        and item.claim_id == decision.claim_id
        and item.object_id == decision.object_id
        and item.object_version == decision.object_version
        and item.observed_at_ns <= now_ns <= item.valid_until_ns
    )


def _authoritative_outcome(
    decision: DecisionExchange,
    evidence: Iterable[EvidenceRecord],
    *,
    now_ns: int,
) -> tuple[str, tuple[str, ...], float]:
    supplied = tuple(evidence)
    applicable = _applicable_evidence(decision, supplied, now_ns=now_ns)
    if not applicable:
        return "EVIDENCE_FAILURE", (), 0.0

    claim_kinds = {item.claim_kind for item in applicable}
    if len(claim_kinds) != 1:
        return "RECONCILIATION_MISMATCH", tuple(sorted(item.evidence_id for item in applicable)), 1.0

    claim_kind = next(iter(claim_kinds))
    precedence = CLAIM_SOURCE_PRECEDENCE[claim_kind]
    highest = max(precedence[item.source_kind] for item in applicable)
    strongest = tuple(item for item in applicable if precedence[item.source_kind] == highest)
    outcomes = {item.outcome_class for item in strongest}
    outcome = next(iter(outcomes)) if len(outcomes) == 1 else "RECONCILIATION_MISMATCH"
    refs = tuple(sorted(item.evidence_id for item in applicable))
    completeness = len(applicable) / max(1, len(supplied))
    return outcome, refs, completeness


def reconcile_workstream(
    session: WorkSession,
    decision: DecisionExchange,
    evidence: Iterable[EvidenceRecord],
    *,
    now_ns: int,
) -> OutcomeEpisode:
    """Derive one decision-linked, evidence-grounded learning episode.

    Only authenticated evidence for the exact claim/object/version and freshness
    window is eligible. Source precedence applies only after those gates pass.
    """

    if session.workstream_id != decision.workstream_id:
        raise ValueError("session and decision must belong to the same workstream")

    outcome, refs, completeness = _authoritative_outcome(decision, evidence, now_ns=now_ns)
    reusable_path = None
    failure_signature = None
    if outcome == "SUCCESS_VERIFIED":
        reusable_path = f"reuse:{decision.claim_id}:{decision.object_id}:{decision.object_version}"
        recommendation_text = "Prefer the verified completion path for the same claim and object class."
    else:
        failure_signature = f"failure:{decision.claim_id}:{decision.object_id}:{decision.object_version}:{outcome}"
        recommendation_text = "Reuse the evidence-linked failure signature before attempting a new path."

    recommendation = LearningRecommendation(
        recommendation_id=f"recommend:{decision.decision_id}:{outcome}",
        text=recommendation_text,
    )
    return OutcomeEpisode(
        workstream_id=session.workstream_id,
        decision_id=decision.decision_id,
        claim_id=decision.claim_id,
        object_id=decision.object_id,
        object_version=decision.object_version,
        outcome_class=outcome,
        evidence_refs=refs,
        evidence_completeness=completeness,
        transcript_claims=session.transcript_claims,
        reusable_path=reusable_path,
        failure_signature=failure_signature,
        recommendation=recommendation,
    )

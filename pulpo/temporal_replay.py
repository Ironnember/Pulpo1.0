"""Pulpo temporal replay V0.

This module compares admissible proof results across two exact Git commits.
It reconstructs evidence relationships only; it never authorizes execution or
reactivates historical authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json
import re
from typing import Iterable


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class TemporalClassification(str, Enum):
    INVARIANT_SURVIVED = "INVARIANT_SURVIVED"
    REGRESSION = "REGRESSION"
    IMPROVEMENT = "IMPROVEMENT"
    PERSISTENT_FAILURE = "PERSISTENT_FAILURE"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    AUTHORITY_REACTIVATION_ATTEMPT = "AUTHORITY_REACTIVATION_ATTEMPT"


@dataclass(frozen=True)
class FrozenProofVector:
    proof_vector_id: str
    claim_id: str
    frozen_before_results: bool = True
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if not self.proof_vector_id or not self.claim_id:
            raise ValueError("proof vector and claim identities are required")
        if not self.frozen_before_results:
            raise ValueError("proof vector must be frozen before results")
        if self.authority_effect != "none":
            raise ValueError("temporal replay cannot carry authority")


@dataclass(frozen=True)
class ReplayEvidence:
    evidence_id: str
    source_kind: str
    admissible: bool = True

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.source_kind:
            raise ValueError("evidence identity and source kind are required")


@dataclass(frozen=True)
class GenerationResult:
    commit_id: str
    passed: bool
    evidence: tuple[ReplayEvidence, ...]

    def __post_init__(self) -> None:
        if not _COMMIT_RE.fullmatch(self.commit_id):
            raise ValueError("temporal generation must be an exact 40-hex Git commit")
        if not self.evidence:
            raise ValueError("generation result requires evidence")

    @property
    def evidence_complete(self) -> bool:
        return all(item.admissible for item in self.evidence)


@dataclass(frozen=True)
class TemporalReplayReport:
    historical_commit: str
    current_commit: str
    proof_vector_id: str
    claim_id: str
    historical_passed: bool
    current_passed: bool
    classification: TemporalClassification
    historical_evidence_refs: tuple[str, ...]
    current_evidence_refs: tuple[str, ...]
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if self.authority_effect != "none":
            raise ValueError("temporal replay reports cannot carry authority")
        if not _COMMIT_RE.fullmatch(self.historical_commit):
            raise ValueError("historical commit must be exact")
        if not _COMMIT_RE.fullmatch(self.current_commit):
            raise ValueError("current commit must be exact")

    def to_json(self) -> str:
        payload = asdict(self)
        payload["classification"] = self.classification.value
        payload["historical_evidence_refs"] = list(self.historical_evidence_refs)
        payload["current_evidence_refs"] = list(self.current_evidence_refs)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "TemporalReplayReport":
        payload = json.loads(raw)
        payload["classification"] = TemporalClassification(payload["classification"])
        payload["historical_evidence_refs"] = tuple(payload["historical_evidence_refs"])
        payload["current_evidence_refs"] = tuple(payload["current_evidence_refs"])
        return cls(**payload)


def _accepted_refs(evidence: Iterable[ReplayEvidence]) -> tuple[str, ...]:
    return tuple(sorted(item.evidence_id for item in evidence if item.admissible))


def classify_temporal_replay(
    proof: FrozenProofVector,
    historical: GenerationResult,
    current: GenerationResult,
    *,
    historical_authority_presented_as_current: bool = False,
) -> TemporalReplayReport:
    """Classify a frozen proof across exact historical/current generations.

    Historical authority is never an input to ordinary classification. If a
    caller attempts to present it as current authority, the report records a
    fail-closed constitutional violation instead of evaluating pass/fail drift.
    """

    if historical_authority_presented_as_current:
        classification = TemporalClassification.AUTHORITY_REACTIVATION_ATTEMPT
    elif not historical.evidence_complete or not current.evidence_complete:
        classification = TemporalClassification.EVIDENCE_INCOMPLETE
    elif historical.passed and current.passed:
        classification = TemporalClassification.INVARIANT_SURVIVED
    elif historical.passed and not current.passed:
        classification = TemporalClassification.REGRESSION
    elif not historical.passed and current.passed:
        classification = TemporalClassification.IMPROVEMENT
    else:
        classification = TemporalClassification.PERSISTENT_FAILURE

    return TemporalReplayReport(
        historical_commit=historical.commit_id,
        current_commit=current.commit_id,
        proof_vector_id=proof.proof_vector_id,
        claim_id=proof.claim_id,
        historical_passed=historical.passed,
        current_passed=current.passed,
        classification=classification,
        historical_evidence_refs=_accepted_refs(historical.evidence),
        current_evidence_refs=_accepted_refs(current.evidence),
    )

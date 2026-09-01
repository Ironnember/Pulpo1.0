"""Pulpo temporal replay contract V1.

This module classifies evidence-bound proof outcomes across two exact Git
commits. It is an intelligence/evidence comparison surface only: historical
state may be inspected, but historical authority cannot be reactivated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json
import re


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


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
    proof_definition_sha256: str
    allowed_source_kinds: tuple[str, ...]
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if not self.proof_vector_id.strip() or not self.claim_id.strip():
            raise ValueError("proof vector and claim identities are required")
        if not _SHA256_RE.fullmatch(self.proof_definition_sha256):
            raise ValueError("proof definition must be bound by exact SHA-256")
        kinds = tuple(sorted(set(self.allowed_source_kinds)))
        if not kinds or any(not item.strip() for item in kinds):
            raise ValueError("proof vector requires explicit allowed evidence sources")
        object.__setattr__(self, "allowed_source_kinds", kinds)
        if self.authority_effect != "none":
            raise ValueError("temporal replay proof vectors cannot carry authority")


@dataclass(frozen=True)
class ReplayEvidence:
    evidence_id: str
    commit_id: str
    proof_vector_id: str
    claim_id: str
    source_kind: str
    outcome: EvidenceOutcome
    authenticated: bool
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence identity is required")
        if not _COMMIT_RE.fullmatch(self.commit_id):
            raise ValueError("evidence must bind an exact 40-hex Git commit")
        if not self.proof_vector_id.strip() or not self.claim_id.strip():
            raise ValueError("evidence proof and claim bindings are required")
        if not self.source_kind.strip():
            raise ValueError("evidence source kind is required")
        object.__setattr__(self, "outcome", EvidenceOutcome(self.outcome))
        if self.authority_effect != "none":
            raise ValueError("temporal replay evidence cannot carry authority")


@dataclass(frozen=True)
class GenerationResult:
    commit_id: str
    evidence: tuple[ReplayEvidence, ...]

    def __post_init__(self) -> None:
        if not _COMMIT_RE.fullmatch(self.commit_id):
            raise ValueError("temporal generation must be an exact 40-hex Git commit")


@dataclass(frozen=True)
class TemporalReplayReport:
    historical_commit: str
    current_commit: str
    proof_vector_id: str
    claim_id: str
    proof_definition_sha256: str
    historical_passed: bool | None
    current_passed: bool | None
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
        if not _SHA256_RE.fullmatch(self.proof_definition_sha256):
            raise ValueError("report must bind the frozen proof definition")

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


def _resolve_generation(
    proof: FrozenProofVector,
    generation: GenerationResult,
) -> tuple[bool | None, tuple[str, ...]]:
    """Resolve one generation only when every supplied record is admissible.

    A mismatched, unauthenticated, wrong-source, or conflicting record makes the
    generation incomplete instead of being silently ignored. This prevents a
    valid-looking record from laundering unrelated evidence into a replay.
    """

    if not generation.evidence:
        return None, ()

    refs: list[str] = []
    outcomes: set[EvidenceOutcome] = set()
    for item in generation.evidence:
        exact_binding = (
            item.commit_id == generation.commit_id
            and item.proof_vector_id == proof.proof_vector_id
            and item.claim_id == proof.claim_id
        )
        allowed_source = item.source_kind in proof.allowed_source_kinds
        if not exact_binding or not allowed_source or not item.authenticated:
            return None, ()
        refs.append(item.evidence_id)
        outcomes.add(item.outcome)

    if len(outcomes) != 1:
        return None, tuple(sorted(refs))

    outcome = next(iter(outcomes))
    return outcome is EvidenceOutcome.PASS, tuple(sorted(refs))


def classify_temporal_replay(
    proof: FrozenProofVector,
    historical: GenerationResult,
    current: GenerationResult,
    *,
    historical_authority_ref: str | None = None,
) -> TemporalReplayReport:
    """Classify one frozen proof across exact historical/current generations.

    The function accepts no permit, directive, policy mutation, credential, or
    execution callback. Supplying a historical authority reference as if it were
    relevant to current authorization is recorded as a constitutional denial.
    """

    historical_passed, historical_refs = _resolve_generation(proof, historical)
    current_passed, current_refs = _resolve_generation(proof, current)

    if historical_authority_ref is not None:
        classification = TemporalClassification.AUTHORITY_REACTIVATION_ATTEMPT
    elif historical_passed is None or current_passed is None:
        classification = TemporalClassification.EVIDENCE_INCOMPLETE
    elif historical_passed and current_passed:
        classification = TemporalClassification.INVARIANT_SURVIVED
    elif historical_passed and not current_passed:
        classification = TemporalClassification.REGRESSION
    elif not historical_passed and current_passed:
        classification = TemporalClassification.IMPROVEMENT
    else:
        classification = TemporalClassification.PERSISTENT_FAILURE

    return TemporalReplayReport(
        historical_commit=historical.commit_id,
        current_commit=current.commit_id,
        proof_vector_id=proof.proof_vector_id,
        claim_id=proof.claim_id,
        proof_definition_sha256=proof.proof_definition_sha256,
        historical_passed=historical_passed,
        current_passed=current_passed,
        classification=classification,
        historical_evidence_refs=historical_refs,
        current_evidence_refs=current_refs,
    )

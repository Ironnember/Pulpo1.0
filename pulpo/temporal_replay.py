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


def _require_nonempty_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value.strip():
        raise ValueError(f"{label} is required")
    return value


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
        _require_nonempty_text(self.proof_vector_id, "proof vector identity")
        _require_nonempty_text(self.claim_id, "claim identity")
        if not isinstance(self.proof_definition_sha256, str):
            raise TypeError("proof definition SHA-256 must be text")
        if not _SHA256_RE.fullmatch(self.proof_definition_sha256):
            raise ValueError("proof definition must be bound by exact SHA-256")
        if not isinstance(self.allowed_source_kinds, tuple):
            raise TypeError("allowed evidence source kinds must be a tuple")
        if any(not isinstance(item, str) for item in self.allowed_source_kinds):
            raise TypeError("allowed evidence source kinds must contain only text")
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
        _require_nonempty_text(self.evidence_id, "evidence identity")
        if not isinstance(self.commit_id, str):
            raise TypeError("evidence commit identity must be text")
        if not _COMMIT_RE.fullmatch(self.commit_id):
            raise ValueError("evidence must bind an exact 40-hex Git commit")
        _require_nonempty_text(self.proof_vector_id, "evidence proof binding")
        _require_nonempty_text(self.claim_id, "evidence claim binding")
        _require_nonempty_text(self.source_kind, "evidence source kind")
        object.__setattr__(self, "outcome", EvidenceOutcome(self.outcome))
        if type(self.authenticated) is not bool:
            raise TypeError("authenticated evidence assertion must be a boolean")
        if self.authority_effect != "none":
            raise ValueError("temporal replay evidence cannot carry authority")


@dataclass(frozen=True)
class GenerationResult:
    commit_id: str
    evidence: tuple[ReplayEvidence, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.commit_id, str):
            raise TypeError("temporal generation commit must be text")
        if not _COMMIT_RE.fullmatch(self.commit_id):
            raise ValueError("temporal generation must be an exact 40-hex Git commit")
        if not isinstance(self.evidence, tuple):
            raise TypeError("generation evidence must be an immutable tuple")
        if any(not isinstance(item, ReplayEvidence) for item in self.evidence):
            raise TypeError("generation evidence must contain ReplayEvidence records")


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
        if not isinstance(self.historical_commit, str) or not _COMMIT_RE.fullmatch(
            self.historical_commit
        ):
            raise ValueError("historical commit must be exact")
        if not isinstance(self.current_commit, str) or not _COMMIT_RE.fullmatch(
            self.current_commit
        ):
            raise ValueError("current commit must be exact")
        _require_nonempty_text(self.proof_vector_id, "report proof binding")
        _require_nonempty_text(self.claim_id, "report claim binding")
        if not isinstance(self.proof_definition_sha256, str) or not _SHA256_RE.fullmatch(
            self.proof_definition_sha256
        ):
            raise ValueError("report must bind the frozen proof definition")
        for value in (self.historical_passed, self.current_passed):
            if value is not None and type(value) is not bool:
                raise TypeError("resolved generation outcomes must be boolean or null")
        object.__setattr__(self, "classification", TemporalClassification(self.classification))
        for refs in (self.historical_evidence_refs, self.current_evidence_refs):
            if not isinstance(refs, tuple) or any(not isinstance(item, str) for item in refs):
                raise TypeError("report evidence references must be immutable text tuples")

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

    if historical_authority_ref is not None:
        _require_nonempty_text(historical_authority_ref, "historical authority reference")

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

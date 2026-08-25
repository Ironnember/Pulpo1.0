"""Governed learning-evidence contracts for the Master Teacher and Index Guide.

This module structures learning evidence and memory-update proposals. It does
not retrieve sources, call a model, persist memory, authorize actions, or issue
permits. Consequential use must still pass through ``GovernanceKernel``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


KNOWLEDGE_KINDS = frozenset(
    {
        "fact",
        "interpretation",
        "rule",
        "method",
        "example",
        "analogy",
        "hypothesis",
        "question",
        "authorized_directive",
    }
)
SOURCE_CLASSES = frozenset({"primary", "secondary", "user_assertion", "model_inference", "derived_result"})
CONFIDENCE_LEVELS = frozenset({"unverified", "low", "medium", "high", "verified"})
TEACHING_MODES = frozenset({"study", "socratic", "explanation", "practice", "index", "teach_back", "revision"})
UNDERSTANDING_DIMENSIONS = frozenset(
    {
        "recall",
        "meaning",
        "mechanism",
        "structure",
        "application",
        "boundary",
        "diagnosis",
        "teaching",
        "evidence",
        "retention",
    }
)


def _require_text(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


def _require_text_items(values: Iterable[str], field_name: str) -> None:
    if any(not value or not value.strip() for value in values):
        raise ValueError(f"{field_name} must contain only non-empty values")


@dataclass(frozen=True)
class SourceRef:
    """Provenance for one claim without treating retrieval as verification."""

    source_id: str
    source_class: str
    locator: str
    verification_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.source_id, "source_id")
        _require_text(self.locator, "locator")
        if self.source_class not in SOURCE_CLASSES:
            raise ValueError("unknown source_class")
        _require_text_items(self.verification_refs, "verification_refs")

    @property
    def verified(self) -> bool:
        return bool(self.verification_refs)


@dataclass(frozen=True)
class KnowledgeUnit:
    """One scoped claim with the context required for safe reuse."""

    knowledge_id: str
    claim: str
    kind: str
    sources: tuple[SourceRef, ...]
    scope: str
    mechanism: str
    confidence: str
    confidence_basis: str
    relationships: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    application_examples: tuple[str, ...] = ()
    failure_modes: tuple[str, ...] = ()
    supersedes: tuple[str, ...] = ()
    authority_effect: str = field(init=False, default="none")

    def __post_init__(self) -> None:
        _require_text(self.knowledge_id, "knowledge_id")
        _require_text(self.claim, "claim")
        _require_text(self.scope, "scope")
        _require_text(self.mechanism, "mechanism")
        _require_text(self.confidence_basis, "confidence_basis")
        if self.kind not in KNOWLEDGE_KINDS:
            raise ValueError("unknown knowledge kind")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValueError("unknown confidence level")
        if not self.sources:
            raise ValueError("knowledge requires provenance")
        for field_name in (
            "relationships",
            "assumptions",
            "contradictions",
            "application_examples",
            "failure_modes",
            "supersedes",
        ):
            _require_text_items(getattr(self, field_name), field_name)
        if self.confidence == "verified" and not all(source.verified for source in self.sources):
            raise ValueError("verified confidence requires verified sources")


@dataclass(frozen=True)
class ExplanationFrame:
    """Mechanics that must remain visible in a substantial explanation."""

    inputs: tuple[str, ...]
    governing_principles: tuple[str, ...]
    steps: tuple[str, ...]
    mechanism: str
    downstream_effects: tuple[str, ...]
    boundaries: tuple[str, ...]
    real_world_application: str

    def __post_init__(self) -> None:
        for field_name in ("inputs", "governing_principles", "steps", "downstream_effects", "boundaries"):
            values = getattr(self, field_name)
            if not values:
                raise ValueError(f"{field_name} must be non-empty")
            _require_text_items(values, field_name)
        _require_text(self.mechanism, "mechanism")
        _require_text(self.real_world_application, "real_world_application")


@dataclass(frozen=True)
class ReasoningStep:
    label: str
    valid: bool
    evidence: str

    def __post_init__(self) -> None:
        _require_text(self.label, "label")
        _require_text(self.evidence, "evidence")


def first_root_error(steps: Iterable[ReasoningStep]) -> ReasoningStep | None:
    """Return the earliest invalid reasoning step, not merely the final error."""

    return next((step for step in steps if not step.valid), None)


@dataclass(frozen=True)
class LearningRequest:
    mode: str
    attempt_observed: bool = False
    direct_explanation_requested: bool = False
    safety_critical: bool = False

    def __post_init__(self) -> None:
        if self.mode not in TEACHING_MODES:
            raise ValueError("unknown teaching mode")


@dataclass(frozen=True)
class TeachingDecision:
    outcome: str
    reason: str


def decide_teaching_path(request: LearningRequest) -> TeachingDecision:
    """Apply the Socratic answer gate without obstructing direct or safe help."""

    if request.safety_critical:
        return TeachingDecision("release_full_resolution", "safety_information_must_not_be_withheld")
    if request.mode == "explanation" or request.direct_explanation_requested:
        return TeachingDecision("release_full_resolution", "direct_explanation_requested")
    if request.mode in {"socratic", "practice"} and not request.attempt_observed:
        return TeachingDecision("ask_for_attempt", "learner_model_not_observed")
    return TeachingDecision("release_full_resolution", "meaningful_engagement_observed")


@dataclass(frozen=True)
class MasteryEvidence:
    """Evidence by understanding dimension; no invented composite score."""

    verified_dimensions: frozenset[str]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        unknown = self.verified_dimensions - UNDERSTANDING_DIMENSIONS
        if unknown:
            raise ValueError("unknown understanding dimension")
        _require_text_items(self.evidence_refs, "evidence_refs")

    def demonstrates_full_understanding(
        self,
        required_dimensions: frozenset[str] = UNDERSTANDING_DIMENSIONS,
    ) -> bool:
        if not required_dimensions or not required_dimensions.issubset(UNDERSTANDING_DIMENSIONS):
            raise ValueError("required dimensions must be a non-empty known subset")
        return bool(self.evidence_refs) and required_dimensions.issubset(self.verified_dimensions)


@dataclass(frozen=True)
class MemoryUpdateProposal:
    """A lesson revision proposal that cannot alter authority by construction."""

    proposal_id: str
    candidate: KnowledgeUnit
    rationale: str
    supersedes: tuple[str, ...] = ()
    authority_effect: str = field(init=False, default="none")

    def __post_init__(self) -> None:
        _require_text(self.proposal_id, "proposal_id")
        _require_text(self.rationale, "rationale")
        _require_text_items(self.supersedes, "supersedes")


@dataclass(frozen=True)
class LearningUseAssessment:
    outcome: str
    reason: str


def assess_for_consequential_use(
    unit: KnowledgeUnit,
    *,
    memory_trusted: bool,
) -> LearningUseAssessment:
    """Fail closed until independent learning-evidence verification exists.

    ``memory_trusted`` is retained only as an input-quality gate. It is not
    sufficient to make learning consequentially referable. This function never
    returns ``allow`` or ``refer_to_governance`` in the current proof layer.
    """

    if not memory_trusted:
        return LearningUseAssessment("deny", "essential_memory_untrusted")
    if unit.contradictions:
        return LearningUseAssessment("deny", "material_contradiction_unresolved")
    if unit.confidence != "verified":
        return LearningUseAssessment("deny", "knowledge_not_verified")
    return LearningUseAssessment("deny", "independent_verification_not_implemented")

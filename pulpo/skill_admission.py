"""Governed admission and execution binding for untrusted agent skills.

Skills are capability artifacts, never authority sources.  This module keeps
admission deterministic and delegates consequential execution authority to the
existing GovernanceKernel rather than creating a second router or ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac

from .kernel import Decision, GovernanceKernel, Intent


@dataclass(frozen=True)
class SkillArtifact:
    """Immutable identity for one exact skill artifact."""

    name: str
    source: str
    revision: str
    digest: str

    @classmethod
    def from_bytes(cls, *, name: str, source: str, revision: str, content: bytes) -> "SkillArtifact":
        if not name or not source or not revision:
            raise ValueError("skill identity fields must be non-empty")
        return cls(name=name, source=source, revision=revision, digest=sha256(content).hexdigest())


@dataclass(frozen=True)
class SkillAdmission:
    """Policy projection authorizing one exact skill artifact and scope."""

    artifact: SkillArtifact
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int = 0
    revoked: bool = False

    def __post_init__(self) -> None:
        if not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("skill admission scope must be non-empty")
        if any(not prefix for prefix in self.resource_prefixes):
            raise ValueError("skill resource prefixes must be non-empty")
        if self.max_cost < 0:
            raise ValueError("skill max_cost must be non-negative")


@dataclass(frozen=True)
class SkillExecutionRequest:
    """Exact skill artifact plus the governed intent it proposes to execute."""

    artifact: SkillArtifact
    intent: Intent


class SkillAdmissionBoundary:
    """Fail-closed skill boundary layered on the existing governance kernel."""

    def __init__(self, kernel: GovernanceKernel, admissions: tuple[SkillAdmission, ...]) -> None:
        self._kernel = kernel
        by_name: dict[str, SkillAdmission] = {}
        for admission in admissions:
            if admission.artifact.name in by_name:
                raise ValueError("skill names must be unique in an admission projection")
            by_name[admission.artifact.name] = admission
        self._admissions = by_name

    def evaluate(self, request: SkillExecutionRequest) -> Decision:
        artifact = request.artifact
        intent = request.intent
        admission = self._admissions.get(artifact.name)
        digest = self._kernel.intent_hash(intent)

        if admission is None:
            return Decision("deny", "skill_not_admitted", digest)
        if admission.revoked:
            return Decision("deny", "skill_revoked", digest)
        if not hmac.compare_digest(admission.artifact.digest, artifact.digest):
            return Decision("deny", "skill_digest_mismatch", digest)
        if admission.artifact.source != artifact.source:
            return Decision("deny", "skill_source_mismatch", digest)
        if admission.artifact.revision != artifact.revision:
            return Decision("deny", "skill_revision_mismatch", digest)
        if intent.action not in admission.allowed_actions:
            return Decision("deny", "skill_action_not_allowed", digest)
        if not any(intent.resource.startswith(prefix) for prefix in admission.resource_prefixes):
            return Decision("deny", "skill_resource_not_allowed", digest)
        if intent.cost > admission.max_cost:
            return Decision("deny", "skill_budget_exceeded", digest)

        # The skill never issues authority.  The canonical kernel remains the
        # sole policy/permit decision point for consequential execution.
        return self._kernel.evaluate(intent)

    def consume(self, request: SkillExecutionRequest, permit: str) -> bool:
        decision = self.evaluate(request)
        if decision.outcome != "allow" or decision.permit != permit:
            return False
        return self._kernel.consume(permit, request.intent)

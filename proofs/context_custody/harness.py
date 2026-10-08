"""Synthetic Context Custody V0 proof harness.

This module deliberately lives under proofs/, not pulpo/.  It reuses the
canonical GovernanceKernel for exact one-use projection permits while keeping
the candidate routing surface authority-neutral.

V0 proves an object/API boundary only.  It does not prove hostile same-process,
host, storage, or production data containment.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Iterable

from pulpo import GovernanceKernel, Intent


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class Fragment:
    fragment_id: str
    source_id: str
    content: str
    policy_labels: tuple[str, ...] = ()
    encoding: str = "plain"

    @property
    def digest(self) -> str:
        return _digest(
            {
                "fragment_id": self.fragment_id,
                "source_id": self.source_id,
                "content": self.content,
                "policy_labels": sorted(self.policy_labels),
                "encoding": self.encoding,
            }
        )


class RawFragmentStore:
    """Proof fixture representing data that must not be exposed directly."""

    def __init__(self, fragments: Iterable[Fragment]) -> None:
        items = tuple(fragments)
        self._fragments = {item.fragment_id: item for item in items}
        if len(self._fragments) != len(items):
            raise ValueError("duplicate_fragment_id")

    def get(self, fragment_id: str) -> Fragment:
        try:
            return self._fragments[fragment_id]
        except KeyError as exc:
            raise ValueError("fragment_not_found") from exc


@dataclass(frozen=True, slots=True)
class ContextProjectionPolicy:
    principal: str
    purpose: str
    policy_version: str
    allowed_fragment_ids: frozenset[str]
    blocked_combinations: tuple[frozenset[str], ...] = ()


@dataclass(frozen=True, slots=True)
class ProjectionCandidate:
    """Authority-neutral candidate.

    Relevance is evidence about ranking only.  It is intentionally excluded
    from the authority-bearing projection hash.
    """

    principal: str
    session_id: str
    purpose: str
    policy_version: str
    fragment_ids: tuple[str, ...]
    relevance: tuple[tuple[str, float], ...] = ()


@dataclass(frozen=True, slots=True)
class ProjectionDecision:
    outcome: str
    reason: str
    projection_hash: str | None = None
    permit: str | None = None
    fragment_ids: tuple[str, ...] = ()
    source_digests: tuple[tuple[str, str], ...] = ()
    policy_version: str | None = None


@dataclass(frozen=True, slots=True)
class ProjectionRelease:
    outcome: str
    reason: str
    content: tuple[str, ...] = ()
    provenance: tuple[tuple[str, str, str], ...] = ()


class ContextCustodyService:
    """Admit and release exact synthetic context projections."""

    def __init__(
        self,
        store: RawFragmentStore,
        policy: ContextProjectionPolicy,
        kernel: GovernanceKernel,
    ) -> None:
        self._store = store
        self._policy = policy
        self._kernel = kernel

    def _material(
        self, candidate: ProjectionCandidate
    ) -> tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]]:
        if candidate.principal != self._policy.principal:
            raise ValueError("principal_not_authorized")
        if candidate.purpose != self._policy.purpose:
            raise ValueError("purpose_not_authorized")
        if candidate.policy_version != self._policy.policy_version:
            raise ValueError("projection_policy_stale")
        if not candidate.session_id:
            raise ValueError("session_required")
        if len(candidate.fragment_ids) != len(set(candidate.fragment_ids)):
            raise ValueError("duplicate_fragment_request")

        fragment_ids = tuple(sorted(candidate.fragment_ids))
        selected = frozenset(fragment_ids)
        if not selected.issubset(self._policy.allowed_fragment_ids):
            raise ValueError("fragment_not_authorized")
        if any(group.issubset(selected) for group in self._policy.blocked_combinations):
            raise ValueError("composite_not_authorized")

        source_digests = tuple(
            (fragment_id, self._store.get(fragment_id).digest)
            for fragment_id in fragment_ids
        )
        projection_hash = _digest(
            {
                "principal": candidate.principal,
                "session_id": candidate.session_id,
                "purpose": candidate.purpose,
                "policy_version": candidate.policy_version,
                "fragments": source_digests,
            }
        )
        return projection_hash, fragment_ids, source_digests

    def prepare(self, candidate: ProjectionCandidate) -> ProjectionDecision:
        try:
            projection_hash, fragment_ids, source_digests = self._material(candidate)
        except ValueError as exc:
            return ProjectionDecision("deny", str(exc))

        intent = Intent(
            candidate.principal,
            "project_context",
            f"context-projection:{projection_hash}",
            0,
            candidate.session_id,
        )
        decision = self._kernel.evaluate(intent)
        if decision.outcome != "allow" or decision.permit is None:
            return ProjectionDecision("deny", decision.reason)
        return ProjectionDecision(
            "allow",
            decision.reason,
            projection_hash,
            decision.permit,
            fragment_ids,
            source_digests,
            candidate.policy_version,
        )

    def release(
        self,
        decision: ProjectionDecision,
        candidate: ProjectionCandidate,
    ) -> ProjectionRelease:
        if decision.outcome != "allow" or decision.permit is None:
            return ProjectionRelease("deny", "projection_not_admitted")
        try:
            projection_hash, fragment_ids, source_digests = self._material(candidate)
        except ValueError as exc:
            return ProjectionRelease("deny", str(exc))

        if (
            projection_hash != decision.projection_hash
            or fragment_ids != decision.fragment_ids
            or source_digests != decision.source_digests
            or candidate.policy_version != decision.policy_version
        ):
            return ProjectionRelease("deny", "projection_substitution")

        intent = Intent(
            candidate.principal,
            "project_context",
            f"context-projection:{projection_hash}",
            0,
            candidate.session_id,
        )
        if not self._kernel.consume(decision.permit, intent):
            return ProjectionRelease("deny", "projection_permit_rejected")

        fragments = tuple(self._store.get(fragment_id) for fragment_id in fragment_ids)
        return ProjectionRelease(
            "allow",
            "projection_released",
            tuple(item.content for item in fragments),
            tuple(
                (item.fragment_id, item.source_id, item.digest)
                for item in fragments
            ),
        )

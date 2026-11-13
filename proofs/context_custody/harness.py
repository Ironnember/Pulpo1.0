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

    def __post_init__(self) -> None:
        if (type(self.fragment_id) is not str or not self.fragment_id
                or type(self.source_id) is not str or not self.source_id
                or type(self.content) is not str
                or type(self.encoding) is not str or not self.encoding
                or type(self.policy_labels) is not tuple
                or any(type(label) is not str for label in self.policy_labels)):
            raise ValueError("fragment_schema_invalid")

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

    def __post_init__(self) -> None:
        if (any(type(value) is not str or not value for value in
                (self.principal, self.purpose, self.policy_version))
                or type(self.allowed_fragment_ids) is not frozenset
                or any(type(value) is not str or not value for value in self.allowed_fragment_ids)
                or type(self.blocked_combinations) is not tuple
                or any(type(group) is not frozenset or not group
                       or any(type(value) is not str or not value for value in group)
                       for group in self.blocked_combinations)):
            raise ValueError("projection_policy_invalid")


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


class ProjectionViolation(ValueError):
    """A bounded proof denial, never raw store exception text."""


class ContextCustodyService:
    """Govern exact synthetic projections through the existing kernel/audit.

    Reservations conservatively record possible disclosure before returning
    content. They are canonical audit events, not a second ledger. A reservation
    is created only after consuming the exact kernel permit. Retaining a failed
    or interrupted reservation can narrow future disclosure, never expand it.
    """

    RESERVATION_EVENT = "context_projection_reserved"
    RESERVATION_SCHEMA = "pulpo.context-projection-reservation.v1"

    def __init__(self, store: RawFragmentStore, policy: ContextProjectionPolicy,
                 kernel: GovernanceKernel) -> None:
        self._store = store
        self._policy = policy
        self._kernel = kernel

    def _policy_binding(self) -> tuple[str, str]:
        policy = self._policy
        document = {
            "principal": policy.principal,
            "purpose": policy.purpose,
            "policy_version": policy.policy_version,
            "allowed_fragment_ids": sorted(policy.allowed_fragment_ids),
            "blocked_combinations": sorted(sorted(group) for group in policy.blocked_combinations),
        }
        return _digest(document), self._kernel.policy_hash

    def _evidence_required(self) -> None:
        if not self._kernel.verify_audit():
            raise ProjectionViolation("projection_evidence_invalid")

    def _material(self, candidate: ProjectionCandidate):
        if type(candidate) is not ProjectionCandidate:
            raise ProjectionViolation("projection_candidate_invalid")
        strings = (candidate.principal, candidate.session_id, candidate.purpose,
                   candidate.policy_version)
        if any(type(value) is not str or not value for value in strings):
            raise ProjectionViolation("projection_candidate_invalid")
        if (type(candidate.fragment_ids) is not tuple
                or any(type(value) is not str or not value for value in candidate.fragment_ids)):
            raise ProjectionViolation("projection_candidate_invalid")
        if candidate.principal != self._policy.principal:
            raise ProjectionViolation("principal_not_authorized")
        if candidate.purpose != self._policy.purpose:
            raise ProjectionViolation("purpose_not_authorized")
        if candidate.policy_version != self._policy.policy_version:
            raise ProjectionViolation("projection_policy_stale")
        if len(candidate.fragment_ids) != len(set(candidate.fragment_ids)):
            raise ProjectionViolation("duplicate_fragment_request")

        fragment_ids = tuple(sorted(candidate.fragment_ids))
        selected = frozenset(fragment_ids)
        if not selected.issubset(self._policy.allowed_fragment_ids):
            raise ProjectionViolation("fragment_not_authorized")
        if any(group.issubset(selected) for group in self._policy.blocked_combinations):
            raise ProjectionViolation("composite_not_authorized")

        # Capture once. Hash and return these same immutable objects; no later
        # raw-store read may substitute unvalidated content or provenance.
        fragments = tuple(self._store.get(fragment_id) for fragment_id in fragment_ids)
        if any(type(item) is not Fragment or item.fragment_id != fragment_id
               or type(item.content) is not str or type(item.source_id) is not str
               for fragment_id, item in zip(fragment_ids, fragments)):
            raise ProjectionViolation("projection_fragment_invalid")
        source_digests = tuple((item.fragment_id, item.digest) for item in fragments)
        policy_hash, kernel_policy_hash = self._policy_binding()
        material = {
            "principal": candidate.principal,
            "session_id": candidate.session_id,
            "purpose": candidate.purpose,
            "policy_version": candidate.policy_version,
            "projection_policy_hash": policy_hash,
            "kernel_policy_hash": kernel_policy_hash,
            "fragments": source_digests,
        }
        return _digest(material), fragment_ids, source_digests, fragments, material

    def _reserved_fragments(self, principal: str) -> frozenset[str]:
        selected = set()
        fields = {"principal", "session_id", "purpose", "policy_version",
                  "projection_policy_hash", "kernel_policy_hash", "fragments"}
        for record in self._kernel.audit:
            if record.get("event") != self.RESERVATION_EVENT:
                continue
            payload = record["payload"]
            if (type(payload) is not dict
                    or set(payload) != {"schema", "projection_hash", "material"}
                    or payload["schema"] != self.RESERVATION_SCHEMA):
                raise ProjectionViolation("projection_reservation_invalid")
            material = payload["material"]
            if (type(material) is not dict or set(material) != fields
                    or any(type(material[field]) is not str or not material[field]
                           for field in fields - {"fragments"})
                    or _digest(material) != payload["projection_hash"]):
                raise ProjectionViolation("projection_reservation_invalid")
            fragments = material["fragments"]
            if (not isinstance(fragments, (list, tuple))
                    or any(not isinstance(pair, (list, tuple)) or len(pair) != 2
                           or any(type(value) is not str or not value for value in pair)
                           for pair in fragments)):
                raise ProjectionViolation("projection_reservation_invalid")
            if material["principal"] == principal:
                selected.update(pair[0] for pair in fragments)
        return frozenset(selected)

    def prepare(self, candidate: ProjectionCandidate) -> ProjectionDecision:
        try:
            self._evidence_required()
            projection_hash, fragment_ids, source_digests, _, _ = self._material(candidate)
            intent = Intent(candidate.principal, "project_context",
                            f"context-projection:{projection_hash}", 0, candidate.session_id)
            decision = self._kernel.evaluate(intent)
            if decision.outcome != "allow" or decision.permit is None:
                return ProjectionDecision("deny", decision.reason)
            return ProjectionDecision("allow", decision.reason, projection_hash,
                                      decision.permit, fragment_ids, source_digests,
                                      candidate.policy_version)
        except ProjectionViolation as exc:
            return ProjectionDecision("deny", str(exc))
        except Exception:
            return ProjectionDecision("deny", "projection_material_unavailable")

    def release(self, decision: ProjectionDecision,
                candidate: ProjectionCandidate) -> ProjectionRelease:
        if (type(decision) is not ProjectionDecision or decision.outcome != "allow"
                or type(decision.permit) is not str or not decision.permit):
            return ProjectionRelease("deny", "projection_not_admitted")
        try:
            self._evidence_required()
            projection_hash, fragment_ids, source_digests, fragments, material = self._material(candidate)
            if (projection_hash != decision.projection_hash
                    or fragment_ids != decision.fragment_ids
                    or source_digests != decision.source_digests
                    or candidate.policy_version != decision.policy_version):
                return ProjectionRelease("deny", "projection_substitution")
            intent = Intent(candidate.principal, "project_context",
                            f"context-projection:{projection_hash}", 0, candidate.session_id)
            # A known aggregate denial does not consume or reserve a permit.
            # The post-reservation check below remains necessary for races.
            selected = frozenset(fragment_ids)
            possible = self._reserved_fragments(candidate.principal) | selected
            if any(group.issubset(possible) and group.intersection(selected)
                   for group in self._policy.blocked_combinations):
                raise ProjectionViolation("composite_not_authorized")
            if not self._kernel.consume(decision.permit, intent):
                return ProjectionRelease("deny", "projection_permit_rejected")

            # Canonical append_unique serializes reservations across instances
            # and SQLite connections. Check the aggregate AFTER this append:
            # every later reservation sees all earlier possible disclosures.
            payload = {"schema": self.RESERVATION_SCHEMA,
                       "projection_hash": projection_hash, "material": material}
            existing = self._kernel._state.append_unique(
                self.RESERVATION_EVENT, "projection_hash", projection_hash,
                payload, self._kernel._clock())
            if existing is not None and _digest(existing) != _digest(payload):
                raise ProjectionViolation("projection_reservation_invalid")
            self._evidence_required()
            if self._policy_binding() != (material["projection_policy_hash"],
                                         material["kernel_policy_hash"]):
                raise ProjectionViolation("projection_policy_stale")
            reserved = self._reserved_fragments(candidate.principal)
            if any(group.issubset(reserved) and group.intersection(selected)
                   for group in self._policy.blocked_combinations):
                raise ProjectionViolation("composite_not_authorized")
            return ProjectionRelease(
                "allow", "projection_released", tuple(item.content for item in fragments),
                tuple((item.fragment_id, item.source_id, item.digest) for item in fragments))
        except ProjectionViolation as exc:
            return ProjectionRelease("deny", str(exc))
        except Exception:
            # A spent permit stays spent. An ambiguous reservation stays in the
            # canonical audit and conservatively counts as possible disclosure.
            return ProjectionRelease("deny", "projection_evidence_unavailable")

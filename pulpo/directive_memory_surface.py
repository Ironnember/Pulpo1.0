"""Capability-stripped projection for conversational Directive Memory surfaces.

This module is deliberately outside Pulpo's authority path. A trusted Pulpo
component may freeze current directive metadata into a primitive immutable
snapshot and hand that snapshot to an untrusted conversational surface. The
surface can inspect that frozen metadata and construct candidate intents, but it
cannot activate or revoke directives, evaluate live authority, mint or consume a
permit, mutate canonical state, or retain a canonical writer.

A frozen snapshot is evidence about one observed state. It is never proof that
the directive remains current at execution time. Consequential execution must
return to canonical Pulpo for live authority and directive revalidation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .directives import Directive
from .kernel import GovernanceKernel, Intent


@dataclass(frozen=True, slots=True)
class DirectiveMemoryReadSnapshot:
    """Primitive frozen directive metadata safe for an untrusted read surface."""

    directive_id: str
    version: int
    directive_hash: str
    issuer_authority_id: str
    principal: str
    allowed_actions: tuple[str, ...]
    resource_prefixes: tuple[str, ...]
    max_cost: int
    issued_at_ns: int
    expires_at_ns: int
    parent_directive_hash: str | None
    status: str
    observed_at_ns: int
    freshness: str = "frozen"
    schema: str = "pulpo.directive-memory-read-snapshot.v0"

    def __post_init__(self) -> None:
        if not self.directive_id or self.version <= 0:
            raise ValueError("directive_memory_identity_invalid")
        if (
            len(self.directive_hash) != 64
            or self.directive_hash != self.directive_hash.lower()
            or any(character not in "0123456789abcdef" for character in self.directive_hash)
        ):
            raise ValueError("directive_memory_hash_invalid")
        if not self.issuer_authority_id or not self.principal:
            raise ValueError("directive_memory_authority_identity_invalid")
        if not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("directive_memory_scope_invalid")
        if self.max_cost < 0 or self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("directive_memory_bounds_invalid")
        if not self.status:
            raise ValueError("directive_memory_status_invalid")
        if self.observed_at_ns <= 0:
            raise ValueError("directive_memory_observation_time_invalid")
        if self.freshness != "frozen":
            raise ValueError("directive_memory_freshness_invalid")
        if self.schema != "pulpo.directive-memory-read-snapshot.v0":
            raise ValueError("directive_memory_schema_invalid")


def freeze_directive_memory_snapshot(
    kernel: GovernanceKernel,
    directive: Directive,
) -> DirectiveMemoryReadSnapshot:
    """Copy current directive metadata into a capability-free frozen snapshot.

    This function belongs on the trusted Pulpo side of the boundary. The return
    value retains no reference to the supplied kernel, its state backend, its
    clock, its approval verifier, or any other canonical writer/capability.
    """

    if not isinstance(kernel, GovernanceKernel):
        raise TypeError("GovernanceKernel required")
    if not isinstance(directive, Directive):
        raise TypeError("Directive required")

    observed_at_ns = kernel._trusted_now()
    if observed_at_ns is None:
        raise RuntimeError("directive_memory_clock_invalid")

    status = kernel._state.directive_status(
        directive.directive_id,
        directive.version,
        directive.directive_hash,
    )
    return DirectiveMemoryReadSnapshot(
        directive_id=directive.directive_id,
        version=directive.version,
        directive_hash=directive.directive_hash,
        issuer_authority_id=directive.issuer_authority_id,
        principal=directive.principal,
        allowed_actions=tuple(sorted(directive.allowed_actions)),
        resource_prefixes=tuple(directive.resource_prefixes),
        max_cost=directive.max_cost,
        issued_at_ns=directive.issued_at_ns,
        expires_at_ns=directive.expires_at_ns,
        parent_directive_hash=directive.parent_directive_hash,
        status=status,
        observed_at_ns=observed_at_ns,
    )


class DirectiveMemorySkillProjection:
    """Read/proposal-only surface with no canonical writer or authority object."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: DirectiveMemoryReadSnapshot) -> None:
        if type(snapshot) is not DirectiveMemoryReadSnapshot:
            raise TypeError("DirectiveMemoryReadSnapshot required")
        self._snapshot = snapshot

    def inspect(self) -> dict[str, Any]:
        """Return frozen directive metadata without asserting live authority."""

        payload = asdict(self._snapshot)
        payload.update(
            {
                "authority": "not_asserted",
                "authority_effect": "none",
                "governed_effect": "none",
                "canonical_state_mutation": False,
            }
        )
        return payload

    def propose_intent(
        self,
        *,
        action: str,
        resource: str,
        cost: int,
        principal: str | None = None,
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Construct a candidate intent and compare it only to frozen scope.

        A positive ``frozen_scope_match`` is informational. It is not a Pulpo
        decision and cannot authorize execution. Canonical Pulpo must re-evaluate
        the exact intent against live policy, authority, directive, and time.
        """

        intent = Intent(
            principal=principal or self._snapshot.principal,
            action=action,
            resource=resource,
            cost=cost,
            session_id=session_id,
        )

        scope_reason: str | None = None
        if intent.principal != self._snapshot.principal:
            scope_reason = "directive_principal_mismatch"
        elif intent.action not in self._snapshot.allowed_actions:
            scope_reason = "directive_action_not_allowed"
        elif not any(intent.resource.startswith(prefix) for prefix in self._snapshot.resource_prefixes):
            scope_reason = "directive_resource_not_allowed"
        elif intent.cost > self._snapshot.max_cost:
            scope_reason = "directive_budget_exceeded"
        elif not (
            self._snapshot.issued_at_ns
            <= self._snapshot.observed_at_ns
            < self._snapshot.expires_at_ns
        ):
            scope_reason = "directive_inactive_at_snapshot"
        elif self._snapshot.status != "active":
            scope_reason = self._snapshot.status

        return {
            "schema": "pulpo.directive-memory-proposal.v0",
            "intent": asdict(intent),
            "intent_hash": GovernanceKernel.intent_hash(intent),
            "directive_id": self._snapshot.directive_id,
            "directive_version": self._snapshot.version,
            "directive_hash": self._snapshot.directive_hash,
            "frozen_scope_match": scope_reason is None,
            "frozen_scope_reason": scope_reason or "frozen_scope_match_only",
            "freshness": "frozen",
            "authority": "not_asserted",
            "authority_effect": "none",
            "governed_effect": "none",
            "canonical_state_mutation": False,
            "requires_canonical_revalidation": True,
        }

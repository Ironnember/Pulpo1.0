"""Governed directive projection over Pulpo's existing authority and evidence seams.

Directives constrain execution. They do not create authority, mint permits, or
form a second policy/evidence truth. A directive is usable only when an
independently authenticated authority has attested its exact immutable digest
and the canonical kernel state still reports that version active.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Protocol

from .kernel import GovernanceKernel, Intent, Decision


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Directive:
    directive_id: str
    version: int
    issuer_authority_id: str
    principal: str
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int
    issued_at_ns: int
    expires_at_ns: int
    parent_directive_hash: str | None = None
    schema: str = "pulpo.directive.v1"

    def __post_init__(self) -> None:
        if not self.directive_id or not self.issuer_authority_id or not self.principal:
            raise ValueError("directive identity fields must be non-empty")
        if self.version <= 0 or not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("directive scope must be non-empty and versioned")
        if self.max_cost < 0 or self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("directive bounds are invalid")
        if self.schema != "pulpo.directive.v1":
            raise ValueError("unsupported directive schema")

    @property
    def directive_hash(self) -> str:
        payload = asdict(self)
        payload["allowed_actions"] = sorted(self.allowed_actions)
        return sha256(_canonical(payload)).hexdigest()

    def permits(self, intent: Intent, now_ns: int) -> str | None:
        if now_ns < self.issued_at_ns or now_ns >= self.expires_at_ns:
            return "directive_inactive"
        if intent.principal != self.principal:
            return "directive_principal_mismatch"
        if intent.action not in self.allowed_actions:
            return "directive_action_not_allowed"
        if not any(intent.resource.startswith(prefix) for prefix in self.resource_prefixes):
            return "directive_resource_not_allowed"
        if intent.cost > self.max_cost:
            return "directive_budget_exceeded"
        return None


class DirectiveState(Protocol):
    def activate_directive(self, directive: Directive, authority_evidence: dict[str, object], timestamp_ns: int) -> None: ...
    def revoke_directive(self, directive_id: str, version: int, authority_evidence: dict[str, object], timestamp_ns: int) -> None: ...
    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str: ...


class GovernedDirectiveProjection:
    """Execution-time directive check that delegates permits to the one kernel."""

    def __init__(self, kernel: GovernanceKernel, state: DirectiveState, clock) -> None:
        self.kernel = kernel
        self.state = state
        self.clock = clock

    def evaluate(self, intent: Intent, directive: Directive) -> Decision:
        status = self.state.directive_status(directive.directive_id, directive.version, directive.directive_hash)
        digest = self.kernel.intent_hash(intent)
        if status != "active":
            return Decision("deny", status, digest)
        failure = directive.permits(intent, self.clock())
        if failure:
            return Decision("deny", failure, digest)
        return self.kernel.evaluate(intent)

"""Evidence-only contracts for consequential decision boundaries and agent interactions.

These records describe what intelligence proposed and how principals interacted. They
never authorize an action, issue a permit, modify policy, or create another ledger.
Consequential execution remains exclusively controlled by GovernanceKernel.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(payload).hexdigest()


@dataclass(frozen=True)
class DecisionBoundary:
    """Declared boundary at which a proposed consequence must be governed."""

    boundary_id: str
    task_id: str
    principal: str
    proposed_action: str
    resource: str
    consequence_class: str
    required_evidence: tuple[str, ...]
    approval_class: str | None = None

    def __post_init__(self) -> None:
        required = (
            self.boundary_id,
            self.task_id,
            self.principal,
            self.proposed_action,
            self.resource,
            self.consequence_class,
        )
        if any(not value for value in required):
            raise ValueError("decision boundary fields must be non-empty")
        if not self.required_evidence or any(not item for item in self.required_evidence):
            raise ValueError("required evidence must be non-empty")

    @property
    def boundary_hash(self) -> str:
        return _digest({"schema": "pulpo.decision-boundary.v1", **asdict(self)})


@dataclass(frozen=True)
class AgentInteraction:
    """Evidence of one bounded principal-to-principal interaction.

    ``authority_effect`` is intentionally fixed to ``none``. Delegated authority must
    be represented and evaluated by Pulpo governance, never inferred from a message.
    """

    interaction_id: str
    task_id: str
    source_principal: str
    target_principal: str
    relation: str
    payload_hash: str
    boundary_hash: str
    authority_effect: str = "none"

    def __post_init__(self) -> None:
        required = (
            self.interaction_id,
            self.task_id,
            self.source_principal,
            self.target_principal,
            self.relation,
            self.payload_hash,
            self.boundary_hash,
        )
        if any(not value for value in required):
            raise ValueError("agent interaction fields must be non-empty")
        if self.source_principal == self.target_principal:
            raise ValueError("agent interaction principals must be distinct")
        if self.authority_effect != "none":
            raise ValueError("agent interactions cannot grant authority")

    @property
    def interaction_hash(self) -> str:
        return _digest({"schema": "pulpo.agent-interaction.v1", **asdict(self)})


def evidence_projection(
    boundary: DecisionBoundary,
    interactions: tuple[AgentInteraction, ...] = (),
) -> dict[str, object]:
    """Create a portable read-only projection suitable for an existing receipt.

    This function does not append audit state. A caller may attach the projection to
    the canonical task/receipt evidence only after the normal governance path runs.
    """

    for interaction in interactions:
        if interaction.task_id != boundary.task_id:
            raise ValueError("interaction task does not match decision boundary")
        if interaction.boundary_hash != boundary.boundary_hash:
            raise ValueError("interaction is not bound to decision boundary")

    return {
        "schema": "pulpo.decision-evidence.v1",
        "task_id": boundary.task_id,
        "decision_boundary": {
            **asdict(boundary),
            "boundary_hash": boundary.boundary_hash,
        },
        "agent_interactions": [
            {**asdict(item), "interaction_hash": item.interaction_hash}
            for item in interactions
        ],
        "authority_effect": "none",
    }

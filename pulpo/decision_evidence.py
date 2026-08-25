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


def attach_to_proof_bundle(
    bundle: dict[str, object],
    boundary: DecisionBoundary,
    interactions: tuple[AgentInteraction, ...] = (),
) -> dict[str, object]:
    """Attach decision evidence to an existing canonical proof bundle.

    The incoming bundle must already be internally hash-consistent. This function
    validates it, attaches the evidence projection, and recomputes the same bundle
    hash over the augmented payload. It does not create or append a second receipt,
    ledger, permit, or authority record.
    """

    if bundle.get("schema") != "pulpo.commerce.proof.v1":
        raise ValueError("unsupported proof bundle schema")
    supplied_hash = bundle.get("bundle_hash")
    if not isinstance(supplied_hash, str) or len(supplied_hash) != 64:
        raise ValueError("proof bundle hash is required")

    base_payload = {key: value for key, value in bundle.items() if key != "bundle_hash"}
    if _digest(base_payload) != supplied_hash:
        raise ValueError("proof bundle hash mismatch")
    if "decision_evidence" in base_payload:
        raise ValueError("decision evidence already attached")

    order = base_payload.get("order")
    if not isinstance(order, dict):
        raise ValueError("proof bundle requires an exact order")
    order_hash = _digest(order)
    expected_resource = f"commerce:domain:{order_hash}"
    if boundary.principal != order.get("principal"):
        raise ValueError("decision boundary principal does not match order")
    if boundary.proposed_action != "purchase_domain":
        raise ValueError("decision boundary action does not match commerce proof")
    if boundary.resource != expected_resource:
        raise ValueError("decision boundary resource does not match exact order")

    augmented = {
        **base_payload,
        "decision_evidence": evidence_projection(boundary, interactions),
    }
    return {**augmented, "bundle_hash": _digest(augmented)}

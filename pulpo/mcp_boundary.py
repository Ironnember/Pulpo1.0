"""Capability-stripped MCP projection for Pulpo.

MCP is a transport and capability-discovery surface, not an authority source or
canonical-state writer. The MCP server receives only a frozen primitive snapshot
created from canonical Pulpo. It never retains a kernel, orchestrator, state
backend, authority client, executor, policy object, clock, or ledger reference.

The optional MCP SDK is imported only by ``create_mcp_server`` so Pulpo's core
kernel and its CI remain dependency-free.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .kernel import GovernanceKernel, Intent
from .orchestrator import PulpoOrchestrator


class MCPBoundaryError(ValueError):
    """Raised when an MCP payload cannot form an exact Pulpo proposal."""


@dataclass(frozen=True, slots=True)
class MCPReadSnapshot:
    """Primitive frozen evidence handed across the MCP trust boundary.

    The exact type intentionally contains only immutable primitives. It carries
    no callback or object reference capable of reaching canonical Pulpo state.
    """

    policy_hash: str
    audit_valid: bool
    audit_records: int
    audit_tip: str | None
    source_schema: str = "pulpo.orchestration-evidence.v0"
    schema: str = "pulpo.mcp-read-snapshot.v0"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_hash, str)
            or len(self.policy_hash) != 64
            or self.policy_hash != self.policy_hash.lower()
            or any(character not in "0123456789abcdef" for character in self.policy_hash)
        ):
            raise ValueError("mcp_policy_hash_invalid")
        if type(self.audit_valid) is not bool:
            raise ValueError("mcp_audit_valid_invalid")
        if isinstance(self.audit_records, bool) or not isinstance(self.audit_records, int) or self.audit_records < 0:
            raise ValueError("mcp_audit_records_invalid")
        if self.audit_tip is not None and (
            not isinstance(self.audit_tip, str)
            or len(self.audit_tip) != 64
            or self.audit_tip != self.audit_tip.lower()
            or any(character not in "0123456789abcdef" for character in self.audit_tip)
        ):
            raise ValueError("mcp_audit_tip_invalid")
        if self.source_schema != "pulpo.orchestration-evidence.v0":
            raise ValueError("mcp_source_schema_invalid")
        if self.schema != "pulpo.mcp-read-snapshot.v0":
            raise ValueError("mcp_snapshot_schema_invalid")


def freeze_mcp_snapshot(orchestrator: PulpoOrchestrator) -> MCPReadSnapshot:
    """Copy canonical read metadata into a capability-free immutable snapshot.

    This extraction belongs on the trusted Pulpo side of the boundary. The
    returned object may be handed to an MCP host because it retains no reference
    to the supplied orchestrator or its kernel.
    """

    if not isinstance(orchestrator, PulpoOrchestrator):
        raise TypeError("canonical PulpoOrchestrator required")
    evidence = orchestrator.evidence_snapshot()
    return MCPReadSnapshot(
        policy_hash=evidence.policy_hash,
        audit_valid=evidence.audit_valid,
        audit_records=evidence.audit_records,
        audit_tip=evidence.audit_tip,
        source_schema=evidence.schema,
    )


class PulpoMCPProjection:
    """Project proposals and frozen evidence without canonical write capability."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: MCPReadSnapshot) -> None:
        if type(snapshot) is not MCPReadSnapshot:
            raise TypeError("MCPReadSnapshot required")
        self._snapshot = snapshot

    @staticmethod
    def _intent(
        principal: str,
        action: str,
        resource: str,
        cost: int,
        session_id: str,
    ) -> Intent:
        values = (principal, action, resource, session_id)
        if any(not isinstance(value, str) or not value or value != value.strip() for value in values):
            raise MCPBoundaryError("mcp_intent_invalid")
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
            raise MCPBoundaryError("mcp_intent_invalid")
        return Intent(
            principal=principal,
            action=action,
            resource=resource,
            cost=cost,
            session_id=session_id,
        )

    def propose_intent(
        self,
        target_id: str,
        principal: str,
        action: str,
        resource: str,
        cost: int = 0,
        session_id: str = "default",
        version: int = 1,
    ) -> dict[str, Any]:
        """Return one exact candidate proposal without mutating canonical state.

        A target hash is intentionally absent because a canonical target does not
        exist until Pulpo accepts a governed state transition and records trusted
        lock time. The policy hash is from the frozen read snapshot and therefore
        is informational only until canonical Pulpo re-evaluates the proposal.
        """

        if not isinstance(target_id, str) or not target_id or target_id != target_id.strip():
            raise MCPBoundaryError("mcp_target_invalid")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise MCPBoundaryError("mcp_target_invalid")
        intent = self._intent(principal, action, resource, cost, session_id)
        return {
            "schema": "pulpo.mcp-proposal.v2",
            "target_id": target_id,
            "target_version": version,
            "intent": asdict(intent),
            "intent_hash": GovernanceKernel.intent_hash(intent),
            "policy_hash": self._snapshot.policy_hash,
            "freshness": "frozen",
            "canonical_state_mutation": False,
            "governed_effect": "none",
            "authority_effect": "none",
        }

    def evidence_snapshot(self) -> dict[str, Any]:
        """Return the frozen evidence metadata supplied by trusted Pulpo."""

        snapshot = self._snapshot
        return {
            "schema": "pulpo.mcp-evidence.v1",
            "source_schema": snapshot.source_schema,
            "policy_hash": snapshot.policy_hash,
            "audit_valid": snapshot.audit_valid,
            "audit_records": snapshot.audit_records,
            "audit_tip": snapshot.audit_tip,
            "freshness": "frozen",
            "canonical_state_mutation": False,
            "governed_effect": "none",
            "authority_effect": "none",
        }


def create_mcp_server(snapshot: MCPReadSnapshot):
    """Create an MCP SDK server from capability-free frozen Pulpo metadata."""

    if type(snapshot) is not MCPReadSnapshot:
        raise TypeError("MCPReadSnapshot required")
    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - environment-specific path
        raise RuntimeError("Pulpo MCP support requires the 'mcp' optional dependency") from exc

    projection = PulpoMCPProjection(snapshot)
    server = MCPServer("pulpo")

    @server.tool()
    async def pulpo_propose_intent(
        target_id: str,
        principal: str,
        action: str,
        resource: str,
        cost: int = 0,
        session_id: str = "default",
        version: int = 1,
    ) -> dict[str, Any]:
        """Project one exact proposal without committing canonical state."""

        return projection.propose_intent(
            target_id,
            principal,
            action,
            resource,
            cost,
            session_id,
            version,
        )

    @server.tool()
    async def pulpo_get_evidence() -> dict[str, Any]:
        """Read the frozen integrity metadata supplied by canonical Pulpo."""

        return projection.evidence_snapshot()

    return server

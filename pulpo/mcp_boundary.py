"""Non-authoritative MCP projection over the canonical Pulpo orchestrator.

MCP is a capability transport, not an authority source. This module exposes
only ephemeral proposal projections and read-only evidence. It cannot mutate
canonical state, evaluate policy, mint or return a permit, consume a permit,
approve a directive, or invoke an execution surface.

The optional MCP SDK is imported only by ``create_mcp_server`` so Pulpo's core
kernel and its CI remain dependency-free.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .kernel import Intent
from .orchestrator import PulpoOrchestrator


class MCPBoundaryError(ValueError):
    """Raised when an MCP payload cannot form an exact Pulpo proposal."""


class PulpoMCPProjection:
    """Translate MCP calls without granting a governed mutation capability.

    The projection owns no state or clock. Both remain inside the orchestrator's
    canonical kernel. Proposal construction is deliberately ephemeral: an MCP
    caller may describe an exact candidate intent, but only a separately
    governed mutation path may persist a target, audit event, directive, budget
    transition, permit, or other canonical state.
    """

    def __init__(self, orchestrator: PulpoOrchestrator) -> None:
        if not isinstance(orchestrator, PulpoOrchestrator):
            raise TypeError("canonical PulpoOrchestrator required")
        self.orchestrator = orchestrator

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
        exist until Pulpo accepts a governed state transition and records the
        trusted lock time. ``NO_PERMIT`` therefore cannot be mistaken for
        ``NO_GOVERNED_EFFECT``: this projection performs neither.
        """

        if not isinstance(target_id, str) or not target_id or target_id != target_id.strip():
            raise MCPBoundaryError("mcp_target_invalid")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise MCPBoundaryError("mcp_target_invalid")
        intent = self._intent(principal, action, resource, cost, session_id)
        return {
            "schema": "pulpo.mcp-proposal.v1",
            "target_id": target_id,
            "target_version": version,
            "intent": asdict(intent),
            "intent_hash": self.orchestrator.kernel.intent_hash(intent),
            "policy_hash": self.orchestrator.kernel.policy_hash,
            "canonical_state_mutation": False,
            "governed_effect": "none",
            "authority_effect": "none",
        }

    def evidence_snapshot(self) -> dict[str, Any]:
        """Project canonical evidence metadata without creating another ledger."""

        snapshot = self.orchestrator.evidence_snapshot()
        return {
            "schema": "pulpo.mcp-evidence.v0",
            "policy_hash": snapshot.policy_hash,
            "audit_valid": snapshot.audit_valid,
            "audit_records": snapshot.audit_records,
            "audit_tip": snapshot.audit_tip,
            "canonical_state_mutation": False,
            "governed_effect": "none",
            "authority_effect": "none",
        }


def create_mcp_server(orchestrator: PulpoOrchestrator):
    """Create an MCP SDK server with Pulpo's deliberately narrow tool surface."""

    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - environment-specific path
        raise RuntimeError("Pulpo MCP support requires the 'mcp' optional dependency") from exc

    projection = PulpoMCPProjection(orchestrator)
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
        """Read integrity metadata from Pulpo's canonical evidence chain."""

        return projection.evidence_snapshot()

    return server

"""Trusted-side JSON transport for the Directive Memory read/proposal surface.

The transport serializes only the frozen primitive snapshot plus a requested
read/proposal operation. It does not serialize a kernel, state backend, clock,
verifier, authority client, permit, executor, or ledger reference.
"""

from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any

from .directive_memory_surface import DirectiveMemoryReadSnapshot


REQUEST_SCHEMA = "pulpo.directive-memory-skill-request.v0"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_directive_memory_request(
    snapshot: DirectiveMemoryReadSnapshot,
    *,
    operation: str,
    action: str | None = None,
    resource: str | None = None,
    cost: int | None = None,
    principal: str | None = None,
    session_id: str = "default",
) -> bytes:
    """Serialize one capability-free request for an untrusted skill host."""

    if type(snapshot) is not DirectiveMemoryReadSnapshot:
        raise TypeError("DirectiveMemoryReadSnapshot required")
    if operation not in {"inspect", "propose"}:
        raise ValueError("directive_memory_operation_invalid")

    proposal: dict[str, Any] | None = None
    if operation == "propose":
        if not isinstance(action, str) or not action:
            raise ValueError("directive_memory_action_invalid")
        if not isinstance(resource, str) or not resource:
            raise ValueError("directive_memory_resource_invalid")
        if not isinstance(cost, int) or isinstance(cost, bool) or cost < 0:
            raise ValueError("directive_memory_cost_invalid")
        if principal is not None and (not isinstance(principal, str) or not principal):
            raise ValueError("directive_memory_principal_invalid")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("directive_memory_session_invalid")
        proposal = {
            "principal": principal or snapshot.principal,
            "action": action,
            "resource": resource,
            "cost": cost,
            "session_id": session_id,
        }
    elif any(value is not None for value in (action, resource, cost, principal)):
        raise ValueError("directive_memory_inspect_has_proposal_fields")

    return _canonical_json(
        {
            "schema": REQUEST_SCHEMA,
            "operation": operation,
            "snapshot": asdict(snapshot),
            "proposal": proposal,
        }
    )

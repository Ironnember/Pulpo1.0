"""Capability-stripped Directive Memory skill host.

This host intentionally imports only Python stdlib. It accepts one JSON request
containing a frozen primitive snapshot and returns a non-authoritative inspection
or proposal result. It has no Pulpo kernel, canonical state backend, approval
verifier, authority client, trusted clock, executor, permit, or ledger capability.
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

REQUEST_SCHEMA = "pulpo.directive-memory-skill-request.v0"
SNAPSHOT_SCHEMA = "pulpo.directive-memory-read-snapshot.v0"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_dict(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(reason)
    return value


def _validate_snapshot(value: Any) -> dict[str, Any]:
    snapshot = _require_dict(value, "directive_memory_snapshot_invalid")
    required = {
        "directive_id",
        "version",
        "directive_hash",
        "issuer_authority_id",
        "principal",
        "allowed_actions",
        "resource_prefixes",
        "max_cost",
        "issued_at_ns",
        "expires_at_ns",
        "parent_directive_hash",
        "status",
        "observed_at_ns",
        "freshness",
        "schema",
    }
    if set(snapshot) != required:
        raise ValueError("directive_memory_snapshot_fields_invalid")
    if snapshot["schema"] != SNAPSHOT_SCHEMA or snapshot["freshness"] != "frozen":
        raise ValueError("directive_memory_snapshot_schema_invalid")
    if not isinstance(snapshot["directive_id"], str) or not snapshot["directive_id"]:
        raise ValueError("directive_memory_identity_invalid")
    if not isinstance(snapshot["version"], int) or isinstance(snapshot["version"], bool) or snapshot["version"] <= 0:
        raise ValueError("directive_memory_version_invalid")
    directive_hash = snapshot["directive_hash"]
    if (
        not isinstance(directive_hash, str)
        or len(directive_hash) != 64
        or directive_hash != directive_hash.lower()
        or any(character not in "0123456789abcdef" for character in directive_hash)
    ):
        raise ValueError("directive_memory_hash_invalid")
    for name in ("issuer_authority_id", "principal", "status"):
        if not isinstance(snapshot[name], str) or not snapshot[name]:
            raise ValueError("directive_memory_snapshot_identity_invalid")
    for name in ("allowed_actions", "resource_prefixes"):
        values = snapshot[name]
        if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item for item in values):
            raise ValueError("directive_memory_snapshot_scope_invalid")
    for name in ("max_cost", "issued_at_ns", "expires_at_ns", "observed_at_ns"):
        if not isinstance(snapshot[name], int) or isinstance(snapshot[name], bool):
            raise ValueError("directive_memory_snapshot_bounds_invalid")
    if snapshot["max_cost"] < 0 or snapshot["issued_at_ns"] <= 0:
        raise ValueError("directive_memory_snapshot_bounds_invalid")
    if snapshot["expires_at_ns"] <= snapshot["issued_at_ns"] or snapshot["observed_at_ns"] <= 0:
        raise ValueError("directive_memory_snapshot_bounds_invalid")
    parent = snapshot["parent_directive_hash"]
    if parent is not None and (not isinstance(parent, str) or len(parent) != 64):
        raise ValueError("directive_memory_parent_hash_invalid")
    return snapshot


def _intent_hash(intent: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(intent)).hexdigest()


def handle(request: Any) -> dict[str, Any]:
    request = _require_dict(request, "directive_memory_request_invalid")
    if set(request) != {"schema", "operation", "snapshot", "proposal"}:
        raise ValueError("directive_memory_request_fields_invalid")
    if request["schema"] != REQUEST_SCHEMA:
        raise ValueError("directive_memory_request_schema_invalid")

    snapshot = _validate_snapshot(request["snapshot"])
    operation = request["operation"]
    proposal = request["proposal"]

    common = {
        "freshness": "frozen",
        "authority": "not_asserted",
        "authority_effect": "none",
        "governed_effect": "none",
        "canonical_state_mutation": False,
    }

    if operation == "inspect":
        if proposal is not None:
            raise ValueError("directive_memory_inspect_has_proposal")
        return {
            "schema": "pulpo.directive-memory-skill-inspection.v0",
            "snapshot": snapshot,
            **common,
        }

    if operation != "propose":
        raise ValueError("directive_memory_operation_invalid")
    proposal = _require_dict(proposal, "directive_memory_proposal_invalid")
    if set(proposal) != {"principal", "action", "resource", "cost", "session_id"}:
        raise ValueError("directive_memory_proposal_fields_invalid")
    for name in ("principal", "action", "resource", "session_id"):
        if not isinstance(proposal[name], str) or not proposal[name]:
            raise ValueError("directive_memory_proposal_identity_invalid")
    if not isinstance(proposal["cost"], int) or isinstance(proposal["cost"], bool) or proposal["cost"] < 0:
        raise ValueError("directive_memory_proposal_cost_invalid")

    reason: str | None = None
    if proposal["principal"] != snapshot["principal"]:
        reason = "directive_principal_mismatch"
    elif proposal["action"] not in snapshot["allowed_actions"]:
        reason = "directive_action_not_allowed"
    elif not any(proposal["resource"].startswith(prefix) for prefix in snapshot["resource_prefixes"]):
        reason = "directive_resource_not_allowed"
    elif proposal["cost"] > snapshot["max_cost"]:
        reason = "directive_budget_exceeded"
    elif not snapshot["issued_at_ns"] <= snapshot["observed_at_ns"] < snapshot["expires_at_ns"]:
        reason = "directive_inactive_at_snapshot"
    elif snapshot["status"] != "active":
        reason = snapshot["status"]

    return {
        "schema": "pulpo.directive-memory-proposal.v0",
        "intent": proposal,
        "intent_hash": _intent_hash(proposal),
        "directive_id": snapshot["directive_id"],
        "directive_version": snapshot["version"],
        "directive_hash": snapshot["directive_hash"],
        "frozen_scope_match": reason is None,
        "frozen_scope_reason": reason or "frozen_scope_match_only",
        "requires_canonical_revalidation": True,
        **common,
    }


def main() -> int:
    try:
        request = json.load(sys.stdin)
        response = handle(request)
    except Exception as exc:
        response = {
            "schema": "pulpo.directive-memory-skill-error.v0",
            "error": type(exc).__name__,
            "reason": str(exc),
            "freshness": "unknown",
            "authority": "not_asserted",
            "authority_effect": "none",
            "governed_effect": "none",
            "canonical_state_mutation": False,
        }
        json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
        return 2
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Deterministic, no-side-effect public Pulpo proof lab."""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from typing import Any

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy
from pulpo.authority import AuthorityTrust


class PublicProofError(ValueError):
    pass


_TRUST = AuthorityTrust(
    authority_id="public-lab-authority",
    verifier_id="public-lab-verifier",
    key_id="public-lab-key",
    algorithm="Ed25519",
    key_fingerprint="0" * 64,
    deployment_id="public-proof-lab-v0",
    max_approval_ttl_ns=60_000_000_000,
)

_SCENARIOS: dict[str, dict[str, Any]] = {
    "safe_read": {
        "title": "Read public evidence",
        "description": "A bounded read is inside policy and receives a one-use permit.",
        "intent": Intent("agent:public", "read", "evidence:public-demo", cost=0, session_id="proof-lab"),
    },
    "over_budget": {
        "title": "Try to exceed the budget",
        "description": "The requested cost is above the hard policy ceiling.",
        "intent": Intent("agent:public", "write", "sandbox:demo", cost=101, session_id="proof-lab"),
    },
    "unknown_action": {
        "title": "Try an unapproved capability",
        "description": "The action is not present in Pulpo's allowed action set.",
        "intent": Intent("agent:public", "delete", "sandbox:demo", cost=0, session_id="proof-lab"),
    },
    "needs_approval": {
        "title": "Request a consequential action",
        "description": "Policy recognizes the action but refuses to issue a permit without external approval.",
        "intent": Intent("agent:public", "write", "sandbox:demo", cost=5, session_id="proof-lab"),
    },
}


def _policy() -> Policy:
    return Policy(
        allowed_actions=frozenset({"read", "write"}),
        max_cost=100,
        approval_actions=frozenset({"write"}),
        agent_grants=(
            AgentGrant(
                principal="agent:public",
                allowed_actions=frozenset({"read", "write"}),
                resource_prefixes=("evidence:", "sandbox:"),
                max_cost=100,
            ),
        ),
        authority_trust=_TRUST,
    )


def list_scenarios() -> list[dict[str, str]]:
    return [
        {"id": scenario_id, "title": item["title"], "description": item["description"]}
        for scenario_id, item in _SCENARIOS.items()
    ]


def evaluate_scenario(scenario_id: str) -> dict[str, Any]:
    item = _SCENARIOS.get(scenario_id)
    if item is None:
        raise PublicProofError("unknown_scenario")
    intent: Intent = item["intent"]
    kernel = GovernanceKernel(_policy(), secret=b"public-proof-lab-v0-secret")
    decision = kernel.evaluate(intent)
    permit_issued = decision.permit is not None
    consumed = False
    replay_rejected = None
    if permit_issued:
        consumed = kernel.consume(decision.permit, intent)
        replay_rejected = not kernel.consume(decision.permit, intent)
    audit_tip = kernel.audit[-1]["hash"] if kernel.audit else None
    return {
        "scenario": scenario_id,
        "intent": asdict(intent),
        "decision": {"outcome": decision.outcome, "reason": decision.reason},
        "permit_issued": permit_issued,
        "permit_consumed_for_proof": consumed,
        "permit_replay_rejected": replay_rejected,
        "external_execution": "not_performed",
        "authority_effect": "none",
        "audit_valid": kernel.verify_audit(),
        "audit_tip": audit_tip,
        "boundary": "This public lab evaluates the canonical Pulpo kernel. It performs no external side effect and does not authenticate a human authority.",
    }


def usage_event(scenario_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Privacy-minimized event suitable for aggregate learning.

    No IP, user agent, free-form prompt, email, cookie, or stable user identifier is
    included. Deployment logs may still contain provider-standard request metadata;
    the application does not deliberately add identity data.
    """
    payload = {
        "schema": "pulpo.public-proof-usage.v0",
        "scenario": scenario_id,
        "outcome": result["decision"]["outcome"],
        "reason": result["decision"]["reason"],
        "replay_rejected": result["permit_replay_rejected"],
        "authority_effect": "none",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {**payload, "event_hash": sha256(canonical).hexdigest()}

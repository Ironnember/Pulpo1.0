"""Small, deterministic governance kernel with no runtime dependencies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import secrets
import time
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Intent:
    principal: str
    action: str
    resource: str
    cost: int = 0


@dataclass(frozen=True)
class Policy:
    allowed_actions: frozenset[str]
    max_cost: int
    approval_actions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    intent_hash: str
    permit: str | None = None


class GovernanceKernel:
    """Evaluates intent, issues one-use permits, and maintains an audit chain."""

    def __init__(self, policy: Policy, secret: bytes | None = None) -> None:
        self.policy = policy
        self._secret = secret or secrets.token_bytes(32)
        self._issued: dict[str, str] = {}
        self._spent: set[str] = set()
        self.audit: list[dict[str, Any]] = []

    @staticmethod
    def intent_hash(intent: Intent) -> str:
        return sha256(_canonical(asdict(intent))).hexdigest()

    def evaluate(self, intent: Intent, approved: bool = False) -> Decision:
        digest = self.intent_hash(intent)
        if not intent.principal or not intent.action or not intent.resource:
            return self._decide("deny", "incomplete_intent", digest)
        if intent.cost < 0 or intent.cost > self.policy.max_cost:
            return self._decide("deny", "budget_exceeded", digest)
        if intent.action not in self.policy.allowed_actions:
            return self._decide("deny", "action_not_allowed", digest)
        if intent.action in self.policy.approval_actions and not approved:
            return self._decide("require_approval", "approval_required", digest)

        nonce = secrets.token_hex(16)
        payload = f"{digest}:{nonce}"
        signature = hmac.new(self._secret, payload.encode(), sha256).hexdigest()
        permit = f"{payload}:{signature}"
        self._issued[permit] = digest
        return self._decide("allow", "policy_satisfied", digest, permit)

    def consume(self, permit: str, intent: Intent) -> bool:
        digest = self.intent_hash(intent)
        valid = self._issued.get(permit) == digest and permit not in self._spent
        if valid:
            self._spent.add(permit)
        self._append("permit_consumed" if valid else "permit_rejected", {"intent_hash": digest})
        return valid

    def verify_audit(self) -> bool:
        previous = "0" * 64
        for record in self.audit:
            body = {key: value for key, value in record.items() if key != "hash"}
            if body["previous_hash"] != previous:
                return False
            expected = sha256(_canonical(body)).hexdigest()
            if not hmac.compare_digest(record["hash"], expected):
                return False
            previous = record["hash"]
        return True

    def _decide(self, outcome: str, reason: str, digest: str, permit: str | None = None) -> Decision:
        decision = Decision(outcome, reason, digest, permit)
        self._append("decision", {"outcome": outcome, "reason": reason, "intent_hash": digest})
        return decision

    def _append(self, event: str, payload: dict[str, Any]) -> None:
        previous = self.audit[-1]["hash"] if self.audit else "0" * 64
        body = {"event": event, "payload": payload, "previous_hash": previous, "timestamp_ns": time.time_ns()}
        self.audit.append({**body, "hash": sha256(_canonical(body)).hexdigest()})

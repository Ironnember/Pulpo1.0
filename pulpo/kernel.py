"""Small, deterministic governance kernel with no runtime dependencies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import secrets
import time
from typing import Any, Callable

from .authority import ApprovalEnvelope, ApprovalVerifier
from .state import ApprovalUse, InMemoryKernelState, KernelState


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Intent:
    principal: str
    action: str
    resource: str
    cost: int = 0
    session_id: str = "default"


@dataclass(frozen=True)
class AgentGrant:
    """Least-authority limits for one agent principal.

    Resource prefixes are namespaces such as ``repo:`` or ``evidence:``.  They
    are evaluated by the same kernel as every other policy condition; this is
    not a second agent router.
    """

    principal: str
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int

    def __post_init__(self) -> None:
        if not self.principal or not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("agent grant fields must be non-empty")
        if any(not prefix for prefix in self.resource_prefixes):
            raise ValueError("resource prefixes must be non-empty")
        if self.max_cost < 0:
            raise ValueError("agent max_cost must be non-negative")


@dataclass(frozen=True)
class Policy:
    allowed_actions: frozenset[str]
    max_cost: int
    approval_actions: frozenset[str] = frozenset()
    agent_grants: tuple[AgentGrant, ...] = ()

    def __post_init__(self) -> None:
        principals = [grant.principal for grant in self.agent_grants]
        if len(principals) != len(set(principals)):
            raise ValueError("agent principals must be unique")
        if any(not grant.allowed_actions.issubset(self.allowed_actions) for grant in self.agent_grants):
            raise ValueError("agent actions must be a subset of policy actions")


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    intent_hash: str
    permit: str | None = None


class StateIntegrityError(RuntimeError):
    """Raised when persisted audit state cannot be trusted at bootstrap."""


class GovernanceKernel:
    """Evaluates intent, issues one-use permits, and maintains an audit chain."""

    def __init__(
        self,
        policy: Policy,
        secret: bytes | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        clock: Callable[[], int] | None = None,
        state: KernelState | None = None,
    ) -> None:
        self.policy = policy
        self._secret = secret or secrets.token_bytes(32)
        self._approval_verifier = approval_verifier
        self._clock = clock or time.time_ns
        self._state = state if state is not None else InMemoryKernelState()
        if not self.verify_audit():
            raise StateIntegrityError("kernel state audit chain is invalid")

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self._state.audit

    @staticmethod
    def intent_hash(intent: Intent) -> str:
        return sha256(_canonical(asdict(intent))).hexdigest()

    @property
    def policy_hash(self) -> str:
        grants = [
            {
                "principal": grant.principal,
                "allowed_actions": sorted(grant.allowed_actions),
                "resource_prefixes": sorted(grant.resource_prefixes),
                "max_cost": grant.max_cost,
            }
            for grant in sorted(self.policy.agent_grants, key=lambda item: item.principal)
        ]
        payload = {
            "schema": "pulpo.policy.v1",
            "allowed_actions": sorted(self.policy.allowed_actions),
            "max_cost": self.policy.max_cost,
            "approval_actions": sorted(self.policy.approval_actions),
            "agent_grants": grants,
        }
        return sha256(_canonical(payload)).hexdigest()

    def evaluate(self, intent: Intent) -> Decision:
        digest = self.intent_hash(intent)
        failure = self._policy_failure(intent)
        if failure:
            return self._decide("deny", failure, digest)
        if intent.action in self.policy.approval_actions:
            return self._decide("require_approval", "approval_required", digest)

        return self._issue_permit(digest)

    def evaluate_with_approval(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
    ) -> Decision:
        """Issue a permit only after verification by the configured authority."""

        digest = self.intent_hash(intent)
        failure = self._policy_failure(intent)
        if failure:
            return self._decide("deny", failure, digest)
        if intent.action not in self.policy.approval_actions:
            if not isinstance(envelope, ApprovalEnvelope):
                return self._decide("deny", "approval_envelope_invalid", digest)
            return self._approval_decide("approval_not_required", digest, envelope)
        if not isinstance(envelope, ApprovalEnvelope):
            return self._decide("deny", "approval_envelope_invalid", digest)
        if self._approval_verifier is None:
            return self._approval_decide("approval_verifier_unavailable", digest, envelope)
        if not envelope.signature:
            return self._approval_decide("approval_signature_missing", digest, envelope)
        if envelope.authority_id != self._approval_verifier.authority_id:
            return self._approval_decide("approval_authority_mismatch", digest, envelope)
        if envelope.session_id != intent.session_id:
            return self._approval_decide("approval_session_mismatch", digest, envelope)
        if envelope.principal != intent.principal:
            return self._approval_decide("approval_principal_mismatch", digest, envelope)
        if envelope.intent_hash != digest:
            return self._approval_decide("approval_intent_mismatch", digest, envelope)
        if envelope.policy_hash != self.policy_hash:
            return self._approval_decide("approval_policy_mismatch", digest, envelope)
        now_ns = self._clock()
        if now_ns <= 0:
            return self._approval_decide("approval_clock_invalid", digest, envelope)
        if now_ns >= envelope.expires_at_ns:
            return self._approval_decide("approval_expired", digest, envelope)
        replay = self._state.approval_replay_reason(envelope.approval_id, envelope.nonce)
        if replay:
            return self._approval_decide(replay, digest, envelope)
        try:
            signature_valid = self._approval_verifier.verify(envelope.signing_bytes(), envelope.signature)
        except Exception:
            return self._approval_decide("approval_verifier_failed", digest, envelope)
        if not signature_valid:
            return self._approval_decide("approval_signature_invalid", digest, envelope)

        approval = ApprovalUse(
            envelope.approval_id,
            envelope.nonce,
            {
                "approval_id": envelope.approval_id,
                "authority_id": envelope.authority_id,
                "envelope_hash": envelope.envelope_hash,
                "intent_hash": digest,
            },
        )
        return self._issue_permit(digest, reason="verified_approval", approval=approval, envelope=envelope)

    def _policy_failure(self, intent: Intent) -> str | None:
        if not intent.principal or not intent.session_id or not intent.action or not intent.resource:
            return "incomplete_intent"
        if intent.cost < 0 or intent.cost > self.policy.max_cost:
            return "budget_exceeded"
        if intent.action not in self.policy.allowed_actions:
            return "action_not_allowed"
        if self.policy.agent_grants:
            grant = next((item for item in self.policy.agent_grants if item.principal == intent.principal), None)
            if grant is None:
                return "unknown_principal"
            if intent.action not in grant.allowed_actions:
                return "agent_action_not_allowed"
            if not any(intent.resource.startswith(prefix) for prefix in grant.resource_prefixes):
                return "agent_resource_not_allowed"
            if intent.cost > grant.max_cost:
                return "agent_budget_exceeded"
        return None

    def _issue_permit(
        self,
        digest: str,
        *,
        reason: str = "policy_satisfied",
        approval: ApprovalUse | None = None,
        envelope: ApprovalEnvelope | None = None,
    ) -> Decision:
        nonce = secrets.token_hex(16)
        payload = f"{digest}:{nonce}"
        signature = hmac.new(self._secret, payload.encode(), sha256).hexdigest()
        permit = f"{payload}:{signature}"
        replay = self._state.issue_permit(permit, digest, reason, self._clock(), approval)
        if replay:
            if envelope is None:
                raise RuntimeError("state rejected an approval-free permit")
            return self._approval_decide(replay, digest, envelope)
        return Decision("allow", reason, digest, permit)

    def _approval_decide(self, reason: str, digest: str, envelope: ApprovalEnvelope) -> Decision:
        self._append(
            "approval_rejected",
            {
                "approval_id": envelope.approval_id,
                "authority_id": envelope.authority_id,
                "envelope_hash": envelope.envelope_hash,
                "intent_hash": digest,
                "reason": reason,
            },
        )
        return self._decide("deny", reason, digest)

    def consume(self, permit: str, intent: Intent) -> bool:
        digest = self.intent_hash(intent)
        return self._state.consume_permit(permit, digest, self._clock())

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
        self._state.append(event, payload, self._clock())

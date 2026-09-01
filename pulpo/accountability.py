"""Pre-deployment accountability context proof seam.

This module deliberately extends the existing kernel authority/policy/audit seam.  It is
not a router, executor, policy engine, authority service, memory governor, or
second ledger.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
from typing import Any, Callable, Literal

from .authority import ApprovalEnvelope
from .kernel import Decision, GovernanceKernel, Intent


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


EvidenceStatus = Literal["verified", "Unknown"]


@dataclass(frozen=True)
class AccountableContext:
    """Versioned pre-deployment accountability boundary.

    The context answers who is accountable, under what authority, and for what
    deployment scope before any delegated policy, permit, or execution can act.
    It narrows the normal kernel policy; it cannot broaden authority.
    """

    context_id: str
    version: int
    accountable_party: str
    authority_source: str
    deployment_context: str
    allowed_actions: frozenset[str]
    forbidden_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int
    evidence_requirements: tuple[str, ...]
    signer_trust_basis: str
    escalation_path: str
    revocation_path: str
    proof_boundary: str
    open_unknowns: tuple[str, ...] = ()
    schema: str = "pulpo.accountable_context.v0"

    def __post_init__(self) -> None:
        if self.schema != "pulpo.accountable_context.v0":
            raise ValueError("unsupported accountable context schema")
        if not self.context_id or self.version <= 0:
            raise ValueError("context identity and version must be valid")
        required = (
            self.accountable_party,
            self.authority_source,
            self.deployment_context,
            self.signer_trust_basis,
            self.escalation_path,
            self.revocation_path,
            self.proof_boundary,
        )
        if any(not value for value in required):
            raise ValueError("accountable context fields must be non-empty")
        if not self.allowed_actions or not self.resource_prefixes or not self.evidence_requirements:
            raise ValueError("accountable context scope and evidence requirements must be non-empty")
        if self.max_cost < 0:
            raise ValueError("accountable context max_cost must be non-negative")
        if self.forbidden_actions.intersection(self.allowed_actions):
            raise ValueError("forbidden actions cannot also be allowed")

    @property
    def context_hash(self) -> str:
        payload = asdict(self)
        payload["allowed_actions"] = sorted(self.allowed_actions)
        payload["forbidden_actions"] = sorted(self.forbidden_actions)
        payload["resource_prefixes"] = list(self.resource_prefixes)
        payload["evidence_requirements"] = list(self.evidence_requirements)
        payload["open_unknowns"] = list(self.open_unknowns)
        return sha256(_canonical(payload)).hexdigest()


@dataclass(frozen=True)
class AccountableContextObservation:
    outcome: EvidenceStatus
    reason: str
    context_id: str
    expected_context_hash: str
    observed_context_hash: str | None = None


class AccountableGovernance:
    """Governed precondition wrapper around the canonical kernel.

    All records are appended into the kernel audit chain.  The wrapper keeps only
    a runtime projection of active/revoked context hashes and does not maintain a
    second accountability ledger.
    """

    def __init__(self, kernel: GovernanceKernel, *, clock: Callable[[], int] | None = None) -> None:
        self.kernel = kernel
        self._clock = clock
        self._active: dict[str, AccountableContext] = {}
        self._revoked: set[str] = set()

    def activate_context(
        self,
        context: AccountableContext,
        envelope: ApprovalEnvelope,
        *,
        principal: str,
        session_id: str = "default",
    ) -> Decision:
        """Activate a context only through the existing approved authority path."""

        intent = self._context_intent("accountability.activate", context.context_hash, principal, session_id)
        decision = self.kernel.evaluate_with_approval(intent, envelope)
        if decision.outcome != "allow" or decision.permit is None:
            return decision
        if not self.kernel.consume(decision.permit, intent):
            return self._deny(intent, "accountability_activation_permit_rejected")
        self._active[context.context_id] = context
        self._revoked.discard(context.context_hash)
        self._append(
            "accountability_context_activated",
            {
                "context_id": context.context_id,
                "version": context.version,
                "context_hash": context.context_hash,
                "accountable_party": context.accountable_party,
                "authority_source": context.authority_source,
                "deployment_context": context.deployment_context,
                "activation_intent_hash": self.kernel.intent_hash(intent),
                "authority_effect": "accountability_context_activation",
            },
        )
        return decision

    def revoke_context(
        self,
        context_id: str,
        envelope: ApprovalEnvelope,
        *,
        principal: str,
        session_id: str = "default",
    ) -> Decision:
        context = self._active.get(context_id)
        if context is None:
            return self._deny(Intent(principal, "accountability.revoke", f"accountability:{context_id}", session_id=session_id), "accountable_context_missing")
        intent = self._context_intent("accountability.revoke", context.context_hash, principal, session_id)
        decision = self.kernel.evaluate_with_approval(intent, envelope)
        if decision.outcome != "allow" or decision.permit is None:
            return decision
        if not self.kernel.consume(decision.permit, intent):
            return self._deny(intent, "accountability_revocation_permit_rejected")
        self._revoked.add(context.context_hash)
        self._append(
            "accountability_context_revoked",
            {
                "context_id": context.context_id,
                "version": context.version,
                "context_hash": context.context_hash,
                "revocation_intent_hash": self.kernel.intent_hash(intent),
                "authority_effect": "accountability_context_revocation",
            },
        )
        return decision

    def evaluate(self, intent: Intent, *, context_id: str | None = None) -> Decision:
        failure = self._context_failure(intent, context_id)
        if failure:
            return self._deny(intent, failure)
        return self.kernel.evaluate(intent)

    def evaluate_with_approval(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
        *,
        context_id: str | None = None,
    ) -> Decision:
        failure = self._context_failure(intent, context_id)
        if failure:
            return self._deny(intent, failure)
        return self.kernel.evaluate_with_approval(intent, envelope)

    def consume(self, permit: str, intent: Intent, *, context_id: str | None = None) -> bool:
        failure = self._context_failure(intent, context_id)
        if failure:
            self._append(
                "permit_consumption_rejected",
                {
                    "intent_hash": self.kernel.intent_hash(intent),
                    "reason": failure,
                    "context_id": context_id,
                    "authority_effect": "none",
                },
            )
            return False
        return self.kernel.consume(permit, intent)

    def observe_context_evidence(
        self,
        context_id: str,
        observed_context_hash: str | None,
    ) -> AccountableContextObservation:
        context = self._active.get(context_id)
        expected = context.context_hash if context else ""
        if context is None:
            result = AccountableContextObservation("Unknown", "accountable_context_missing", context_id, expected, observed_context_hash)
        elif context.context_hash in self._revoked:
            result = AccountableContextObservation("Unknown", "accountable_context_revoked", context_id, expected, observed_context_hash)
        elif not observed_context_hash or not hmac.compare_digest(context.context_hash, observed_context_hash):
            result = AccountableContextObservation("Unknown", "accountable_context_evidence_mismatch", context_id, expected, observed_context_hash)
        else:
            result = AccountableContextObservation("verified", "accountable_context_exact_match", context_id, expected, observed_context_hash)
        self._append(
            "accountability_context_observation",
            {
                "outcome": result.outcome,
                "reason": result.reason,
                "context_id": result.context_id,
                "expected_context_hash": result.expected_context_hash,
                "observed_context_hash": result.observed_context_hash,
                "authority_effect": "none",
            },
        )
        return result

    def _context_failure(self, intent: Intent, context_id: str | None) -> str | None:
        if not context_id:
            return "accountable_context_required"
        context = self._active.get(context_id)
        if context is None:
            return "accountable_context_missing"
        if context.context_hash in self._revoked:
            return "accountable_context_revoked"
        if intent.action in context.forbidden_actions:
            return "accountable_context_action_forbidden"
        if intent.action not in context.allowed_actions:
            return "accountable_context_action_not_allowed"
        if not any(intent.resource.startswith(prefix) for prefix in context.resource_prefixes):
            return "accountable_context_resource_not_allowed"
        if intent.cost > context.max_cost:
            return "accountable_context_budget_exceeded"
        return None

    def _context_intent(self, action: str, context_hash: str, principal: str, session_id: str) -> Intent:
        return Intent(
            principal=principal,
            action=action,
            resource=f"accountability:{context_hash}",
            cost=0,
            session_id=session_id,
        )

    def _deny(self, intent: Intent, reason: str) -> Decision:
        digest = self.kernel.intent_hash(intent)
        self._append("decision", {"outcome": "deny", "reason": reason, "intent_hash": digest})
        return Decision("deny", reason, digest)

    def _append(self, event: str, payload: dict[str, Any]) -> None:
        now_ns = self._trusted_now()
        self.kernel._state.append(event, payload, now_ns)  # noqa: SLF001 - existing canonical audit seam

    def _trusted_now(self) -> int:
        if self._clock is not None:
            value = self._clock()
        else:
            value = self.kernel._trusted_now()  # noqa: SLF001 - reuse kernel trusted clock
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RuntimeError("accountability_clock_invalid")
        return value

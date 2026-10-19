"""Governed directive projection over Pulpo's existing authority and evidence seams.

Directives constrain execution. They do not create authority, mint permits, or
form a second policy/evidence truth. Activation and revocation are themselves
consequential governance actions and must pass through the existing kernel's
pinned external approval verifier before canonical directive state can change.

Directive state and trusted time are kernel-owned. This module deliberately has
no constructor injection point for an alternate directive state or clock.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .authority import ApprovalEnvelope
from .kernel import Decision, GovernanceKernel, Intent
from .state import DirectivePermitBinding


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Directive:
    directive_id: str
    version: int
    issuer_authority_id: str
    principal: str
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int
    issued_at_ns: int
    expires_at_ns: int
    parent_directive_hash: str | None = None
    schema: str = "pulpo.directive.v1"

    def __post_init__(self) -> None:
        if not self.directive_id or not self.issuer_authority_id or not self.principal:
            raise ValueError("directive identity fields must be non-empty")
        if self.version <= 0 or not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("directive scope must be non-empty and versioned")
        if self.max_cost < 0 or self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("directive bounds are invalid")
        if self.schema != "pulpo.directive.v1":
            raise ValueError("unsupported directive schema")

    @property
    def directive_hash(self) -> str:
        payload = asdict(self)
        payload["allowed_actions"] = sorted(self.allowed_actions)
        return sha256(_canonical(payload)).hexdigest()

    @property
    def permit_binding(self) -> DirectivePermitBinding:
        return DirectivePermitBinding(
            directive_id=self.directive_id,
            version=self.version,
            directive_hash=self.directive_hash,
            issued_at_ns=self.issued_at_ns,
            expires_at_ns=self.expires_at_ns,
            parent_directive_hash=self.parent_directive_hash,
        )

    def permits(self, intent: Intent, now_ns: int) -> str | None:
        if now_ns < self.issued_at_ns or now_ns >= self.expires_at_ns:
            return "directive_inactive"
        if intent.principal != self.principal:
            return "directive_principal_mismatch"
        if intent.action not in self.allowed_actions:
            return "directive_action_not_allowed"
        if not any(intent.resource.startswith(prefix) for prefix in self.resource_prefixes):
            return "directive_resource_not_allowed"
        if intent.cost > self.max_cost:
            return "directive_budget_exceeded"
        return None

    def derivation_failure(self, parent: "Directive") -> str | None:
        """Return why this child would broaden its exact parent, if it would.

        V0 deliberately permits only one derived level and preserves the same
        governed principal and independently authenticated issuer. Cross-principal
        delegation is a separate authority design and is not inferred here.
        """

        if self.parent_directive_hash is None:
            return "directive_parent_required"
        if self.parent_directive_hash != parent.directive_hash:
            return "directive_parent_hash_mismatch"
        if parent.parent_directive_hash is not None:
            return "directive_parent_chain_unsupported"
        if self.issuer_authority_id != parent.issuer_authority_id:
            return "directive_parent_issuer_mismatch"
        if self.principal != parent.principal:
            return "directive_parent_principal_mismatch"
        if not self.allowed_actions.issubset(parent.allowed_actions):
            return "directive_parent_action_broadened"
        if any(
            not any(prefix.startswith(parent_prefix) for parent_prefix in parent.resource_prefixes)
            for prefix in self.resource_prefixes
        ):
            return "directive_parent_resource_broadened"
        if self.max_cost > parent.max_cost:
            return "directive_parent_budget_broadened"
        if self.issued_at_ns < parent.issued_at_ns or self.expires_at_ns > parent.expires_at_ns:
            return "directive_parent_time_broadened"
        return None


class DirectiveAuthorityController:
    """Use the one governance kernel to authorize canonical directive mutations."""

    ACTIVATE = "activate_directive"
    REVOKE = "revoke_directive"

    def __init__(self, kernel: GovernanceKernel) -> None:
        self.kernel = kernel

    @staticmethod
    def authority_intent(
        operation: str,
        directive: Directive,
        *,
        operator_principal: str,
        session_id: str = "default",
    ) -> Intent:
        return Intent(
            principal=operator_principal,
            action=operation,
            resource=(
                f"directive:{directive.directive_id}:{directive.version}:"
                f"{directive.directive_hash}"
            ),
            cost=0,
            session_id=session_id,
        )

    @staticmethod
    def _evidence(
        operation: str,
        directive: Directive,
        envelope: ApprovalEnvelope,
        authority_intent: Intent,
        kernel: GovernanceKernel,
    ) -> dict[str, object]:
        return {
            "operation": operation,
            "directive_id": directive.directive_id,
            "directive_version": directive.version,
            "directive_hash": directive.directive_hash,
            "parent_directive_hash": directive.parent_directive_hash,
            "authority_id": envelope.authority_id,
            "approval_id": envelope.approval_id,
            "envelope_hash": envelope.envelope_hash,
            "intent_hash": kernel.intent_hash(authority_intent),
            "policy_hash": kernel.policy_hash,
        }

    def _trusted_now(self) -> int:
        now_ns = self.kernel._trusted_now()
        if now_ns is None:
            raise RuntimeError("directive_clock_invalid")
        return now_ns

    def _authorize(
        self,
        operation: str,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str,
    ) -> tuple[Decision, Intent]:
        digest = self.kernel.intent_hash(
            self.authority_intent(
                operation,
                directive,
                operator_principal=operator_principal,
                session_id=session_id,
            )
        )
        trust = self.kernel.policy.authority_trust
        if trust is None or directive.issuer_authority_id != trust.authority_id:
            return Decision("deny", "directive_issuer_untrusted", digest), self.authority_intent(
                operation,
                directive,
                operator_principal=operator_principal,
                session_id=session_id,
            )

        authority_intent = self.authority_intent(
            operation,
            directive,
            operator_principal=operator_principal,
            session_id=session_id,
        )
        decision = self.kernel.evaluate_with_approval(authority_intent, envelope)
        if decision.outcome != "allow" or decision.permit is None:
            return decision, authority_intent
        if not self.kernel.consume(decision.permit, authority_intent):
            return Decision("deny", "directive_authority_permit_rejected", digest), authority_intent
        return decision, authority_intent

    def _derivation_decision(
        self,
        directive: Directive,
        parent_directive: Directive | None,
        *,
        operator_principal: str,
        session_id: str,
    ) -> Decision | None:
        authority_intent = self.authority_intent(
            self.ACTIVATE,
            directive,
            operator_principal=operator_principal,
            session_id=session_id,
        )
        digest = self.kernel.intent_hash(authority_intent)
        if directive.parent_directive_hash is None:
            if parent_directive is not None:
                return Decision("deny", "directive_parent_unexpected", digest)
            return None
        if parent_directive is None:
            return Decision("deny", "directive_parent_required", digest)
        failure = directive.derivation_failure(parent_directive)
        if failure:
            return Decision("deny", failure, digest)
        parent_status = self.kernel._state.directive_hash_status(parent_directive.directive_hash)
        if parent_status != "active":
            return Decision("deny", parent_status, digest)
        now_ns = self._trusted_now()
        if not (parent_directive.issued_at_ns <= now_ns < parent_directive.expires_at_ns):
            return Decision("deny", "directive_parent_inactive", digest)
        return None

    def activate(
        self,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str = "default",
        parent_directive: Directive | None = None,
    ) -> Decision:
        derivation = self._derivation_decision(
            directive,
            parent_directive,
            operator_principal=operator_principal,
            session_id=session_id,
        )
        if derivation is not None:
            return derivation
        decision, authority_intent = self._authorize(
            self.ACTIVATE,
            directive,
            envelope,
            operator_principal=operator_principal,
            session_id=session_id,
        )
        if decision.outcome != "allow":
            return decision
        try:
            self.kernel._state.activate_directive(
                directive,
                self._evidence(self.ACTIVATE, directive, envelope, authority_intent, self.kernel),
                self._trusted_now(),
            )
        except ValueError as exc:
            if str(exc) == "parent directive is not active for activation":
                return Decision("deny", "directive_parent_inactive_at_activation", decision.intent_hash)
            raise
        return decision

    def revoke(
        self,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str = "default",
    ) -> Decision:
        decision, authority_intent = self._authorize(
            self.REVOKE,
            directive,
            envelope,
            operator_principal=operator_principal,
            session_id=session_id,
        )
        if decision.outcome != "allow":
            return decision
        self.kernel._state.revoke_directive(
            directive.directive_id,
            directive.version,
            self._evidence(self.REVOKE, directive, envelope, authority_intent, self.kernel),
            self._trusted_now(),
        )
        return decision


class GovernedDirectiveProjection:
    """Bind the kernel's one-use permit to its own live directive state."""

    def __init__(self, kernel: GovernanceKernel) -> None:
        self.kernel = kernel

    def _trusted_now(self) -> int:
        now_ns = self.kernel._trusted_now()
        if now_ns is None:
            raise RuntimeError("directive_clock_invalid")
        return now_ns

    def evaluate(self, intent: Intent, directive: Directive) -> Decision:
        status = self.kernel._state.directive_status(
            directive.directive_id,
            directive.version,
            directive.directive_hash,
        )
        digest = self.kernel.intent_hash(intent)
        if status != "active":
            return Decision("deny", status, digest)
        if directive.parent_directive_hash is not None:
            parent_status = self.kernel._state.directive_hash_status(directive.parent_directive_hash)
            if parent_status != "active":
                return Decision("deny", parent_status, digest)
        now_ns = self._trusted_now()
        failure = directive.permits(intent, now_ns)
        if failure:
            return Decision("deny", failure, digest)

        decision = self.kernel.evaluate(intent)
        if decision.outcome == "allow" and decision.permit is not None:
            self.kernel._state.bind_permit_to_directive(
                decision.permit,
                digest,
                directive.permit_binding,
                now_ns,
            )
        return decision

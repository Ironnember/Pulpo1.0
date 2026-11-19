"""Governed directive projection over Pulpo's existing authority and evidence seams.

Directives constrain execution. They do not create authority, mint permits, or
form a second policy/evidence truth. Activation and revocation are themselves
consequential governance actions and must pass through the existing kernel's
pinned external approval verifier before canonical directive state can change.

Directive state and trusted time are kernel-owned. This module deliberately has
no constructor injection point for an alternate directive state or clock.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json

from .authority import ApprovalEnvelope
from .kernel import Decision, GovernanceKernel, Intent
from .state import (
    DirectiveBudget,
    DirectivePermitBinding,
    VerifiedAuthorityEvidence,
    budget_scope_key,
)


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
    # Cumulative budget (kernel build item #1): the aggregate ceiling
    # over every permit consumed under this directive, in Intent.cost
    # units — where max_cost bounds each act, this bounds the total.
    # None (the default) means no aggregate budget: behavior is then
    # exactly the pre-budget behavior, and the three fields below are
    # excluded from the directive hash so budget-less directives keep
    # their existing identity. When a budget is set, the scope and
    # session-reset rule are explicit policy, stated here in the
    # definition (see DirectiveBudget), and all three fields are
    # bound into the hash like every other mandate term.
    aggregate_budget: int | None = None
    budget_scope: tuple[str, ...] = ("directive",)
    budget_session_reset: bool = False

    def __post_init__(self) -> None:
        if not self.directive_id or not self.issuer_authority_id or not self.principal:
            raise ValueError("directive identity fields must be non-empty")
        if self.version <= 0 or not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("directive scope must be non-empty and versioned")
        if self.max_cost < 0 or self.issued_at_ns <= 0 or self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("directive bounds are invalid")
        if self.schema != "pulpo.directive.v1":
            raise ValueError("unsupported directive schema")
        object.__setattr__(self, "budget_scope", tuple(self.budget_scope))
        if self.aggregate_budget is None:
            if self.budget_scope != ("directive",) or self.budget_session_reset:
                raise ValueError("directive budget scope requires an aggregate budget")
        else:
            # The state layer's policy validation, applied at
            # construction so a malformed budget policy fails
            # identically everywhere it is read.
            DirectiveBudget(self.aggregate_budget, self.budget_scope, self.budget_session_reset)

    @property
    def directive_hash(self) -> str:
        payload = asdict(self)
        payload["allowed_actions"] = sorted(self.allowed_actions)
        if self.aggregate_budget is None:
            # Byte-stability for budget-less directives: their hash
            # payload is exactly the pre-budget field set, so a
            # directive already activated under the old definition
            # keeps its identity across this change.
            payload.pop("aggregate_budget")
            payload.pop("budget_scope")
            payload.pop("budget_session_reset")
        return sha256(_canonical(payload)).hexdigest()

    def budget_scope_key(self, intent: Intent) -> str | None:
        """The budget bucket an intent under this directive debits.

        None when the directive carries no aggregate budget. The key
        is computed from the policy's stated scope and the intent's
        own principal/session — the same facts the projection records
        on the permit binding, which is what consume later debits.
        """

        if self.aggregate_budget is None:
            return None
        return budget_scope_key(
            self.budget_scope,
            directive_id=self.directive_id,
            version=self.version,
            principal=intent.principal,
            session_id=intent.session_id,
        )

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
        if parent.aggregate_budget is not None and (
            self.aggregate_budget is None
            or self.aggregate_budget > parent.aggregate_budget
            or self.budget_scope != parent.budget_scope
            or self.budget_session_reset != parent.budget_session_reset
        ):
            # A child may narrow a parent's aggregate ceiling but may
            # never drop it, raise it, or reshape its scope: a
            # different scope re-buckets the same spend (per-session
            # buckets under a per-directive ceiling multiply the
            # effective total), which is broadening by another name.
            return "directive_parent_aggregate_budget_broadened"
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
    ) -> VerifiedAuthorityEvidence:
        # Item 3A: this is the only production construction site for
        # VerifiedAuthorityEvidence, and it is reached only after
        # _authorize has verified the envelope through the kernel and
        # consumed the one-use authority permit. The state layer
        # requires the type, so the evidence can no longer be an
        # opaque dict a handle holder invents (design repro 3, part B).
        return VerifiedAuthorityEvidence(
            operation=operation,
            directive_id=directive.directive_id,
            directive_version=directive.version,
            directive_hash=directive.directive_hash,
            parent_directive_hash=directive.parent_directive_hash,
            authority_id=envelope.authority_id,
            approval_id=envelope.approval_id,
            envelope_hash=envelope.envelope_hash,
            intent_hash=kernel.intent_hash(authority_intent),
            policy_hash=kernel.policy_hash,
        )

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
        parent_status = self.kernel.directive_hash_status(parent_directive.directive_hash)
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
            self.kernel.activate_directive(
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
        self.kernel.revoke_directive(
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

    def _deny(self, intent: Intent, directive: Directive, reason: str, digest: str) -> Decision:
        # Kernel build item #2: a directive-scope denial is a
        # governed effect (evidence production), so it is recorded in
        # the canonical audit through the kernel's fixed-schema verb
        # — exactly one record per denied attempt, like kernel-reached
        # denials. The Decision returned is the one the projection has
        # always returned; only its visibility changes.
        self.kernel.record_directive_denial(
            intent,
            directive_id=directive.directive_id,
            version=directive.version,
            directive_hash=directive.directive_hash,
            reason=reason,
        )
        return Decision("deny", reason, digest)

    def evaluate(self, intent: Intent, directive: Directive) -> Decision:
        status = self.kernel.directive_status(
            directive.directive_id,
            directive.version,
            directive.directive_hash,
        )
        digest = self.kernel.intent_hash(intent)
        if status != "active":
            return self._deny(intent, directive, status, digest)
        if directive.parent_directive_hash is not None:
            parent_status = self.kernel.directive_hash_status(directive.parent_directive_hash)
            if parent_status != "active":
                return self._deny(intent, directive, parent_status, digest)
        now_ns = self._trusted_now()
        failure = directive.permits(intent, now_ns)
        if failure:
            return self._deny(intent, directive, failure, digest)
        budget_key = directive.budget_scope_key(intent)
        if budget_key is not None and directive.aggregate_budget is not None:
            # Early optimization ONLY (build item #1, design point 1):
            # refuse issuance when the bucket's already-consumed total
            # plus this intent's cost would cross the ceiling.
            # Outstanding unconsumed permits are not counted here —
            # several can pass this check against the same remaining
            # allowance — so this never substitutes for the decisive
            # atomic check-and-debit at consume time in the backend.
            if self.kernel.budget_spent(budget_key) + intent.cost > directive.aggregate_budget:
                return self._deny(intent, directive, "directive_aggregate_budget_exceeded", digest)

        decision = self.kernel.evaluate(intent)
        if decision.outcome == "allow" and decision.permit is not None:
            binding = directive.permit_binding
            if directive.aggregate_budget is not None:
                # Record the evaluated intent's budget facts on the
                # binding: the consume-time debit is computed from
                # this governed record, never from a quantity a
                # caller presents later at release time.
                binding = replace(
                    binding,
                    budget_principal=intent.principal,
                    budget_session_id=intent.session_id,
                    budget_cost=intent.cost,
                )
            self.kernel.bind_permit_to_directive(
                decision.permit,
                digest,
                binding,
                now_ns,
            )
        return decision

"""Thin coordination over Pulpo's existing governance, authority, and execution seams.

The orchestrator does not decide policy, authenticate authority, mint permits,
execute arbitrary tools, or create another evidence ledger. It composes the
canonical kernel, external authority client, directive projection, commerce
executor, and audit projection into one explicit workflow surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .authority import ApprovalEnvelope
from .authority_client import AuthorityApprovalRequest, AuthorityClient, AuthorityPoll
from .commerce import (
    BudgetState,
    CommerceOutcome,
    DomainCommerceExecutor,
    DomainPurchaseOrder,
    RegistrarAdapter,
)
from .directives import (
    Directive,
    DirectiveAuthorityController,
    DirectiveState,
    GovernedDirectiveProjection,
)
from .kernel import Decision, GovernanceKernel, Intent, LockedTarget, TargetResolution
from .targets import evaluate_locked_target_with_approval


class OrchestrationError(RuntimeError):
    """Raised when orchestration cannot safely reach the canonical component."""


@dataclass(frozen=True)
class ApprovalHandle:
    """Non-authoritative reference to one external approval request."""

    target_id: str
    version: int
    target_hash: str
    request_id: str
    approval_url: str


@dataclass(frozen=True)
class AuthorizationAttempt:
    """Result of re-resolving a target and consulting external authority."""

    handle: ApprovalHandle
    resolution: TargetResolution
    poll: AuthorityPoll | None = None
    decision: Decision | None = None


@dataclass(frozen=True)
class EvidenceSnapshot:
    """Read-only projection of the canonical kernel audit chain."""

    policy_hash: str
    audit_valid: bool
    audit_records: int
    audit_tip: str | None
    schema: str = "pulpo.orchestration-evidence.v0"


class PulpoOrchestrator:
    """Coordinate governed work without becoming another trust domain.

    Intelligence may use this surface to lock an exact proposal, ask the
    independent authority service for an approval envelope, return that envelope
    to the one governance kernel, delegate approved execution to an existing
    bounded executor, and project resulting canonical evidence.
    """

    def __init__(
        self,
        kernel: GovernanceKernel,
        *,
        authority_client: AuthorityClient | None = None,
        directive_state: DirectiveState | None = None,
        clock: Callable[[], int] | None = None,
        commerce_executor: DomainCommerceExecutor | None = None,
    ) -> None:
        self.kernel = kernel
        self.authority_client = authority_client
        self.directive_state = directive_state
        self.clock = clock
        self.commerce_executor = commerce_executor or DomainCommerceExecutor()

    def lock_target(self, target_id: str, intent: Intent, *, version: int = 1) -> LockedTarget:
        """Persist one exact proposed consequence with no authority effect."""

        return self.kernel.lock_target(target_id, intent, version=version)

    def request_target_approval(
        self,
        target: LockedTarget,
        *,
        requested_ttl_ns: int,
    ) -> ApprovalHandle:
        """Ask external authority about one currently exact locked target.

        The request carries the current intent and policy hashes but no permit.
        The target is resolved from canonical state before anything is sent.
        """

        client = self.authority_client
        if client is None:
            raise OrchestrationError("authority_client_unavailable")
        resolution = self.kernel.resolve_locked_target(
            target.target_id,
            target.target_hash,
            version=target.version,
        )
        if resolution.outcome != "match" or resolution.target is None:
            raise OrchestrationError(resolution.reason)
        trust = self.kernel.policy.authority_trust
        if trust is None:
            raise OrchestrationError("authority_trust_unavailable")
        if requested_ttl_ns <= 0 or requested_ttl_ns > trust.max_approval_ttl_ns:
            raise OrchestrationError("approval_ttl_out_of_policy")

        intent = resolution.target.intent
        request = AuthorityApprovalRequest(
            principal=intent.principal,
            action=intent.action,
            resource=intent.resource,
            cost=intent.cost,
            session_id=intent.session_id,
            intent_hash=self.kernel.intent_hash(intent),
            policy_hash=self.kernel.policy_hash,
            deployment_id=trust.deployment_id,
            requested_ttl_ns=requested_ttl_ns,
        )
        request_id, approval_url = client.request_approval(request)
        return ApprovalHandle(
            target_id=target.target_id,
            version=target.version,
            target_hash=target.target_hash,
            request_id=request_id,
            approval_url=approval_url,
        )

    def authorize_target(self, handle: ApprovalHandle) -> AuthorizationAttempt:
        """Revalidate target identity, poll authority, then delegate to kernel.

        A changed or missing target stops before a returned envelope can be used.
        Pending, denied, or expired authority responses never reach permit
        issuance. An approved response still has to pass the kernel's complete
        pinned-envelope verification path.
        """

        resolution = self.kernel.resolve_locked_target(
            handle.target_id,
            handle.target_hash,
            version=handle.version,
        )
        if resolution.outcome != "match" or resolution.target is None:
            return AuthorizationAttempt(handle=handle, resolution=resolution)

        client = self.authority_client
        if client is None:
            raise OrchestrationError("authority_client_unavailable")
        poll = client.poll_approval(handle.request_id)
        if poll.status != "approved" or poll.envelope is None:
            return AuthorizationAttempt(handle=handle, resolution=resolution, poll=poll)

        exact_resolution, decision = evaluate_locked_target_with_approval(
            self.kernel,
            handle.target_id,
            handle.target_hash,
            poll.envelope,
            version=handle.version,
        )
        return AuthorizationAttempt(
            handle=handle,
            resolution=exact_resolution,
            poll=poll,
            decision=decision,
        )

    def consume_authorized_target(self, attempt: AuthorizationAttempt) -> bool:
        """Consume the kernel-issued capability for the still-exact target once."""

        decision = attempt.decision
        if decision is None or decision.outcome != "allow" or decision.permit is None:
            return False
        resolution = self.kernel.resolve_locked_target(
            attempt.handle.target_id,
            attempt.handle.target_hash,
            version=attempt.handle.version,
        )
        if resolution.outcome != "match" or resolution.target is None:
            return False
        return self.kernel.consume(decision.permit, resolution.target.intent)

    def activate_directive(
        self,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str = "default",
    ) -> Decision:
        """Delegate directive activation to the existing authority controller."""

        controller = self._directive_controller()
        return controller.activate(
            directive,
            envelope,
            operator_principal=operator_principal,
            session_id=session_id,
        )

    def revoke_directive(
        self,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str = "default",
    ) -> Decision:
        """Delegate directive revocation to the existing authority controller."""

        controller = self._directive_controller()
        return controller.revoke(
            directive,
            envelope,
            operator_principal=operator_principal,
            session_id=session_id,
        )

    def evaluate_directive(self, intent: Intent, directive: Directive) -> Decision:
        """Apply live directive state before the one governance kernel."""

        state, clock = self._directive_dependencies()
        return GovernedDirectiveProjection(self.kernel, state, clock).evaluate(intent, directive)

    def execute_domain_purchase(
        self,
        order: DomainPurchaseOrder,
        permit: str,
        adapter: RegistrarAdapter,
        budget: BudgetState,
        reservation_id: str,
        *,
        now_ns: int,
    ) -> CommerceOutcome:
        """Delegate one exact purchase to the canonical bounded executor."""

        return self.commerce_executor.execute(
            self.kernel,
            order,
            permit,
            adapter,
            budget,
            reservation_id,
            now_ns=now_ns,
        )

    def evidence_snapshot(self) -> EvidenceSnapshot:
        """Return a projection of canonical evidence without creating new state."""

        audit = self.kernel.audit
        return EvidenceSnapshot(
            policy_hash=self.kernel.policy_hash,
            audit_valid=self.kernel.verify_audit(),
            audit_records=len(audit),
            audit_tip=audit[-1]["hash"] if audit else None,
        )

    def _directive_dependencies(self) -> tuple[DirectiveState, Callable[[], int]]:
        if self.directive_state is None:
            raise OrchestrationError("directive_state_unavailable")
        if self.clock is None:
            raise OrchestrationError("directive_clock_unavailable")
        return self.directive_state, self.clock

    def _directive_controller(self) -> DirectiveAuthorityController:
        state, clock = self._directive_dependencies()
        return DirectiveAuthorityController(self.kernel, state, clock)

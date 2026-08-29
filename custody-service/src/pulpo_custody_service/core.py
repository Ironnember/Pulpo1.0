"""Narrow service facade over canonical Pulpo governance/custody components.

The service owns the trusted dependencies. A hostile worker may submit an exact
order, request the immutable approval challenge for that exact locked target,
return a signed external approval envelope when policy requires it, and use
opaque attempt references. It cannot inject time, budget state, permits,
provider credentials, custody roots, or alternate executors/observers.

The canonical SQLite kernel backend intentionally owns a normal thread-bound
SQLite connection. A web service therefore must not keep one kernel connection
alive across request worker threads. `kernel_factory` opens a fresh kernel/state
session inside the current request thread while all sessions share the same
durable database. This preserves SQLite's own thread contract rather than
turning thread checks off.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Callable, Iterator

from pulpo.authority import ApprovalEnvelope
from pulpo.commerce import DomainPurchaseOrder, SQLiteBudgetAccount, purchase_intent
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_executor import (
    CustodyRegistrarAdapter,
    ExternalConsequenceUnknown,
    ProviderAttemptClaim,
    TrustedDomainExecutor,
)
from pulpo.custody_reconcile import (
    DomainReconciliationResult,
    IndependentDomainReconciler,
)
from pulpo.kernel import GovernanceKernel
from pulpo.namecom_observer import NameComCoreObserver


class ServiceRejected(RuntimeError):
    """A request failed the canonical custody/service boundary."""


@dataclass(frozen=True)
class ApprovalChallenge:
    """Exact non-authorizing request compatible with the existing authority service."""

    target_id: str
    target_hash: str
    principal: str
    action: str
    resource: str
    cost: int
    session_id: str
    intent_hash: str
    policy_hash: str
    deployment_id: str | None
    requested_ttl_ns: int | None
    approval_required: bool
    schema: str = "pulpo.custody-approval-challenge.v0"

    def authority_request(self) -> dict[str, object] | None:
        """Return the exact `pulpo.authority-request.v1` payload when required."""

        if not self.approval_required:
            return None
        assert self.deployment_id is not None
        assert self.requested_ttl_ns is not None
        return {
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "cost": self.cost,
            "session_id": self.session_id,
            "intent_hash": self.intent_hash,
            "policy_hash": self.policy_hash,
            "deployment_id": self.deployment_id,
            "requested_ttl_ns": self.requested_ttl_ns,
            "schema": "pulpo.authority-request.v1",
        }


@dataclass(frozen=True)
class AttemptHandle:
    attempt_id: str
    order_hash: str
    target_hash: str
    reservation_id: str
    reserved_cents: int
    state: str
    schema: str = "pulpo.custody-attempt-handle.v0"


class DomainCustodyService:
    """One deployment boundary; no new policy or approval authority."""

    def __init__(
        self,
        *,
        kernel_factory: Callable[[], GovernanceKernel],
        custody: SQLiteGovernanceCustody,
        budget: SQLiteBudgetAccount,
        registrar: CustodyRegistrarAdapter,
        observer: NameComCoreObserver,
        observer_id: str,
        executor_id: str,
    ) -> None:
        if not callable(kernel_factory):
            raise ValueError("kernel_factory is required")
        if not observer_id or not executor_id:
            raise ValueError("observer_id and executor_id are required")
        self._kernel_factory = kernel_factory
        self.custody = custody
        self.budget = budget
        self.registrar = registrar
        self.observer = observer
        self.executor = TrustedDomainExecutor(custody, executor_id=executor_id)
        self.reconciler = IndependentDomainReconciler(
            custody,
            budget,
            observer_id=observer_id,
        )

    @contextmanager
    def _kernel_session(self) -> Iterator[GovernanceKernel]:
        """Open and close one request-local kernel state connection."""

        kernel = self._kernel_factory()
        if not isinstance(kernel, GovernanceKernel):
            raise ServiceRejected("kernel_factory_invalid")
        try:
            yield kernel
        finally:
            state = getattr(kernel, "_state", None)
            close = getattr(state, "close", None)
            if callable(close):
                close()

    @staticmethod
    def _target_id(order: DomainPurchaseOrder) -> str:
        return f"custody-domain:{order.order_hash}"

    def prepare_approval(self, order: DomainPurchaseOrder) -> ApprovalChallenge:
        """Lock the exact target and expose only non-authorizing approval material."""

        with self._kernel_session() as kernel:
            intent = purchase_intent(order)
            target = kernel.lock_target(self._target_id(order), intent)
            resolution = kernel.resolve_locked_target(target.target_id, target.target_hash)
            if resolution.outcome != "match" or resolution.target is None:
                raise ServiceRejected(f"target_rejected:{resolution.reason}")
            approval_required = intent.action in kernel.policy.approval_actions
            trust = kernel.policy.authority_trust
            if approval_required and trust is None:
                raise ServiceRejected("approval_policy_missing_trust")
            return ApprovalChallenge(
                target_id=target.target_id,
                target_hash=target.target_hash,
                principal=intent.principal,
                action=intent.action,
                resource=intent.resource,
                cost=intent.cost,
                session_id=intent.session_id,
                intent_hash=kernel.intent_hash(intent),
                policy_hash=kernel.policy_hash,
                deployment_id=trust.deployment_id if trust is not None else None,
                requested_ttl_ns=trust.max_approval_ttl_ns if approval_required and trust is not None else None,
                approval_required=approval_required,
            )

    def authorize(
        self,
        order: DomainPurchaseOrder,
        *,
        approval: ApprovalEnvelope | None = None,
    ) -> AttemptHandle:
        """Create one attempt only through canonical kernel + protected budget."""

        with self._kernel_session() as kernel:
            coordinator = GovernedDomainAttemptCoordinator(kernel, self.custody, self.budget)
            intent = purchase_intent(order)
            target = kernel.lock_target(self._target_id(order), intent)
            resolution = kernel.resolve_locked_target(target.target_id, target.target_hash)
            if resolution.outcome != "match" or resolution.target is None:
                raise ServiceRejected(f"target_rejected:{resolution.reason}")

            if intent.action in kernel.policy.approval_actions:
                if approval is None:
                    raise ServiceRejected("external_approval_required")
                decision = kernel.evaluate_with_approval(intent, approval)
            else:
                if approval is not None:
                    raise ServiceRejected("unexpected_approval_for_policy")
                decision = kernel.evaluate(intent)
            if decision.outcome != "allow" or decision.permit is None:
                raise ServiceRejected(f"authorization_rejected:{decision.reason}")

            try:
                reservation = coordinator.reserve(order)
                governed = coordinator.authorize(
                    target_id=target.target_id,
                    expected_target_hash=target.target_hash,
                    order=order,
                    permit=decision.permit,
                    reservation_id=reservation.reservation_id,
                )
            except Exception as exc:
                raise ServiceRejected(f"custody_authorization_failed:{exc}") from exc

        return AttemptHandle(
            attempt_id=governed.attempt_id,
            order_hash=governed.order_hash,
            target_hash=governed.target_hash,
            reservation_id=governed.reservation_id,
            reserved_cents=governed.reserved_cents,
            state=self.custody.ATTEMPT_AUTHORIZED,
        )

    def _ref(self, handle: AttemptHandle):
        snapshot = self.custody.attempt(handle.attempt_id)
        if snapshot is None:
            raise ServiceRejected("attempt_unknown")
        if snapshot.object_hash != handle.order_hash:
            raise ServiceRejected("attempt_handle_order_mismatch")
        return SimpleNamespace(
            attempt_id=handle.attempt_id,
            order_hash=handle.order_hash,
            reservation_id=handle.reservation_id,
        )

    def execute(self, handle: AttemptHandle, order: DomainPurchaseOrder) -> ProviderAttemptClaim | None:
        if order.order_hash != handle.order_hash:
            raise ServiceRejected("execute_order_mismatch")
        try:
            return self.executor.execute(self._ref(handle), order, self.registrar)
        except ExternalConsequenceUnknown:
            return None
        except CustodyViolation as exc:
            raise ServiceRejected(f"execution_rejected:{exc}") from exc

    def reconcile(self, handle: AttemptHandle, order: DomainPurchaseOrder) -> DomainReconciliationResult:
        if order.order_hash != handle.order_hash:
            raise ServiceRejected("reconcile_order_mismatch")
        ref = self._ref(handle)
        try:
            observation = self.observer.observe(ref, order)
            return self.reconciler.reconcile(ref, order, observation)
        except CustodyViolation as exc:
            raise ServiceRejected(f"reconciliation_rejected:{exc}") from exc

    def status(self, attempt_id: str) -> dict[str, object]:
        snapshot = self.custody.attempt(attempt_id)
        if snapshot is None:
            raise ServiceRejected("attempt_unknown")
        head = self.custody.snapshot()
        return {
            "attempt_id": snapshot.attempt_id,
            "order_hash": snapshot.object_hash,
            "state": snapshot.state,
            "provider_request_id": snapshot.provider_request_id,
            "reconciliation_outcome": snapshot.reconciliation_outcome,
            "governance_epoch": head.epoch,
            "governance_state_root": head.state_root,
        }

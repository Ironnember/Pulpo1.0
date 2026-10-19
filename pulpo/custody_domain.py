"""Domain-specific bridge from canonical Pulpo authorization into V0 custody.

This is not another router, budget system, or policy engine. It accepts only the
already-bounded `purchase_domain` object, re-resolves the exact locked target
from the canonical kernel, checks the existing durable commerce budget from the
trusted custody process, consumes the canonical one-use permit (including live
directive revalidation), marks the exact reservation attempted, then records one
monotonic custody attempt.

The bridge belongs inside the trusted V0 governance-custody process. A hostile
worker receives only opaque target/reservation/attempt references; it does not
supply the authoritative budget object or authority time.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any

from .commerce import BudgetReservation, DomainPurchaseOrder, SQLiteBudgetAccount, purchase_intent
from .custody import AttemptAuthorization, CustodyViolation, SQLiteGovernanceCustody
from .kernel import GovernanceKernel


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class GovernedDomainAttempt:
    attempt_id: str
    order_hash: str
    target_hash: str
    intent_hash: str
    policy_hash: str
    reservation_id: str
    reserved_cents: int
    canonical_audit_tip: str
    custody: AttemptAuthorization


class GovernedDomainAttemptCoordinator:
    """Turn one canonical domain permit + protected reservation into one attempt.

    `kernel`, `custody`, and `budget` are trusted-process dependencies. They are
    construction-time custody components, not request fields controlled by the
    hostile worker.
    """

    def __init__(
        self,
        kernel: GovernanceKernel,
        custody: SQLiteGovernanceCustody,
        budget: SQLiteBudgetAccount,
    ) -> None:
        self.kernel = kernel
        self.custody = custody
        self.budget = budget

    def _trusted_now(self) -> int:
        # One V0 custody clock. Worker time is never accepted. This uses the
        # custody component's internal monotonic check without advancing the
        # governance head merely to observe time.
        head = self.custody.snapshot()
        return self.custody._custody_now(head)

    def reserve(self, order: DomainPurchaseOrder) -> BudgetReservation:
        """Reserve the exact order against protected budget using custody time."""

        return self.budget.reserve(order, now_ns=self._trusted_now())

    def authorize(
        self,
        *,
        target_id: str,
        expected_target_hash: str,
        order: DomainPurchaseOrder,
        permit: str,
        reservation_id: str,
        version: int = 1,
    ) -> GovernedDomainAttempt:
        if not permit:
            raise CustodyViolation("canonical_permit_required")
        if not reservation_id:
            raise CustodyViolation("budget_reservation_required")

        resolution = self.kernel.resolve_locked_target(
            target_id,
            expected_target_hash,
            version=version,
        )
        if resolution.outcome != "match" or resolution.target is None:
            raise CustodyViolation(resolution.reason)

        exact_intent = purchase_intent(order)
        if resolution.target.intent != exact_intent:
            raise CustodyViolation("custody_order_target_mismatch")

        # The trusted coordinator reads the existing durable budget. A stale
        # worker balance or a worker-created substitute BudgetState is ignored.
        try:
            reservation = self.budget.require_active(
                reservation_id,
                order,
                now_ns=self._trusted_now(),
            )
        except Exception as exc:
            raise CustodyViolation(f"protected_budget_rejected:{exc}") from exc

        # Existing canonical one-use consumption point. For a directive-bound
        # permit, the state backend revalidates exact id/version/hash/revocation
        # and validity window here before returning true.
        if not self.kernel.consume(permit, exact_intent):
            raise CustodyViolation("canonical_permit_rejected")

        audit = self.kernel.audit
        if not audit or audit[-1].get("event") != "permit_consumed":
            raise CustodyViolation("canonical_consumption_evidence_missing")
        canonical_audit_tip = audit[-1]["hash"]

        # Forward-only ordering is intentional. If the process dies after the
        # canonical permit is spent or after the reservation becomes attempted,
        # availability may be lost, but no second execution right appears.
        try:
            self.budget.mark_attempted(reservation_id)
        except Exception as exc:
            raise CustodyViolation(f"protected_budget_attempt_failed:{exc}") from exc

        intent_hash = self.kernel.intent_hash(exact_intent)
        permit_hash = sha256(permit.encode()).hexdigest()
        authorization_hash = _hash(
            {
                "schema": "pulpo.custody-authorization.v0",
                "target_hash": expected_target_hash,
                "order_hash": order.order_hash,
                "intent_hash": intent_hash,
                "policy_hash": self.kernel.policy_hash,
                "permit_hash": permit_hash,
                "reservation_id": reservation.reservation_id,
                "reserved_cents": reservation.reserved_cents,
                "budget_ceiling_cents": self.budget.ceiling_cents,
                "canonical_audit_tip": canonical_audit_tip,
            }
        )

        # The trusted coordinator, not the worker, reads the current custody
        # head. Worker-local epoch/root copies are therefore never authority.
        head = self.custody.snapshot()
        custody_authorization = self.custody.authorize_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            object_hash=order.order_hash,
            target_hash=expected_target_hash,
            permit_hash=permit_hash,
            authorization_hash=authorization_hash,
        )
        return GovernedDomainAttempt(
            attempt_id=custody_authorization.attempt_id,
            order_hash=order.order_hash,
            target_hash=expected_target_hash,
            intent_hash=intent_hash,
            policy_hash=self.kernel.policy_hash,
            reservation_id=reservation.reservation_id,
            reserved_cents=reservation.reserved_cents,
            canonical_audit_tip=canonical_audit_tip,
            custody=custody_authorization,
        )

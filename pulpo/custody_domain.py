"""Domain-specific bridge from canonical Pulpo authorization into V0 custody.

This is not another router or policy engine.  It accepts only the already-bounded
`purchase_domain` object, re-resolves the exact locked target from the canonical
kernel, consumes the canonical one-use permit (including live directive
revalidation), then records one monotonic custody attempt.

The bridge belongs inside the trusted V0 governance-custody process.  A hostile
worker receives only the resulting opaque attempt reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any

from .commerce import DomainPurchaseOrder, purchase_intent
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
    canonical_audit_tip: str
    custody: AttemptAuthorization


class GovernedDomainAttemptCoordinator:
    """Turn one consumed canonical domain permit into one custody attempt."""

    def __init__(
        self,
        kernel: GovernanceKernel,
        custody: SQLiteGovernanceCustody,
    ) -> None:
        self.kernel = kernel
        self.custody = custody

    def authorize(
        self,
        *,
        target_id: str,
        expected_target_hash: str,
        order: DomainPurchaseOrder,
        permit: str,
        version: int = 1,
    ) -> GovernedDomainAttempt:
        if not permit:
            raise CustodyViolation("canonical_permit_required")

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

        # This is the existing canonical one-use consumption point.  For a
        # directive-bound permit, the state backend revalidates the directive's
        # exact id/version/hash/revocation/time window here before returning true.
        if not self.kernel.consume(permit, exact_intent):
            raise CustodyViolation("canonical_permit_rejected")

        audit = self.kernel.audit
        if not audit or audit[-1].get("event") != "permit_consumed":
            raise CustodyViolation("canonical_consumption_evidence_missing")
        canonical_audit_tip = audit[-1]["hash"]
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
                "canonical_audit_tip": canonical_audit_tip,
            }
        )

        # The trusted coordinator, not the worker, reads the current custody
        # head.  Worker-local epoch/root copies are therefore never authority.
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
            canonical_audit_tip=canonical_audit_tip,
            custody=custody_authorization,
        )

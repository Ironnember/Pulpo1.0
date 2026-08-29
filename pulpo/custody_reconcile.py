"""Independent domain observation and reconciliation for Hostile Worker V0.

The hostile worker and credential-bearing executor may report claims, but neither
can mark a consequence accepted or settle protected budget. This reconciler is
intended to run outside the worker trust domain with its own observation path,
identity, and access to the existing durable commerce budget.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any

from .commerce import (
    DomainPurchaseOrder,
    PaymentEvidence,
    Reconciliation,
    SQLiteBudgetAccount,
)
from .custody import CustodyViolation, SQLiteGovernanceCustody, TransitionReceipt
from .custody_domain import GovernedDomainAttempt


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _valid_hash(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True)
class IndependentDomainObservation:
    observation_id: str
    provider_request_id: str
    provider_request_status: str
    domain: str | None
    registrar: str | None
    owner_ref: str | None
    registered: bool | None
    payment_id: str | None
    charged_cents: int | None
    receipt_hash: str | None
    privacy_enabled: bool | None
    dns_state: str | None
    schema: str = "pulpo.domain-observation.v0"

    def __post_init__(self) -> None:
        if not self.observation_id or not self.provider_request_id:
            raise CustodyViolation("observation_identity_required")
        if self.provider_request_status not in {
            "succeeded",
            "failed",
            "not_found",
            "unknown",
        }:
            raise CustodyViolation("provider_request_status_invalid")
        if self.payment_id is not None and not self.payment_id:
            raise CustodyViolation("observation_payment_id_invalid")
        if self.charged_cents is not None and self.charged_cents < 0:
            raise CustodyViolation("observation_charge_invalid")
        if self.receipt_hash is not None and not _valid_hash(self.receipt_hash):
            raise CustodyViolation("observation_receipt_hash_invalid")

    @property
    def observation_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class DomainReconciliationResult:
    outcome: str
    reason: str
    observation_hash: str
    receipt: TransitionReceipt
    budget_reconciliation: Reconciliation | None = None


class IndependentDomainReconciler:
    """Classify reality and settle budget from a trusted independent observer."""

    def __init__(
        self,
        custody: SQLiteGovernanceCustody,
        budget: SQLiteBudgetAccount,
        *,
        observer_id: str,
    ) -> None:
        if not observer_id:
            raise CustodyViolation("observer_id_required")
        self.custody = custody
        self.budget = budget
        self.observer_id = observer_id

    @staticmethod
    def _classify(
        order: DomainPurchaseOrder,
        provider_request_id: str | None,
        observation: IndependentDomainObservation,
    ) -> tuple[str, str]:
        if provider_request_id is None:
            return "unresolved", "provider_request_identity_missing"
        if observation.provider_request_id != provider_request_id:
            return "unresolved", "provider_request_identity_mismatch"

        if observation.provider_request_status == "unknown":
            return "unresolved", "provider_status_unknown"
        if observation.provider_request_status == "not_found":
            # Absence from one lookup is not strong enough to prove no real-world
            # consequence; eventual consistency and provider failure modes remain.
            return "unresolved", "provider_request_not_found"

        if observation.provider_request_status == "failed":
            if observation.registered is True or (
                observation.charged_cents is not None and observation.charged_cents > 0
            ):
                return "unresolved", "failure_status_conflicts_with_observed_effect"
            return "failure", "provider_failure_independently_observed"

        # Provider success is insufficient by itself. Exact payment and side-
        # effect properties must match the authorized order.
        missing = (
            observation.domain is None
            or observation.registrar is None
            or observation.owner_ref is None
            or observation.registered is None
            or observation.payment_id is None
            or observation.charged_cents is None
            or observation.receipt_hash is None
            or observation.privacy_enabled is None
            or observation.dns_state is None
        )
        if missing:
            return "unresolved", "success_observation_incomplete"
        if observation.domain != order.domain:
            return "failure", "observed_domain_mismatch"
        if observation.registrar != order.registrar:
            return "failure", "observed_registrar_mismatch"
        if observation.owner_ref != order.owner_ref:
            return "failure", "observed_owner_mismatch"
        if observation.registered is not True:
            return "failure", "registration_not_observed"
        if observation.charged_cents > order.purchase_price_cents:
            return "failure", "observed_charge_exceeded_authorization"
        if order.privacy_required and observation.privacy_enabled is not True:
            return "failure", "observed_privacy_mismatch"
        if observation.dns_state not in {"registered", "configured"}:
            return "failure", "observed_dns_state_not_accepted"
        return "success", "external_consequence_verified"

    def _commit_observation(
        self,
        *,
        governed: GovernedDomainAttempt,
        prior_state: str,
        outcome: str,
        observation: IndependentDomainObservation,
    ) -> TransitionReceipt:
        """Commit first or later evidence without reopening execution rights.

        `UNRESOLVED` means evidence is incomplete, not that reality can never be
        known. Later trusted observation may move it to success/failure. No path
        from unresolved returns to an executable state.
        """

        head = self.custody.snapshot()
        if prior_state != self.custody.UNRESOLVED:
            return self.custody.reconcile_observed(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                attempt_id=governed.attempt_id,
                outcome=outcome,
                observation_hash=observation.observation_hash,
                observer_id=self.observer_id,
            )

        next_state = {
            "success": self.custody.RECONCILED_SUCCESS,
            "failure": self.custody.RECONCILED_FAILURE,
            "unresolved": self.custody.UNRESOLVED,
        }[outcome]
        return self.custody._transition_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            required_states=frozenset({self.custody.UNRESOLVED}),
            next_state=next_state,
            payload={
                "observer_id": self.observer_id,
                "observation_hash": observation.observation_hash,
                "reconciliation_outcome": outcome,
                "later_evidence": True,
            },
            updates={
                "observation_hash": observation.observation_hash,
                "reconciliation_outcome": outcome,
            },
        )

    def reconcile(
        self,
        governed: GovernedDomainAttempt,
        order: DomainPurchaseOrder,
        observation: IndependentDomainObservation,
    ) -> DomainReconciliationResult:
        if order.order_hash != governed.order_hash:
            raise CustodyViolation("reconciliation_order_mismatch")
        attempt = self.custody.attempt(governed.attempt_id)
        if attempt is None or attempt.object_hash != order.order_hash:
            raise CustodyViolation("reconciliation_attempt_mismatch")
        if attempt.state not in {
            self.custody.REQUEST_TRANSMITTED,
            self.custody.RECONCILIATION_REQUIRED,
            self.custody.UNRESOLVED,
        }:
            raise CustodyViolation("reconciliation_state_not_open")

        outcome, reason = self._classify(
            order,
            attempt.provider_request_id,
            observation,
        )

        budget_reconciliation = None
        if outcome == "success":
            # Settle protected budget before canonical success. If this fails,
            # custody remains non-success rather than accepting a consequence
            # whose money state could not be reconciled.
            assert observation.payment_id is not None
            assert observation.charged_cents is not None
            assert observation.receipt_hash is not None
            try:
                budget_reconciliation = self.budget.reconcile(
                    governed.reservation_id,
                    PaymentEvidence(
                        observation.payment_id,
                        observation.charged_cents,
                        observation.receipt_hash,
                    ),
                )
            except Exception as exc:
                raise CustodyViolation(f"protected_budget_reconciliation_failed:{exc}") from exc

        # Failure and unresolved outcomes deliberately keep the attempted
        # reservation held in V0. Releasing uncertain money would recreate
        # spend authority. A later explicitly governed no-charge release may be
        # added only with equally strong external evidence.
        receipt = self._commit_observation(
            governed=governed,
            prior_state=attempt.state,
            outcome=outcome,
            observation=observation,
        )
        return DomainReconciliationResult(
            outcome=outcome,
            reason=reason,
            observation_hash=observation.observation_hash,
            receipt=receipt,
            budget_reconciliation=budget_reconciliation,
        )

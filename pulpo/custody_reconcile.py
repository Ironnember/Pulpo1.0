"""Independent domain observation, reconciliation, and governed outcome memory.

The hostile worker and credential-bearing executor may report claims, but neither
can mark a consequence accepted or settle protected budget. The reconciler is
intended to run outside the worker trust domain with its own observation path,
identity, and access to the existing durable commerce budget.

Outcome memory is projected only after the exact persisted reconciliation can be
re-derived from independent evidence. It is stored in the existing canonical
kernel audit, not in a second memory database, ledger, policy engine, or router.
Outcome memory can improve future competence but creates no permit or authority.
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
    purchase_intent,
)
from .custody import CustodyViolation, SQLiteGovernanceCustody, TransitionReceipt
from .custody_domain import GovernedDomainAttempt
from .kernel import GovernanceKernel


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
    auto_renew_enabled: bool | None = None
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
        if self.auto_renew_enabled is not None and type(self.auto_renew_enabled) is not bool:
            raise CustodyViolation("observation_auto_renew_invalid")

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


@dataclass(frozen=True)
class DomainOutcomeMemory:
    """Immutable projection of one exact reconciliation into canonical memory.

    A later reconciliation transition for the same attempt may produce a new
    memory record, preserving the earlier uncertainty/failure record rather than
    replacing history. Re-recording the same transition is idempotent.
    """

    memory_id: str
    attempt_id: str
    order_hash: str
    target_hash: str
    intent_hash: str
    policy_hash: str
    observation_hash: str
    reconciliation_transition_hash: str
    reconciliation_epoch: int
    reconciliation_outcome: str
    classification: str
    reason: str
    reusable: bool
    recorded_at_ns: int
    authority_effect: str = "none"
    governed_effect: str = "canonical_outcome_memory"
    schema: str = "pulpo.domain-outcome-memory.v0"

    def __post_init__(self) -> None:
        for value, field in (
            (self.memory_id, "memory_id"),
            (self.order_hash, "order_hash"),
            (self.target_hash, "target_hash"),
            (self.intent_hash, "intent_hash"),
            (self.policy_hash, "policy_hash"),
            (self.observation_hash, "observation_hash"),
            (self.reconciliation_transition_hash, "reconciliation_transition_hash"),
        ):
            if not _valid_hash(value):
                raise CustodyViolation(f"outcome_memory_{field}_invalid")
        if not self.attempt_id or self.reconciliation_epoch <= 0 or self.recorded_at_ns <= 0:
            raise CustodyViolation("outcome_memory_identity_invalid")
        if self.reconciliation_outcome not in {"success", "failure", "unresolved"}:
            raise CustodyViolation("outcome_memory_reconciliation_outcome_invalid")
        if self.classification not in {
            "SUCCESS_VERIFIED",
            "RECONCILIATION_MISMATCH",
            "RECONCILIATION_FAILURE",
            "EVIDENCE_FAILURE",
        }:
            raise CustodyViolation("outcome_memory_classification_invalid")
        if self.reusable != (self.classification == "SUCCESS_VERIFIED"):
            raise CustodyViolation("outcome_memory_reusable_classification_mismatch")
        if self.authority_effect != "none":
            raise CustodyViolation("outcome_memory_cannot_grant_authority")
        if self.governed_effect != "canonical_outcome_memory":
            raise CustodyViolation("outcome_memory_governed_effect_invalid")
        if self.schema != "pulpo.domain-outcome-memory.v0":
            raise CustodyViolation("outcome_memory_schema_invalid")


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
            or observation.auto_renew_enabled is None
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
        if observation.auto_renew_enabled != order.auto_renew_enabled:
            return "failure", "observed_auto_renew_mismatch"
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


class GovernedDomainOutcomeMemoryProjection:
    """Project trusted reconciliation into the existing canonical kernel audit.

    This object is deliberately stateless. The custody database remains the
    durable consequence state and the kernel audit remains canonical evidence and
    governed memory. The projection has no policy-evaluation or permit-minting
    path, and memory is explicitly non-authoritative.
    """

    EVENT = "domain_outcome_memory"
    CUSTODY_EVIDENCE_EVENT = "custody_transition"

    def __init__(
        self,
        kernel: GovernanceKernel,
        custody: SQLiteGovernanceCustody,
    ) -> None:
        self.kernel = kernel
        self.custody = custody

    def _trusted_now(self) -> int:
        now_ns = self.kernel._trusted_now()
        if now_ns is None:
            raise CustodyViolation("outcome_memory_clock_invalid")
        return now_ns

    def _target_is_exact(
        self,
        governed: GovernedDomainAttempt,
        order: DomainPurchaseOrder,
    ) -> None:
        if not self.kernel.verify_audit():
            raise CustodyViolation("outcome_memory_canonical_audit_invalid")
        intent = purchase_intent(order)
        intent_hash = self.kernel.intent_hash(intent)
        if governed.order_hash != order.order_hash:
            raise CustodyViolation("outcome_memory_order_mismatch")
        if governed.intent_hash != intent_hash:
            raise CustodyViolation("outcome_memory_intent_mismatch")
        if governed.policy_hash != self.kernel.policy_hash:
            raise CustodyViolation("outcome_memory_policy_mismatch")

        matching = []
        expected_intent = asdict(intent)
        for record in self.kernel.audit:
            if record.get("event") != "target_locked":
                continue
            payload = record.get("payload", {})
            if payload.get("target_hash") == governed.target_hash:
                matching.append(payload)
        if len(matching) != 1:
            raise CustodyViolation("outcome_memory_target_evidence_ambiguous")
        target = matching[0]
        if (
            target.get("intent_hash") != intent_hash
            or target.get("intent") != expected_intent
            or target.get("authority_effect") != "none"
        ):
            raise CustodyViolation("outcome_memory_target_mismatch")

    def _attempt_is_exact(
        self,
        governed: GovernedDomainAttempt,
        order: DomainPurchaseOrder,
        observation: IndependentDomainObservation,
        reconciliation: DomainReconciliationResult,
    ) -> tuple[str, str]:
        attempt = self.custody.attempt(governed.attempt_id)
        if attempt is None:
            raise CustodyViolation("outcome_memory_attempt_missing")
        if governed.custody.attempt_id != governed.attempt_id:
            raise CustodyViolation("outcome_memory_attempt_authorization_mismatch")
        authorization_receipt = governed.custody.receipt
        if not self.custody.verify_receipt(authorization_receipt):
            raise CustodyViolation("outcome_memory_authorization_receipt_invalid")
        if (
            authorization_receipt.transition_type != self.custody.ATTEMPT_AUTHORIZED
            or authorization_receipt.object_hash != order.order_hash
            or authorization_receipt.epoch != attempt.created_epoch
        ):
            raise CustodyViolation("outcome_memory_authorization_receipt_mismatch")
        if (
            attempt.object_hash != order.order_hash
            or attempt.target_hash != governed.target_hash
            or attempt.observation_hash != observation.observation_hash
            or attempt.observation_hash != reconciliation.observation_hash
            or attempt.reconciliation_outcome != reconciliation.outcome
        ):
            raise CustodyViolation("outcome_memory_persisted_reconciliation_mismatch")

        expected_outcome, expected_reason = IndependentDomainReconciler._classify(
            order,
            attempt.provider_request_id,
            observation,
        )
        if (
            reconciliation.outcome != expected_outcome
            or reconciliation.reason != expected_reason
        ):
            raise CustodyViolation("outcome_memory_reconciliation_result_mismatch")

        expected_state = {
            "success": self.custody.RECONCILED_SUCCESS,
            "failure": self.custody.RECONCILED_FAILURE,
            "unresolved": self.custody.UNRESOLVED,
        }[expected_outcome]
        receipt = reconciliation.receipt
        if not self.custody.verify_receipt(receipt):
            raise CustodyViolation("outcome_memory_reconciliation_receipt_invalid")
        if (
            attempt.state != expected_state
            or receipt.transition_type != expected_state
            or receipt.object_hash != order.order_hash
            or receipt.epoch != attempt.updated_epoch
        ):
            raise CustodyViolation("outcome_memory_reconciliation_receipt_mismatch")

        if expected_outcome == "success":
            budget = reconciliation.budget_reconciliation
            if (
                budget is None
                or budget.reservation_id != governed.reservation_id
                or budget.authorized_cents != order.purchase_price_cents
                or not budget.balanced
            ):
                raise CustodyViolation("outcome_memory_budget_reconciliation_missing")
        elif reconciliation.budget_reconciliation is not None:
            raise CustodyViolation("outcome_memory_unexpected_budget_reconciliation")

        return expected_outcome, expected_reason

    def _require_canonical_custody_evidence(self, receipt: TransitionReceipt) -> None:
        if not self.kernel.verify_audit():
            raise CustodyViolation("outcome_memory_canonical_audit_invalid")
        matches: list[dict[str, Any]] = []
        for record in self.kernel.audit:
            if record.get("event") != self.CUSTODY_EVIDENCE_EVENT:
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict):
                raise CustodyViolation("outcome_memory_custody_evidence_record_invalid")
            if payload.get("transition_hash") == receipt.transition_hash:
                matches.append(payload)
        if not matches:
            raise CustodyViolation("outcome_memory_custody_evidence_unprojected")
        if len(matches) != 1:
            raise CustodyViolation("outcome_memory_custody_evidence_ambiguous")
        evidence = matches[0]
        if (
            evidence.get("schema") != "pulpo.custody-evidence-projection.v0"
            or evidence.get("transition_hash") != receipt.transition_hash
            or evidence.get("receipt") != asdict(receipt)
        ):
            raise CustodyViolation("outcome_memory_custody_evidence_mismatch")

    @staticmethod
    def _classification(outcome: str, reason: str) -> tuple[str, bool]:
        if outcome == "success":
            return "SUCCESS_VERIFIED", True
        if outcome == "unresolved":
            return "EVIDENCE_FAILURE", False
        if reason == "provider_failure_independently_observed":
            return "RECONCILIATION_FAILURE", False
        return "RECONCILIATION_MISMATCH", False

    def _memory_records(self, attempt_id: str) -> tuple[DomainOutcomeMemory, ...]:
        if not attempt_id:
            raise CustodyViolation("outcome_memory_attempt_id_required")
        if not self.kernel.verify_audit():
            raise CustodyViolation("outcome_memory_canonical_audit_invalid")
        records: list[DomainOutcomeMemory] = []
        seen_transitions: set[str] = set()
        for record in self.kernel.audit:
            if record.get("event") != self.EVENT:
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict) or payload.get("attempt_id") != attempt_id:
                continue
            try:
                memory = DomainOutcomeMemory(**payload)
            except (TypeError, CustodyViolation) as exc:
                raise CustodyViolation("outcome_memory_record_invalid") from exc
            if memory.reconciliation_transition_hash in seen_transitions:
                raise CustodyViolation("outcome_memory_transition_duplicate")
            seen_transitions.add(memory.reconciliation_transition_hash)
            records.append(memory)
        return tuple(records)

    def latest(self, attempt_id: str) -> DomainOutcomeMemory | None:
        records = self._memory_records(attempt_id)
        return records[-1] if records else None

    def record(
        self,
        governed: GovernedDomainAttempt,
        order: DomainPurchaseOrder,
        observation: IndependentDomainObservation,
        reconciliation: DomainReconciliationResult,
    ) -> DomainOutcomeMemory:
        self._target_is_exact(governed, order)
        outcome, reason = self._attempt_is_exact(
            governed,
            order,
            observation,
            reconciliation,
        )
        self._require_canonical_custody_evidence(reconciliation.receipt)
        classification, reusable = self._classification(outcome, reason)

        identity = {
            "schema": "pulpo.domain-outcome-memory.v0",
            "attempt_id": governed.attempt_id,
            "order_hash": order.order_hash,
            "target_hash": governed.target_hash,
            "intent_hash": governed.intent_hash,
            "policy_hash": governed.policy_hash,
            "observation_hash": observation.observation_hash,
            "reconciliation_transition_hash": reconciliation.receipt.transition_hash,
            "reconciliation_epoch": reconciliation.receipt.epoch,
            "reconciliation_outcome": outcome,
            "classification": classification,
            "reason": reason,
            "reusable": reusable,
            "authority_effect": "none",
            "governed_effect": "canonical_outcome_memory",
        }
        memory_id = _hash(identity)

        for existing in self._memory_records(governed.attempt_id):
            if existing.reconciliation_transition_hash != reconciliation.receipt.transition_hash:
                continue
            if existing.memory_id != memory_id:
                raise CustodyViolation("outcome_memory_conflicting_replacement")
            return existing

        memory = DomainOutcomeMemory(
            memory_id=memory_id,
            attempt_id=governed.attempt_id,
            order_hash=order.order_hash,
            target_hash=governed.target_hash,
            intent_hash=governed.intent_hash,
            policy_hash=governed.policy_hash,
            observation_hash=observation.observation_hash,
            reconciliation_transition_hash=reconciliation.receipt.transition_hash,
            reconciliation_epoch=reconciliation.receipt.epoch,
            reconciliation_outcome=outcome,
            classification=classification,
            reason=reason,
            reusable=reusable,
            recorded_at_ns=self._trusted_now(),
        )
        try:
            existing_payload = self.kernel._state.append_unique(
                self.EVENT,
                "reconciliation_transition_hash",
                reconciliation.receipt.transition_hash,
                asdict(memory),
                memory.recorded_at_ns,
            )
        except ValueError as exc:
            raise CustodyViolation("outcome_memory_canonical_identity_ambiguous") from exc

        if existing_payload is not None:
            try:
                existing = DomainOutcomeMemory(**existing_payload)
            except (TypeError, CustodyViolation) as exc:
                raise CustodyViolation("outcome_memory_record_invalid") from exc
            if (
                existing.reconciliation_transition_hash
                != reconciliation.receipt.transition_hash
                or existing.memory_id != memory_id
            ):
                raise CustodyViolation("outcome_memory_conflicting_replacement")
            return existing

        if not self.kernel.verify_audit():
            raise CustodyViolation("outcome_memory_canonical_audit_invalid_after_append")
        return memory

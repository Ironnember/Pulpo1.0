"""Bounded credential-side executor for Hostile Worker Consequence Proof V0.

This module is domain-specific and intentionally not a general execution
gateway. It releases at most one provider transmission right for the exact
custody-bound order. Provider results remain claims until independent
reconciliation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Protocol

from .commerce import DomainPurchaseOrder, RegistrarResult
from .custody import CustodyViolation, SQLiteGovernanceCustody
from .custody_domain import GovernedDomainAttempt


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _require_hash(value: str, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CustodyViolation(f"{field}_invalid")


class ExternalConsequenceUnknown(RuntimeError):
    """The provider request may have changed reality and requires reconciliation."""

    def __init__(self, attempt_id: str) -> None:
        super().__init__(f"external_consequence_unknown:{attempt_id}")
        self.attempt_id = attempt_id


class CustodyRegistrarAdapter(Protocol):
    def preflight(self, order: DomainPurchaseOrder) -> str: ...

    def purchase(
        self,
        order: DomainPurchaseOrder,
        *,
        max_charge_cents: int,
        idempotency_key: str,
    ) -> RegistrarResult: ...


@dataclass(frozen=True)
class ProviderAttemptClaim:
    attempt_id: str
    order_hash: str
    provider_request_id: str
    preflight_hash: str
    idempotency_key: str
    result: RegistrarResult
    claim_hash: str
    reconciliation_required: bool = True
    schema: str = "pulpo.provider-attempt-claim.v0"


class TrustedDomainExecutor:
    """Release at most one network-transmission right for one custody attempt."""

    def __init__(
        self,
        custody: SQLiteGovernanceCustody,
        *,
        executor_id: str,
        evidence_projector: Callable[[], None] | None = None,
    ) -> None:
        if not executor_id:
            raise CustodyViolation("executor_id_required")
        self.custody = custody
        self.executor_id = executor_id
        self._evidence_projector = evidence_projector

    def _project_evidence(self) -> None:
        if self._evidence_projector is not None:
            self._evidence_projector()

    def _claim_or_resume(self, attempt_id: str) -> None:
        snapshot = self.custody.attempt(attempt_id)
        if snapshot is None:
            raise CustodyViolation("attempt_unknown")
        if snapshot.state == self.custody.ATTEMPT_AUTHORIZED:
            head = self.custody.snapshot()
            self.custody.claim_attempt(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                attempt_id=attempt_id,
                executor_id=self.executor_id,
            )
            # The claim and its evidence obligation committed together. Do not
            # permit preflight/transmission until canonical evidence catches up.
            self._project_evidence()
            return
        if (
            snapshot.state == self.custody.ATTEMPT_CLAIMED
            and snapshot.executor_id == self.executor_id
        ):
            # Crash-before-transmission recovery resumes the same attempt only.
            self._project_evidence()
            return
        raise CustodyViolation("attempt_not_executable")

    def execute(
        self,
        governed: GovernedDomainAttempt,
        order: DomainPurchaseOrder,
        adapter: CustodyRegistrarAdapter,
    ) -> ProviderAttemptClaim:
        if order.order_hash != governed.order_hash:
            raise CustodyViolation("executor_order_mismatch")
        snapshot = self.custody.attempt(governed.attempt_id)
        if snapshot is None or snapshot.object_hash != order.order_hash:
            raise CustodyViolation("executor_attempt_mismatch")

        self._claim_or_resume(governed.attempt_id)

        preflight_hash = adapter.preflight(order)
        _require_hash(preflight_hash, "provider_preflight_hash")
        provider_request_id = f"domain:{governed.attempt_id}:preflight:{preflight_hash}"

        # Release the transmission right before the network call, then require
        # its canonical evidence projection before any external write occurs.
        head = self.custody.snapshot()
        transmission = self.custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=provider_request_id,
        )
        try:
            self._project_evidence()
        except Exception as exc:
            # No provider call has occurred. The custody state is conservative
            # and cannot advance again until the obligation is projected.
            raise CustodyViolation("transmission_evidence_not_canonical") from exc

        try:
            result = adapter.purchase(
                order,
                max_charge_cents=order.purchase_price_cents,
                idempotency_key=transmission.idempotency_key,
            )
        except Exception as exc:
            current = self.custody.snapshot()
            try:
                self.custody.require_reconciliation(
                    expected_epoch=current.epoch,
                    expected_state_root=current.state_root,
                    attempt_id=governed.attempt_id,
                )
                self._project_evidence()
            except Exception:
                # The already-projected transmission right remains the safety
                # boundary. Pending evidence blocks any further authority.
                pass
            raise ExternalConsequenceUnknown(governed.attempt_id) from exc

        current = self.custody.snapshot()
        self.custody.require_reconciliation(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=governed.attempt_id,
        )
        try:
            self._project_evidence()
        except Exception as exc:
            # Reality may already have changed; do not surface provider success
            # when canonical accountability has not converged.
            raise ExternalConsequenceUnknown(governed.attempt_id) from exc

        claim_material = {
            "schema": "pulpo.provider-attempt-claim.v0",
            "attempt_id": governed.attempt_id,
            "order_hash": order.order_hash,
            "provider_request_id": provider_request_id,
            "preflight_hash": preflight_hash,
            "idempotency_key": transmission.idempotency_key,
            "result": asdict(result),
        }
        return ProviderAttemptClaim(
            attempt_id=governed.attempt_id,
            order_hash=order.order_hash,
            provider_request_id=provider_request_id,
            preflight_hash=preflight_hash,
            idempotency_key=transmission.idempotency_key,
            result=result,
            claim_hash=_hash(claim_material),
        )

"""Canonical credential-side consequence transmission boundary.

This module owns the one durable network-transmission primitive used by bounded
provider adapters. Provider-specific executors may perform read-only preflight
or shape provider claims, but they must delegate the consequential transmission
through `TrustedConsequenceExecutor`.

The durable custody state is conservative: once `REQUEST_TRANSMITTED` commits,
the request may have changed external reality. Restart, timeout, process crash,
or a lost provider response therefore cannot create another transmission right.
Independent reconciliation is required before the consequence can be settled.
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


@dataclass(frozen=True)
class GovernedConsequenceRef:
    """Minimal exact-object reference accepted by the shared transmission primitive."""

    attempt_id: str
    object_hash: str

    def __post_init__(self) -> None:
        if not self.attempt_id:
            raise CustodyViolation("attempt_id_required")
        _require_hash(self.object_hash, "object_hash")


@dataclass(frozen=True)
class ConsequenceTransmissionResult:
    attempt_id: str
    provider_request_id: str
    idempotency_key: str
    result: Any


class TrustedConsequenceExecutor:
    """Release at most one network-transmission right for one custody attempt.

    This class does not decide policy, verify an approval, mint a permit, or
    interpret provider success. It only enforces the durable execution sequence:

    `ATTEMPT_AUTHORIZED -> ATTEMPT_CLAIMED -> REQUEST_TRANSMITTED
       -> RECONCILIATION_REQUIRED`

    The `REQUEST_TRANSMITTED` transition and canonical evidence projection occur
    before the external callable is invoked. A process crash after the provider
    receives bytes therefore leaves durable state that cannot be re-executed.
    """

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

    def claim_or_resume(self, attempt_id: str) -> None:
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
            # permit provider preparation/transmission until evidence converges.
            self._project_evidence()
            return
        if (
            snapshot.state == self.custody.ATTEMPT_CLAIMED
            and snapshot.executor_id == self.executor_id
        ):
            # Crash-before-transmission recovery may resume this same attempt.
            self._project_evidence()
            return
        raise CustodyViolation("attempt_not_executable")

    def execute(
        self,
        governed: GovernedConsequenceRef,
        *,
        provider_request_id: str,
        transmit: Callable[[str], Any],
    ) -> ConsequenceTransmissionResult:
        if not provider_request_id:
            raise CustodyViolation("provider_request_id_invalid")
        if not callable(transmit):
            raise CustodyViolation("provider_transmit_callable_required")

        snapshot = self.custody.attempt(governed.attempt_id)
        if snapshot is None or snapshot.object_hash != governed.object_hash:
            raise CustodyViolation("executor_attempt_mismatch")

        self.claim_or_resume(governed.attempt_id)

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
            # No provider call has occurred. The conservative transmitted state
            # cannot advance again until the evidence obligation converges.
            raise CustodyViolation("transmission_evidence_not_canonical") from exc

        try:
            result = transmit(transmission.idempotency_key)
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
                # The already-projected transmission receipt remains the safety
                # boundary. No retry right is recreated by an evidence failure.
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

        return ConsequenceTransmissionResult(
            attempt_id=governed.attempt_id,
            provider_request_id=provider_request_id,
            idempotency_key=transmission.idempotency_key,
            result=result,
        )


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
    """Domain adapter over the single canonical transmission primitive."""

    def __init__(
        self,
        custody: SQLiteGovernanceCustody,
        *,
        executor_id: str,
        evidence_projector: Callable[[], None] | None = None,
    ) -> None:
        self.custody = custody
        self.executor_id = executor_id
        self._evidence_projector = evidence_projector
        self._consequence = TrustedConsequenceExecutor(
            custody,
            executor_id=executor_id,
            evidence_projector=evidence_projector,
        )

    def _project_evidence(self) -> None:
        self._consequence._project_evidence()

    def _claim_or_resume(self, attempt_id: str) -> None:
        self._consequence.claim_or_resume(attempt_id)

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

        # Domain preflight is read-only and intentionally occurs after claiming
        # the attempt but before a provider-transmission right is released.
        self._claim_or_resume(governed.attempt_id)
        preflight_hash = adapter.preflight(order)
        _require_hash(preflight_hash, "provider_preflight_hash")
        provider_request_id = f"domain:{governed.attempt_id}:preflight:{preflight_hash}"

        transmitted = self._consequence.execute(
            GovernedConsequenceRef(governed.attempt_id, order.order_hash),
            provider_request_id=provider_request_id,
            transmit=lambda idempotency_key: adapter.purchase(
                order,
                max_charge_cents=order.purchase_price_cents,
                idempotency_key=idempotency_key,
            ),
        )
        result = transmitted.result
        if not isinstance(result, RegistrarResult):
            raise CustodyViolation("provider_result_invalid")

        claim_material = {
            "schema": "pulpo.provider-attempt-claim.v0",
            "attempt_id": governed.attempt_id,
            "order_hash": order.order_hash,
            "provider_request_id": provider_request_id,
            "preflight_hash": preflight_hash,
            "idempotency_key": transmitted.idempotency_key,
            "result": asdict(result),
        }
        return ProviderAttemptClaim(
            attempt_id=governed.attempt_id,
            order_hash=order.order_hash,
            provider_request_id=provider_request_id,
            preflight_hash=preflight_hash,
            idempotency_key=transmitted.idempotency_key,
            result=result,
            claim_hash=_hash(claim_material),
        )

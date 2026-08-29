"""Bounded credential-side executor for Hostile Worker Consequence Proof V0.

This module is domain-specific and intentionally not a general execution
Gateway.  It is designed to run outside the hostile worker boundary with the
registrar credential adapter.  It can perform only the exact domain order
already bound to a custody attempt.

Provider return values remain claims.  Successful or failed calls always move
the attempt toward independent reconciliation; they never become accepted
consequence directly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Protocol

from .commerce import DomainPurchaseOrder, RegistrarResult
from .custody import CustodyViolation, SQLiteGovernanceCustody
from .custody_domain import GovernedDomainAttempt


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


class ExternalConsequenceUnknown(RuntimeError):
    """The provider request may have changed reality and requires reconciliation."""

    def __init__(self, attempt_id: str) -> None:
        super().__init__(f"external_consequence_unknown:{attempt_id}")
        self.attempt_id = attempt_id


class CustodyRegistrarAdapter(Protocol):
    """Credential-bearing registrar adapter available only to the trusted executor."""

    def purchase(
        self,
        order: DomainPurchaseOrder,
        *,
        max_charge_cents: int,
        idempotency_key: str,
    ) -> RegistrarResult:
        """Transmit the exact bounded purchase using the custody attempt key."""


@dataclass(frozen=True)
class ProviderAttemptClaim:
    attempt_id: str
    order_hash: str
    provider_request_id: str
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
    ) -> None:
        if not executor_id:
            raise CustodyViolation("executor_id_required")
        self.custody = custody
        self.executor_id = executor_id

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
            return
        if (
            snapshot.state == self.custody.ATTEMPT_CLAIMED
            and snapshot.executor_id == self.executor_id
        ):
            # Crash-before-transmission recovery: resume the same attempt and
            # same executor identity.  No provider-transmission right has yet
            # been released, so this does not manufacture a second capability.
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

        # Release the one network right *before* calling the provider.  From
        # this point forward a crash is conservatively treated as a possibly
        # transmitted request and may not trigger automatic retry.
        head = self.custody.snapshot()
        provider_request_id = f"domain:{governed.attempt_id}"
        transmission = self.custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=provider_request_id,
        )

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
            except CustodyViolation:
                # The transmission receipt remains the authoritative safety
                # boundary even if recording the secondary classification fails.
                pass
            raise ExternalConsequenceUnknown(governed.attempt_id) from exc

        current = self.custody.snapshot()
        self.custody.require_reconciliation(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=governed.attempt_id,
        )
        claim_material = {
            "schema": "pulpo.provider-attempt-claim.v0",
            "attempt_id": governed.attempt_id,
            "order_hash": order.order_hash,
            "provider_request_id": provider_request_id,
            "idempotency_key": transmission.idempotency_key,
            "result": asdict(result),
        }
        return ProviderAttemptClaim(
            attempt_id=governed.attempt_id,
            order_hash=order.order_hash,
            provider_request_id=provider_request_id,
            idempotency_key=transmission.idempotency_key,
            result=result,
            claim_hash=_hash(claim_material),
        )

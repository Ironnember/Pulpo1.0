"""Read-only name.com CORE observation for Hostile Worker Consequence Proof V0.

This observer uses a separately constructed NameComCoreClient and never consumes
worker- or executor-reported provider success as truth.  It combines filtered
registration-order history with account-authenticated Get Domain state.

A successful order without a matching domain read-back is classified `unknown`,
not failure.  name.com documents that some registries can reject asynchronously
after initial create acceptance, and read paths can also be eventually
consistent.  V0 therefore requires reconciliation rather than inference.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

from .commerce import DomainPurchaseOrder
from .custody import CustodyViolation, SQLiteGovernanceCustody
from .custody_domain import GovernedDomainAttempt
from .custody_reconcile import IndependentDomainObservation
from .namecom_core import NameComCoreClient, NameComViolation


def _usd_to_cents(value: Any) -> int | None:
    if value is None:
        return None
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError):
        return None
    if amount < 0:
        return None
    return int(amount * 100)


def _registration_matches(order_record: dict[str, Any], domain: str) -> bool:
    items = order_record.get("orderItems")
    if not isinstance(items, list):
        return False
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "registration" and item.get("name") == domain:
            return True
    return False


class NameComCoreObserver:
    """Map current name.com account state into independent Pulpo observation."""

    def __init__(
        self,
        custody: SQLiteGovernanceCustody,
        client: NameComCoreClient,
        *,
        owner_ref: str,
        observation_id_prefix: str = "namecom-core",
    ) -> None:
        if not owner_ref.startswith("owner://") or owner_ref == "owner://":
            raise CustodyViolation("observer_owner_ref_invalid")
        if not observation_id_prefix:
            raise CustodyViolation("observer_id_prefix_required")
        self.custody = custody
        self.client = client
        self.owner_ref = owner_ref
        self.observation_id_prefix = observation_id_prefix

    def _get_domain_or_none(self, domain: str) -> dict[str, Any] | None:
        try:
            result = self.client.get_domain(domain)
        except NameComViolation as exc:
            if str(exc) == "namecom_http_404":
                return None
            raise CustodyViolation(f"namecom_observer_domain_unavailable:{exc}") from exc
        if result.get("domainName") != domain:
            raise CustodyViolation("namecom_observer_domain_mismatch")
        return result

    def _matching_orders(self, domain: str) -> list[dict[str, Any]]:
        try:
            response = self.client.list_orders_for_domain(domain)
        except NameComViolation as exc:
            raise CustodyViolation(f"namecom_observer_orders_unavailable:{exc}") from exc
        orders = response.get("orders")
        if not isinstance(orders, list):
            raise CustodyViolation("namecom_observer_orders_shape_invalid")
        return [
            item
            for item in orders
            if isinstance(item, dict) and _registration_matches(item, domain)
        ]

    @staticmethod
    def _order_status(record: dict[str, Any] | None) -> str:
        if record is None:
            return "unknown"
        status = record.get("status")
        if status == "success":
            return "succeeded"
        if status == "failed":
            return "failed"
        return "unknown"

    def observe(
        self,
        governed: GovernedDomainAttempt,
        order: DomainPurchaseOrder,
    ) -> IndependentDomainObservation:
        if order.order_hash != governed.order_hash:
            raise CustodyViolation("namecom_observer_order_mismatch")
        attempt = self.custody.attempt(governed.attempt_id)
        if attempt is None or attempt.object_hash != order.order_hash:
            raise CustodyViolation("namecom_observer_attempt_mismatch")
        if not attempt.provider_request_id:
            raise CustodyViolation("namecom_observer_request_not_transmitted")

        matches = self._matching_orders(order.domain)
        # More than one matching registration order cannot safely be attributed
        # to the one Pulpo attempt without an exact provider-order identifier.
        record = matches[0] if len(matches) == 1 else None
        status = self._order_status(record)
        domain_record = self._get_domain_or_none(order.domain)

        # A provider order marked success without account-visible domain state is
        # not accepted as known failure or success.  It remains unknown pending
        # later observation/webhook reconciliation.
        if status == "succeeded" and domain_record is None:
            status = "unknown"

        provider_order_id = record.get("id") if record is not None else None
        payment_id = (
            f"namecom-order:{provider_order_id}"
            if isinstance(provider_order_id, int) and provider_order_id > 0
            else None
        )
        charged_cents = (
            _usd_to_cents(record.get("totalCapture")) if record is not None else None
        )

        registered = domain_record is not None
        privacy_enabled = (
            domain_record.get("privacyEnabled")
            if domain_record is not None
            and isinstance(domain_record.get("privacyEnabled"), bool)
            else None
        )
        auto_renew_enabled = (
            domain_record.get("autorenewEnabled")
            if domain_record is not None
            and isinstance(domain_record.get("autorenewEnabled"), bool)
            else None
        )
        receipt_hash = None
        if payment_id is not None and charged_cents is not None:
            # The read-back evidence hash is not the executor's response hash.
            # Independent reconciliation binds the provider order record itself.
            from hashlib import sha256
            import json

            receipt_hash = sha256(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        return IndependentDomainObservation(
            observation_id=f"{self.observation_id_prefix}:{governed.attempt_id}",
            provider_request_id=attempt.provider_request_id,
            provider_request_status=status,
            domain=order.domain if registered else None,
            registrar="name.com" if registered else None,
            # Successful Get Domain under the observer's account-authenticated
            # credential is treated as evidence of account custody for the
            # configured opaque owner_ref. V0 does not expose contact PII.
            owner_ref=self.owner_ref if registered else None,
            registered=registered,
            payment_id=payment_id,
            charged_cents=charged_cents,
            receipt_hash=receipt_hash,
            privacy_enabled=privacy_enabled,
            dns_state="registered" if registered else None,
            auto_renew_enabled=auto_renew_enabled,
        )

"""Read-only name.com CORE observation for Hostile Worker Consequence Proof V0.

This observer uses a separately constructed NameComCoreClient and never consumes
worker- or executor-reported provider success as truth. It requires the durable
custody snapshot to contain the provider-native Name.com order identifier, then
reads that exact order and the exact domain from the provider.

A successful order without a matching domain read-back is classified `unknown`,
not failure. Name.com documents that some registries can reject asynchronously
after initial create acceptance, and read paths can also be eventually
consistent. V0 therefore requires reconciliation rather than inference.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from hashlib import sha256
import json
from typing import Any

from .commerce import DomainPurchaseOrder
from .custody import CustodyViolation, SQLiteGovernanceCustody
from .custody_domain import GovernedDomainAttempt
from .custody_reconcile import IndependentDomainObservation
from .namecom_core import NameComCoreClient, NameComViolation


NAMECOM_ORDER_PREFIX = "namecom-order:"


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
    matches = [
        item
        for item in items
        if isinstance(item, dict)
        and item.get("type") == "registration"
        and item.get("name") == domain
    ]
    return len(matches) == 1


def _provider_order_id(provider_reference: str) -> int | None:
    if not provider_reference.startswith(NAMECOM_ORDER_PREFIX):
        return None
    raw = provider_reference[len(NAMECOM_ORDER_PREFIX) :]
    if not raw.isdigit():
        return None
    order_id = int(raw)
    return order_id if order_id > 0 else None


class NameComCoreObserver:
    """Map exact provider-native Name.com state into independent observation."""

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

    def _get_exact_order_or_none(self, order_id: int, domain: str) -> dict[str, Any] | None:
        try:
            record = self.client.get_order(order_id)
        except NameComViolation as exc:
            if str(exc) == "namecom_http_404":
                return None
            raise CustodyViolation(f"namecom_observer_order_unavailable:{exc}") from exc
        if record.get("id") != order_id:
            raise CustodyViolation("namecom_observer_provider_order_id_mismatch")
        if not _registration_matches(record, domain):
            raise CustodyViolation("namecom_observer_provider_order_object_mismatch")
        return record

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

    def _unknown_without_provider_identity(
        self,
        governed: GovernedDomainAttempt,
        provider_request_id: str,
    ) -> IndependentDomainObservation:
        # A transmitted request without a durably captured provider-native order
        # identifier cannot be attributed safely. Do not search by domain or
        # manufacture identity from the local request id. No retry authority is
        # created; reconciliation remains unresolved.
        return IndependentDomainObservation(
            observation_id=f"{self.observation_id_prefix}:{governed.attempt_id}",
            provider_request_id=provider_request_id,
            provider_request_status="unknown",
            domain=None,
            registrar=None,
            owner_ref=None,
            registered=None,
            payment_id=None,
            charged_cents=None,
            receipt_hash=None,
            privacy_enabled=None,
            dns_state=None,
            auto_renew_enabled=None,
        )

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

        provider_reference = attempt.provider_request_id
        provider_order_id = _provider_order_id(provider_reference)
        if provider_order_id is None:
            return self._unknown_without_provider_identity(
                governed,
                provider_reference,
            )

        record = self._get_exact_order_or_none(provider_order_id, order.domain)
        status = self._order_status(record)
        if record is None:
            return IndependentDomainObservation(
                observation_id=f"{self.observation_id_prefix}:{governed.attempt_id}",
                provider_request_id=provider_reference,
                provider_request_status="not_found",
                domain=None,
                registrar=None,
                owner_ref=None,
                registered=None,
                payment_id=None,
                charged_cents=None,
                receipt_hash=None,
                privacy_enabled=None,
                dns_state=None,
                auto_renew_enabled=None,
            )

        domain_record = self._get_domain_or_none(order.domain)

        # A provider order marked success without account-visible domain state is
        # not accepted as known failure or success. It remains unknown pending
        # later provider-native reconciliation.
        if status == "succeeded" and domain_record is None:
            status = "unknown"

        charged_cents = _usd_to_cents(record.get("totalCapture"))
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
        receipt_hash = sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        return IndependentDomainObservation(
            observation_id=f"{self.observation_id_prefix}:{governed.attempt_id}",
            provider_request_id=provider_reference,
            provider_request_status=status,
            domain=order.domain if registered else None,
            registrar="name.com" if registered else None,
            owner_ref=self.owner_ref if registered else None,
            registered=registered,
            payment_id=provider_reference,
            charged_cents=charged_cents,
            receipt_hash=receipt_hash,
            privacy_enabled=privacy_enabled,
            dns_state="registered" if registered else None,
            auto_renew_enabled=auto_renew_enabled,
        )

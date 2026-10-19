"""Fail-closed name.com CORE adapter for the bounded domain pilot.

The adapter owns no API secret.  An injected transport resolves the opaque
credential reference and performs authenticated HTTPS.  Production purchase is
deliberately denied because CORE v1 exposes no per-request hard charge cap;
post-charge ``totalPaid`` evidence is reconciliation, not payment-rail control.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
from typing import Any, Protocol

from .commerce import (
    CommerceViolation,
    DomainPurchaseOrder,
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
)


NAMECOM_PRODUCTION_ORIGIN = "https://api.name.com"
NAMECOM_SANDBOX_ORIGIN = "https://api.dev.name.com"


class NameComTransport(Protocol):
    """Credential-owning HTTPS boundary injected outside governed code."""

    def request(
        self,
        origin: str,
        method: str,
        path: str,
        body: dict[str, object] | None,
        headers: dict[str, str],
        *,
        credential_ref: str,
    ) -> dict[str, Any]: ...


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _usd_cents(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise CommerceViolation(f"namecom_{field}_invalid")
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise CommerceViolation(f"namecom_{field}_invalid") from error
    if not amount.is_finite() or amount < 0:
        raise CommerceViolation(f"namecom_{field}_invalid")
    try:
        if amount.quantize(Decimal("0.01")) != amount:
            raise CommerceViolation(f"namecom_{field}_invalid")
    except InvalidOperation as error:
        raise CommerceViolation(f"namecom_{field}_invalid") from error
    return int(amount * 100)


class NameComCoreAdapter:
    """Discovery plus sandbox execution for name.com CORE v1.

    Discovery and execution stay separate.  The normal Pulpo commerce executor
    remains responsible for permit consumption and durable attempted-order
    state before ``purchase`` is called.
    """

    def __init__(
        self,
        base_origin: str,
        credential_ref: str,
        transport: NameComTransport,
    ) -> None:
        if base_origin not in {NAMECOM_PRODUCTION_ORIGIN, NAMECOM_SANDBOX_ORIGIN}:
            raise CommerceViolation("namecom_origin_not_pinned")
        if not credential_ref.startswith("credential://") or credential_ref == "credential://":
            raise CommerceViolation("namecom_credential_reference_invalid")
        self.base_origin = base_origin
        self.credential_ref = credential_ref
        self._transport = transport

    @property
    def sandbox(self) -> bool:
        return self.base_origin == NAMECOM_SANDBOX_ORIGIN

    def check_availability(
        self,
        request: DomainPurchaseRequest,
        domain: str,
        *,
        now_ns: int,
        quote_ttl_ns: int,
    ) -> DomainQuote:
        if domain not in request.acceptable_domains:
            raise CommerceViolation("namecom_domain_not_requested")
        if now_ns <= 0 or now_ns >= request.expires_at_ns or quote_ttl_ns <= 0:
            raise CommerceViolation("namecom_discovery_window_invalid")
        response = self._transport.request(
            self.base_origin,
            "POST",
            "/core/v1/domains:checkAvailability",
            {"domainNames": [domain], "purchaseType": "registration"},
            {"Content-Type": "application/json"},
            credential_ref=self.credential_ref,
        )
        results = response.get("results")
        if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict):
            raise CommerceViolation("namecom_availability_response_invalid")
        result = results[0]
        if result.get("domainName") != domain:
            raise CommerceViolation("namecom_domain_substitution")
        if result.get("purchasable") is not True:
            raise CommerceViolation("namecom_domain_not_purchasable")
        if result.get("purchaseType") != "registration":
            raise CommerceViolation("namecom_purchase_type_not_allowed")
        if result.get("premium") is not False:
            raise CommerceViolation("namecom_premium_not_allowed")
        purchase_cents = _usd_cents(result.get("purchasePrice"), "purchase_price")
        renewal_cents = _usd_cents(result.get("renewalPrice"), "renewal_price")
        quote_material = {
            "domain": domain,
            "premium": False,
            "purchase_price_cents": purchase_cents,
            "purchase_type": "registration",
            "renewal_price_cents": renewal_cents,
            "observed_at_ns": now_ns,
        }
        quote_id = f"namecom-core:{sha256(_canonical(quote_material)).hexdigest()}"
        return DomainQuote(
            quote_id=quote_id,
            domain=domain,
            registrar="name.com",
            purchase_price_cents=purchase_cents,
            renewal_price_cents=renewal_cents,
            owner_ref=request.owner_ref,
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=min(request.expires_at_ns, now_ns + quote_ttl_ns),
        )

    def purchase(
        self,
        order: DomainPurchaseOrder,
        *,
        max_charge_cents: int,
    ) -> RegistrarResult:
        if order.registrar != "name.com":
            raise CommerceViolation("namecom_registrar_mismatch")
        if order.credential_ref != self.credential_ref:
            raise CommerceViolation("namecom_credential_reference_mismatch")
        if max_charge_cents != order.purchase_price_cents:
            raise CommerceViolation("namecom_charge_cap_mismatch")
        if order.auto_renew_enabled is not False:
            raise CommerceViolation("namecom_autorenew_not_supported")
        if not self.sandbox:
            raise CommerceViolation("namecom_production_hard_charge_cap_unavailable")

        # CORE requires standard, non-premium registrations to omit
        # purchasePrice.  That is safe to exercise only in the no-charge sandbox.
        response = self._transport.request(
            self.base_origin,
            "POST",
            "/core/v1/domains",
            {
                "domain": {
                    "domainName": order.domain,
                    "autorenewEnabled": order.auto_renew_enabled,
                    "privacyEnabled": order.privacy_required,
                },
                "purchaseType": "registration",
                "years": 1,
            },
            {
                "Content-Type": "application/json",
                "X-Idempotency-Key": order.order_hash,
            },
            credential_ref=self.credential_ref,
        )
        provider_order = response.get("order")
        domain = response.get("domain")
        if isinstance(provider_order, bool) or not isinstance(provider_order, int) or provider_order <= 0:
            raise CommerceViolation("namecom_order_response_invalid")
        if not isinstance(domain, dict) or domain.get("domainName") != order.domain:
            raise CommerceViolation("namecom_delivery_substitution")
        if order.privacy_required and domain.get("privacyEnabled") is not True:
            raise CommerceViolation("namecom_privacy_not_enabled")
        charged_cents = _usd_cents(response.get("totalPaid"), "total_paid")
        if charged_cents > max_charge_cents:
            raise CommerceViolation("namecom_sandbox_charge_exceeded_cap")
        receipt_hash = sha256(_canonical(response)).hexdigest()
        order_id = f"namecom-order:{provider_order}"
        return RegistrarResult(
            payment_id=order_id,
            charged_cents=charged_cents,
            receipt_hash=receipt_hash,
            registration_id=order_id,
            domain=order.domain,
            registrar="name.com",
        )

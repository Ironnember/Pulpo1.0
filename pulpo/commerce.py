"""Bounded digital-commerce contracts subordinate to Pulpo's kernel.

This module does not implement a registrar adapter, credential store, payment
rail, approval service, or second audit ledger.  It binds one exact domain
purchase object to the existing GovernanceKernel intent and permit path, then
keeps payment, delivery, acceptance, and value evidence distinct.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Protocol

from .kernel import GovernanceKernel, Intent


PILOT_PURCHASE_CEILING_CENTS = 3_000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


class CommerceViolation(ValueError):
    """A purchase object or state transition violated the commerce contract."""


@dataclass(frozen=True)
class DomainPurchaseRequest:
    request_id: str
    principal: str
    acceptable_domains: tuple[str, ...]
    max_purchase_cents: int
    max_renewal_cents: int
    approved_registrar: str
    owner_ref: str
    privacy_required: bool
    prohibited_upsells: tuple[str, ...]
    expires_at_ns: int

    def __post_init__(self) -> None:
        if not self.request_id or not self.principal or not self.acceptable_domains:
            raise CommerceViolation("request identity, principal, and domains are required")
        if len(set(self.acceptable_domains)) != len(self.acceptable_domains):
            raise CommerceViolation("acceptable domains must be unique")
        if any(not item or item != item.lower() for item in self.acceptable_domains):
            raise CommerceViolation("acceptable domains must be normalized lowercase names")
        if not 0 <= self.max_purchase_cents <= PILOT_PURCHASE_CEILING_CENTS:
            raise CommerceViolation("purchase ceiling exceeds the $30 pilot boundary")
        if self.max_renewal_cents < 0:
            raise CommerceViolation("renewal ceiling must be non-negative")
        if not self.approved_registrar or self.approved_registrar != self.approved_registrar.lower():
            raise CommerceViolation("approved registrar must be normalized")
        if not self.owner_ref.startswith("owner://"):
            raise CommerceViolation("owner must be an opaque owner reference")
        if len(set(self.prohibited_upsells)) != len(self.prohibited_upsells):
            raise CommerceViolation("prohibited upsells must be unique")
        if any(not item or item != item.lower() for item in self.prohibited_upsells):
            raise CommerceViolation("prohibited upsells must be normalized")
        if self.expires_at_ns <= 0:
            raise CommerceViolation("request expiration is required")


@dataclass(frozen=True)
class DomainQuote:
    quote_id: str
    domain: str
    registrar: str
    purchase_price_cents: int
    renewal_price_cents: int
    owner_ref: str
    privacy_enabled: bool
    upsells: tuple[str, ...]
    expires_at_ns: int

    def __post_init__(self) -> None:
        if not self.quote_id or not self.domain or not self.registrar:
            raise CommerceViolation("quote identity, domain, and registrar are required")
        if self.domain != self.domain.lower() or self.registrar != self.registrar.lower():
            raise CommerceViolation("quote domain and registrar must be normalized")
        if self.purchase_price_cents < 0 or self.renewal_price_cents < 0:
            raise CommerceViolation("quote prices must be non-negative")
        if not self.owner_ref.startswith("owner://"):
            raise CommerceViolation("quote owner must be an opaque owner reference")
        if len(set(self.upsells)) != len(self.upsells):
            raise CommerceViolation("quote upsells must be unique")
        if any(not item or item != item.lower() for item in self.upsells):
            raise CommerceViolation("quote upsells must be normalized")
        if self.expires_at_ns <= 0:
            raise CommerceViolation("quote expiration is required")


@dataclass(frozen=True)
class DomainPurchaseOrder:
    request_id: str
    quote_id: str
    principal: str
    domain: str
    registrar: str
    purchase_price_cents: int
    renewal_price_cents: int
    owner_ref: str
    privacy_required: bool
    prohibited_upsells: tuple[str, ...]
    credential_ref: str
    expires_at_ns: int

    def __post_init__(self) -> None:
        if not self.credential_ref.startswith("credential://"):
            raise CommerceViolation("credential must be an opaque credential reference")

    @property
    def order_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class QuoteAssessment:
    outcome: str
    reason: str
    request_id: str
    quote_id: str
    assessment_hash: str
    order: DomainPurchaseOrder | None = None


def assess_quote(
    request: DomainPurchaseRequest,
    quote: DomainQuote,
    *,
    credential_ref: str,
    now_ns: int,
) -> QuoteAssessment:
    """Deterministically validate one quote against the signed request shape."""

    reason = "policy_satisfied"
    if now_ns >= request.expires_at_ns:
        reason = "request_expired"
    elif now_ns >= quote.expires_at_ns:
        reason = "quote_expired"
    elif quote.domain not in request.acceptable_domains:
        reason = "domain_not_approved"
    elif quote.registrar != request.approved_registrar:
        reason = "registrar_not_approved"
    elif quote.purchase_price_cents > request.max_purchase_cents:
        reason = "purchase_price_exceeded"
    elif quote.renewal_price_cents > request.max_renewal_cents:
        reason = "renewal_price_exceeded"
    elif quote.owner_ref != request.owner_ref:
        reason = "owner_mismatch"
    elif request.privacy_required and not quote.privacy_enabled:
        reason = "privacy_required"
    elif set(quote.upsells).intersection(request.prohibited_upsells):
        reason = "prohibited_upsell"
    elif not credential_ref.startswith("credential://"):
        reason = "credential_reference_invalid"

    order = None
    if reason == "policy_satisfied":
        order = DomainPurchaseOrder(
            request_id=request.request_id,
            quote_id=quote.quote_id,
            principal=request.principal,
            domain=quote.domain,
            registrar=quote.registrar,
            purchase_price_cents=quote.purchase_price_cents,
            renewal_price_cents=quote.renewal_price_cents,
            owner_ref=quote.owner_ref,
            privacy_required=request.privacy_required,
            prohibited_upsells=request.prohibited_upsells,
            credential_ref=credential_ref,
            expires_at_ns=min(request.expires_at_ns, quote.expires_at_ns),
        )

    material = {
        "outcome": "allow" if order else "deny",
        "reason": reason,
        "request": asdict(request),
        "quote": asdict(quote),
        "credential_ref": credential_ref,
    }
    return QuoteAssessment(
        outcome=material["outcome"],
        reason=reason,
        request_id=request.request_id,
        quote_id=quote.quote_id,
        assessment_hash=_hash(material),
        order=order,
    )


def purchase_intent(order: DomainPurchaseOrder) -> Intent:
    """Bind the exact order to Pulpo's canonical intent and permit mechanism."""

    return Intent(
        principal=order.principal,
        action="purchase_domain",
        resource=f"commerce:domain:{order.order_hash}",
        cost=order.purchase_price_cents,
    )


@dataclass(frozen=True)
class RegistrarResult:
    payment_id: str | None
    charged_cents: int | None
    receipt_hash: str | None
    registration_id: str | None
    domain: str | None
    registrar: str | None


class RegistrarAdapter(Protocol):
    def purchase(self, order: DomainPurchaseOrder, *, max_charge_cents: int) -> RegistrarResult:
        """Execute one exact order while enforcing the supplied hard charge cap."""


@dataclass(frozen=True)
class PaymentEvidence:
    payment_id: str
    charged_cents: int
    receipt_hash: str


@dataclass(frozen=True)
class DeliveryEvidence:
    registration_id: str
    domain: str
    registrar: str


@dataclass(frozen=True)
class VerificationEvidence:
    domain: str
    registrar: str
    owner_ref: str
    registration_years: int
    privacy_enabled: bool
    dns_state: str


@dataclass(frozen=True)
class Reconciliation:
    authorized_cents: int
    charged_cents: int
    variance_cents: int
    balanced: bool


@dataclass
class CommerceOutcome:
    order_hash: str
    authorized: bool = False
    payment: PaymentEvidence | None = None
    delivery: DeliveryEvidence | None = None
    verification: VerificationEvidence | None = None
    reconciliation: Reconciliation | None = None
    accepted: bool = False
    valuable: bool = False
    value_observation: str | None = None
    capability_revoked: bool = False


class DomainCommerceExecutor:
    """Consume a Pulpo permit before invoking a registrar adapter exactly once."""

    def __init__(self, attempted_order_hashes: set[str] | None = None) -> None:
        self.attempted_order_hashes = attempted_order_hashes if attempted_order_hashes is not None else set()

    def execute(
        self,
        kernel: GovernanceKernel,
        order: DomainPurchaseOrder,
        permit: str,
        adapter: RegistrarAdapter,
        *,
        now_ns: int,
    ) -> CommerceOutcome:
        if now_ns >= order.expires_at_ns:
            raise CommerceViolation("order_expired")
        if order.order_hash in self.attempted_order_hashes:
            raise CommerceViolation("duplicate_purchase_attempt")

        intent = purchase_intent(order)
        if not kernel.consume(permit, intent):
            raise CommerceViolation("permit_rejected")

        # Mark before the external call.  An uncertain network outcome must be
        # reconciled, not blindly retried with a new capability.
        self.attempted_order_hashes.add(order.order_hash)
        outcome = CommerceOutcome(order_hash=order.order_hash, authorized=True, capability_revoked=True)
        result = adapter.purchase(order, max_charge_cents=order.purchase_price_cents)

        if result.payment_id is not None or result.charged_cents is not None or result.receipt_hash is not None:
            if None in (result.payment_id, result.charged_cents, result.receipt_hash):
                raise CommerceViolation("incomplete_payment_evidence")
            if result.charged_cents < 0 or result.charged_cents > order.purchase_price_cents:
                raise CommerceViolation("charge_exceeded_authorized_amount")
            outcome.payment = PaymentEvidence(result.payment_id, result.charged_cents, result.receipt_hash)
            outcome.reconciliation = Reconciliation(
                authorized_cents=order.purchase_price_cents,
                charged_cents=result.charged_cents,
                variance_cents=order.purchase_price_cents - result.charged_cents,
                balanced=result.charged_cents <= order.purchase_price_cents,
            )

        if result.registration_id is not None or result.domain is not None or result.registrar is not None:
            if None in (result.registration_id, result.domain, result.registrar):
                raise CommerceViolation("incomplete_delivery_evidence")
            outcome.delivery = DeliveryEvidence(result.registration_id, result.domain, result.registrar)

        return outcome


def accept_delivery(
    order: DomainPurchaseOrder,
    outcome: CommerceOutcome,
    verification: VerificationEvidence,
) -> None:
    """Accept only independently verified delivery and configuration evidence."""

    outcome.verification = verification
    if outcome.payment is None:
        raise CommerceViolation("payment_not_proven")
    if outcome.delivery is None:
        raise CommerceViolation("delivery_not_proven")
    if verification.domain != order.domain or outcome.delivery.domain != order.domain:
        raise CommerceViolation("domain_delivery_mismatch")
    if verification.registrar != order.registrar or outcome.delivery.registrar != order.registrar:
        raise CommerceViolation("registrar_delivery_mismatch")
    if verification.owner_ref != order.owner_ref:
        raise CommerceViolation("ownership_not_verified")
    if verification.registration_years < 1:
        raise CommerceViolation("registration_period_not_verified")
    if order.privacy_required and not verification.privacy_enabled:
        raise CommerceViolation("privacy_not_verified")
    if verification.dns_state not in {"registered", "configured"}:
        raise CommerceViolation("dns_state_not_accepted")
    outcome.accepted = True


def record_value(outcome: CommerceOutcome, observation: str) -> None:
    """Record continuing value separately from purchase acceptance."""

    if not outcome.accepted:
        raise CommerceViolation("value_requires_acceptance")
    if not observation:
        raise CommerceViolation("value observation is required")
    outcome.valuable = True
    outcome.value_observation = observation


def build_proof_bundle(
    kernel: GovernanceKernel,
    request: DomainPurchaseRequest,
    quote: DomainQuote,
    assessment: QuoteAssessment,
    outcome: CommerceOutcome | None,
) -> dict[str, Any]:
    """Project portable commerce evidence from domain state and kernel audit."""

    payload = {
        "schema": "pulpo.commerce.proof.v1",
        "request": asdict(request),
        "quote": asdict(quote),
        "assessment": {key: value for key, value in asdict(assessment).items() if key != "order"},
        "order": asdict(assessment.order) if assessment.order else None,
        "outcome": asdict(outcome) if outcome else None,
        "audit_valid": kernel.verify_audit(),
        "audit_tip": kernel.audit[-1]["hash"] if kernel.audit else None,
    }
    return {**payload, "bundle_hash": _hash(payload)}

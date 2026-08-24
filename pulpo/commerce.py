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


def _require_sha256(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(character not in "0123456789abcdef" for character in value):
        raise CommerceViolation(f"{field} must be a lowercase SHA-256 digest")


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

    @property
    def request_hash(self) -> str:
        return _hash(asdict(self))


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

    @property
    def quote_hash(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True)
class DomainPurchaseOrder:
    request_id: str
    request_hash: str
    quote_id: str
    quote_hash: str
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
        if not self.request_id or not self.quote_id or not self.principal:
            raise CommerceViolation("order identity and principal are required")
        _require_sha256(self.request_hash, "request_hash")
        _require_sha256(self.quote_hash, "quote_hash")
        if not self.domain or not self.registrar:
            raise CommerceViolation("order domain and registrar are required")
        if self.domain != self.domain.lower() or self.registrar != self.registrar.lower():
            raise CommerceViolation("order domain and registrar must be normalized")
        if not 0 <= self.purchase_price_cents <= PILOT_PURCHASE_CEILING_CENTS:
            raise CommerceViolation("order exceeds the $30 pilot boundary")
        if self.renewal_price_cents < 0:
            raise CommerceViolation("order renewal must be non-negative")
        if not self.owner_ref.startswith("owner://") or self.owner_ref == "owner://":
            raise CommerceViolation("order owner must be an opaque owner reference")
        if len(set(self.prohibited_upsells)) != len(self.prohibited_upsells):
            raise CommerceViolation("order prohibited upsells must be unique")
        if any(not item or item != item.lower() for item in self.prohibited_upsells):
            raise CommerceViolation("order prohibited upsells must be normalized")
        if not self.credential_ref.startswith("credential://") or self.credential_ref == "credential://":
            raise CommerceViolation("credential must be an opaque credential reference")
        if self.expires_at_ns <= 0:
            raise CommerceViolation("order expiration is required")

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
            request_hash=request.request_hash,
            quote_id=quote.quote_id,
            quote_hash=quote.quote_hash,
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

    def __post_init__(self) -> None:
        if not self.payment_id:
            raise CommerceViolation("payment identifier is required")
        if self.charged_cents < 0:
            raise CommerceViolation("payment charge must be non-negative")
        _require_sha256(self.receipt_hash, "receipt_hash")


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
    reservation_id: str
    authorized_cents: int
    charged_cents: int
    variance_cents: int
    balanced: bool


@dataclass(frozen=True)
class BudgetReservation:
    reservation_id: str
    order_hash: str
    reserved_cents: int


class BudgetAccount:
    """In-memory budget reservation state for the bounded pilot."""

    def __init__(self, ceiling_cents: int = PILOT_PURCHASE_CEILING_CENTS) -> None:
        if not 0 <= ceiling_cents <= PILOT_PURCHASE_CEILING_CENTS:
            raise CommerceViolation("budget exceeds the $30 pilot boundary")
        self.ceiling_cents = ceiling_cents
        self.spent_cents = 0
        self._active: dict[str, BudgetReservation] = {}
        self._order_hashes: set[str] = set()
        self._attempted: set[str] = set()

    @property
    def reserved_cents(self) -> int:
        return sum(reservation.reserved_cents for reservation in self._active.values())

    @property
    def available_cents(self) -> int:
        return self.ceiling_cents - self.spent_cents - self.reserved_cents

    def reserve(self, order: DomainPurchaseOrder, *, now_ns: int) -> BudgetReservation:
        if now_ns <= 0 or now_ns >= order.expires_at_ns:
            raise CommerceViolation("order_expired")
        if order.order_hash in self._order_hashes:
            raise CommerceViolation("order_already_reserved")
        if order.purchase_price_cents > self.available_cents:
            raise CommerceViolation("insufficient_available_budget")
        reservation_id = _hash(
            {
                "order_hash": order.order_hash,
                "reserved_cents": order.purchase_price_cents,
                "ceiling_cents": self.ceiling_cents,
            }
        )
        reservation = BudgetReservation(reservation_id, order.order_hash, order.purchase_price_cents)
        self._active[reservation_id] = reservation
        self._order_hashes.add(order.order_hash)
        return reservation

    def require_active(self, reservation_id: str, order: DomainPurchaseOrder, *, now_ns: int) -> BudgetReservation:
        if now_ns <= 0 or now_ns >= order.expires_at_ns:
            raise CommerceViolation("order_expired")
        reservation = self._active.get(reservation_id)
        if reservation is None:
            raise CommerceViolation("reservation_unknown_or_consumed")
        if reservation_id in self._attempted:
            raise CommerceViolation("reservation_already_attempted")
        if reservation.order_hash != order.order_hash:
            raise CommerceViolation("reservation_order_mismatch")
        if reservation.reserved_cents != order.purchase_price_cents:
            raise CommerceViolation("reservation_amount_mismatch")
        return reservation

    def mark_attempted(self, reservation_id: str) -> None:
        if reservation_id not in self._active or reservation_id in self._attempted:
            raise CommerceViolation("reservation_not_active")
        self._attempted.add(reservation_id)

    def reconcile(self, reservation_id: str, payment: PaymentEvidence) -> Reconciliation:
        reservation = self._active.get(reservation_id)
        if reservation is None or reservation_id not in self._attempted:
            raise CommerceViolation("reservation_not_attempted")
        if payment.charged_cents > reservation.reserved_cents:
            raise CommerceViolation("charge_exceeded_reservation")
        del self._active[reservation_id]
        self.spent_cents += payment.charged_cents
        return Reconciliation(
            reservation_id=reservation_id,
            authorized_cents=reservation.reserved_cents,
            charged_cents=payment.charged_cents,
            variance_cents=reservation.reserved_cents - payment.charged_cents,
            balanced=True,
        )


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
        budget: BudgetAccount,
        reservation_id: str,
        *,
        now_ns: int,
    ) -> CommerceOutcome:
        if now_ns >= order.expires_at_ns:
            raise CommerceViolation("order_expired")
        if order.order_hash in self.attempted_order_hashes:
            raise CommerceViolation("duplicate_purchase_attempt")

        budget.require_active(reservation_id, order, now_ns=now_ns)

        intent = purchase_intent(order)
        if not kernel.consume(permit, intent):
            raise CommerceViolation("permit_rejected")

        # Mark before the external call.  An uncertain network outcome must be
        # reconciled, not blindly retried with a new capability.
        budget.mark_attempted(reservation_id)
        self.attempted_order_hashes.add(order.order_hash)
        outcome = CommerceOutcome(order_hash=order.order_hash, authorized=True, capability_revoked=True)
        result = adapter.purchase(order, max_charge_cents=order.purchase_price_cents)

        if result.payment_id is not None or result.charged_cents is not None or result.receipt_hash is not None:
            if None in (result.payment_id, result.charged_cents, result.receipt_hash):
                raise CommerceViolation("incomplete_payment_evidence")
            if result.charged_cents < 0 or result.charged_cents > order.purchase_price_cents:
                raise CommerceViolation("charge_exceeded_authorized_amount")
            outcome.payment = PaymentEvidence(result.payment_id, result.charged_cents, result.receipt_hash)
            outcome.reconciliation = budget.reconcile(reservation_id, outcome.payment)

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
    outcome.verification = verification
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

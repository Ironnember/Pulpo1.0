"""Trusted read-only Name.com sandbox proposal construction for Hostile Worker V0.

The hostile worker proposes only a normalized domain name. This component runs
inside custody with a read-only provider credential, captures live registration
availability/prices, and produces the exact bounded Pulpo request/quote/order
that can later be sent through the external approval ceremony.

It creates no permit, reservation, execution right, or provider write.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from hashlib import sha256
import json
import secrets
import time
from typing import Any, Callable

from .commerce import (
    PILOT_PURCHASE_CEILING_CENTS,
    DomainPurchaseOrder,
    DomainPurchaseRequest,
    DomainQuote,
    assess_quote,
)
from .namecom_core import NameComCoreClient, NameComViolation


class NameComProposalViolation(RuntimeError):
    """Live sandbox discovery cannot safely produce an exact bounded proposal."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _usd_to_cents(value: Any) -> int:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise NameComProposalViolation("namecom_proposal_price_invalid") from exc
    if amount < 0:
        raise NameComProposalViolation("namecom_proposal_price_negative")
    return int(amount * 100)


@dataclass(frozen=True)
class NameComSandboxProposal:
    request: DomainPurchaseRequest
    quote: DomainQuote
    order: DomainPurchaseOrder
    availability_hash: str
    observed_at_ns: int
    expires_at_ns: int
    schema: str = "pulpo.namecom-sandbox-proposal.v0"


class NameComSandboxProposalBuilder:
    """Read-only proposal builder hard-pinned to Name.com sandbox."""

    def __init__(
        self,
        client: NameComCoreClient,
        *,
        principal: str,
        owner_ref: str,
        credential_ref: str = "credential://name-com/sandbox-executor",
        quote_ttl_ns: int = 5 * 60 * 1_000_000_000,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if client.config.environment != "sandbox" or client.config.allow_production:
            raise NameComProposalViolation("proposal_builder_must_use_sandbox")
        if not principal:
            raise NameComProposalViolation("proposal_principal_required")
        if not owner_ref.startswith("owner://") or owner_ref == "owner://":
            raise NameComProposalViolation("proposal_owner_ref_invalid")
        if not credential_ref.startswith("credential://") or credential_ref == "credential://":
            raise NameComProposalViolation("proposal_credential_ref_invalid")
        if isinstance(quote_ttl_ns, bool) or not isinstance(quote_ttl_ns, int) or quote_ttl_ns <= 0:
            raise NameComProposalViolation("proposal_ttl_invalid")
        if quote_ttl_ns > 15 * 60 * 1_000_000_000:
            raise NameComProposalViolation("proposal_ttl_exceeds_v0_ceiling")
        self.client = client
        self.principal = principal
        self.owner_ref = owner_ref
        self.credential_ref = credential_ref
        self.quote_ttl_ns = quote_ttl_ns
        self._clock = clock or time.time_ns

    def _now(self) -> int:
        try:
            value = self._clock()
        except Exception as exc:
            raise NameComProposalViolation("proposal_clock_unavailable") from exc
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise NameComProposalViolation("proposal_clock_invalid")
        return value

    def propose(self, domain: str) -> NameComSandboxProposal:
        if not isinstance(domain, str) or not domain or domain != domain.strip().lower():
            raise NameComProposalViolation("proposal_domain_must_be_normalized_lowercase")
        if len(domain) > 253 or "." not in domain:
            raise NameComProposalViolation("proposal_domain_invalid")

        observed_at_ns = self._now()
        try:
            decoded = self.client.check_availability(domain)
        except NameComViolation as exc:
            raise NameComProposalViolation(f"proposal_provider_unavailable:{exc}") from exc
        results = decoded.get("results")
        if not isinstance(results, list):
            raise NameComProposalViolation("proposal_results_invalid")
        matches = [
            item
            for item in results
            if isinstance(item, dict) and item.get("domainName") == domain
        ]
        if len(matches) != 1:
            raise NameComProposalViolation("proposal_domain_ambiguous")
        result = matches[0]
        if result.get("purchasable") is not True:
            raise NameComProposalViolation("proposal_domain_not_purchasable")
        if result.get("purchaseType") not in {None, "registration"}:
            raise NameComProposalViolation("proposal_purchase_type_not_registration")
        if result.get("premium") is True:
            raise NameComProposalViolation("proposal_premium_domain_forbidden")

        purchase_cents = _usd_to_cents(result.get("purchasePrice"))
        renewal_cents = _usd_to_cents(result.get("renewalPrice"))
        if purchase_cents > PILOT_PURCHASE_CEILING_CENTS:
            raise NameComProposalViolation("proposal_purchase_price_exceeds_pilot")

        expires_at_ns = observed_at_ns + self.quote_ttl_ns
        availability_material = {
            "schema": "pulpo.namecom-sandbox-availability.v0",
            "domain": domain,
            "observed_at_ns": observed_at_ns,
            "expires_at_ns": expires_at_ns,
            "purchasable": True,
            "purchase_type": result.get("purchaseType") or "registration",
            "purchase_price_cents": purchase_cents,
            "renewal_price_cents": renewal_cents,
            "premium": False,
            "reason": result.get("reason"),
        }
        availability_hash = _hash(availability_material)
        nonce = secrets.token_hex(8)
        request = DomainPurchaseRequest(
            request_id=f"namecom-sandbox-request:{availability_hash[:16]}:{nonce}",
            principal=self.principal,
            acceptable_domains=(domain,),
            max_purchase_cents=purchase_cents,
            max_renewal_cents=renewal_cents,
            approved_registrar="name.com",
            owner_ref=self.owner_ref,
            privacy_required=True,
            prohibited_upsells=("hosting", "email", "ssl"),
            expires_at_ns=expires_at_ns,
        )
        quote = DomainQuote(
            quote_id=f"namecom-sandbox-quote:{availability_hash[:16]}:{nonce}",
            domain=domain,
            registrar="name.com",
            purchase_price_cents=purchase_cents,
            renewal_price_cents=renewal_cents,
            owner_ref=self.owner_ref,
            # The exact create request will ask for privacy. Independent readback
            # still decides whether the provider actually honored that setting.
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=expires_at_ns,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref=self.credential_ref,
            now_ns=observed_at_ns,
        )
        if assessment.outcome != "allow" or assessment.order is None:
            raise NameComProposalViolation(f"proposal_assessment_rejected:{assessment.reason}")
        return NameComSandboxProposal(
            request=request,
            quote=quote,
            order=assessment.order,
            availability_hash=availability_hash,
            observed_at_ns=observed_at_ns,
            expires_at_ns=expires_at_ns,
        )

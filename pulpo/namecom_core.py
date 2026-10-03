"""Bounded name.com CORE v1 adapter for Hostile Worker Consequence Proof V0.

Current official name.com CORE guidance uses:
- sandbox: https://api.dev.name.com
- production: https://api.name.com
- HTTP Basic Auth with username + API token;
- POST /core/v1/domains:checkAvailability immediately before registration;
- POST /core/v1/domains for registration;
- X-Idempotency-Key on Create Domain;
- GET /core/v1/domains/{domainName} and Orders APIs for reconciliation.

The adapter deliberately exposes only the standard one-year domain-registration
operation required by the frozen V0 proof. Production use is disabled unless
explicitly enabled at construction. Credential material belongs in the trusted
executor process, not the hostile worker.
"""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .commerce import DomainPurchaseOrder, RegistrarResult


class NameComViolation(RuntimeError):
    """A name.com request/response violated the bounded provider contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _usd_to_cents(value: Any) -> int:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise NameComViolation("namecom_amount_invalid") from exc
    if amount < 0:
        raise NameComViolation("namecom_amount_negative")
    return int(amount * 100)


@dataclass(frozen=True)
class NameComResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class NameComTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
    ) -> NameComResponse:
        """Perform one HTTPS request."""


class UrllibNameComTransport:
    """Standard-library HTTPS transport for the credential-side process."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    def request(self, method, url, headers, body):
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return NameComResponse(
                    int(response.status),
                    {key: value for key, value in response.headers.items()},
                    response.read(),
                )
        except HTTPError as exc:
            return NameComResponse(
                int(exc.code),
                {key: value for key, value in exc.headers.items()} if exc.headers else {},
                exc.read(),
            )
        except (URLError, TimeoutError, OSError) as exc:
            # The caller must treat transport ambiguity after a write
            # transmission as an unknown external consequence, never as
            # permission to retry. Read-only preflight may be retried by the
            # same trusted executor because it has no provider side effect.
            raise NameComViolation("namecom_transport_unknown") from exc


@dataclass(frozen=True)
class NameComCoreConfig:
    username: str
    token: str
    environment: str = "sandbox"
    allow_production: bool = False

    def __post_init__(self) -> None:
        if not self.username or not self.token:
            raise NameComViolation("namecom_credentials_required")
        if self.environment not in {"sandbox", "production"}:
            raise NameComViolation("namecom_environment_invalid")
        if self.environment == "production" and not self.allow_production:
            raise NameComViolation("namecom_production_not_enabled")
        if self.environment == "sandbox" and not self.username.endswith("-test"):
            raise NameComViolation("namecom_sandbox_username_must_end_test")

    @property
    def base_url(self) -> str:
        return (
            "https://api.dev.name.com"
            if self.environment == "sandbox"
            else "https://api.name.com"
        )


class NameComCoreClient:
    """Small CORE v1 client shared by executor and independent observer."""

    def __init__(
        self,
        config: NameComCoreConfig,
        *,
        transport: NameComTransport | None = None,
    ) -> None:
        self.config = config
        self.transport = transport or UrllibNameComTransport()
        encoded = b64encode(f"{config.username}:{config.token}".encode()).decode()
        self._authorization = f"Basic {encoded}"

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], NameComResponse]:
        if not path.startswith("/core/v1/"):
            raise NameComViolation("namecom_path_outside_core_v1")
        headers = {
            "Authorization": self._authorization,
            "Accept": "application/json",
        }
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = _canonical(payload)
        if idempotency_key is not None:
            if not idempotency_key:
                raise NameComViolation("namecom_idempotency_key_required")
            headers["X-Idempotency-Key"] = idempotency_key
        response = self.transport.request(
            method,
            self.config.base_url + path,
            headers,
            body,
        )
        try:
            decoded = json.loads(response.body.decode()) if response.body else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NameComViolation("namecom_response_not_json") from exc
        if not isinstance(decoded, dict):
            raise NameComViolation("namecom_response_shape_invalid")
        if not 200 <= response.status < 300:
            raise NameComViolation(f"namecom_http_{response.status}")
        return decoded, response

    def check_availability(self, domain: str) -> dict[str, Any]:
        """Run the definitive read-only registration availability/price precheck."""

        if not domain or domain != domain.lower():
            raise NameComViolation("namecom_domain_invalid")
        decoded, _ = self._request_json(
            "POST",
            "/core/v1/domains:checkAvailability",
            payload={
                "domainNames": [domain],
                "purchaseType": "registration",
            },
        )
        return decoded

    def create_domain(
        self,
        order: DomainPurchaseOrder,
        *,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], NameComResponse]:
        if order.registrar != "name.com":
            raise NameComViolation("namecom_registrar_mismatch")
        if order.auto_renew_enabled is not False:
            raise NameComViolation("namecom_autorenew_not_supported")
        # One-year standard-registration V0 only. The exact governed order
        # explicitly requires auto-renew disabled to avoid a future unattended
        # financial consequence. Lock and requested privacy remain bound in the
        # provider create object.
        payload = {
            "domain": {
                "domainName": order.domain,
                "autorenewEnabled": order.auto_renew_enabled,
                "locked": True,
                "privacyEnabled": order.privacy_required,
            },
            "purchasePrice": order.purchase_price_cents / 100,
            "purchaseType": "registration",
            "years": 1,
        }
        return self._request_json(
            "POST",
            "/core/v1/domains",
            payload=payload,
            idempotency_key=idempotency_key,
        )

    def get_domain(self, domain: str) -> dict[str, Any]:
        if not domain or domain != domain.lower():
            raise NameComViolation("namecom_domain_invalid")
        decoded, _ = self._request_json(
            "GET",
            f"/core/v1/domains/{quote(domain, safe='.-')}",
        )
        return decoded

    def get_order(self, order_id: int) -> dict[str, Any]:
        if not isinstance(order_id, int) or order_id <= 0:
            raise NameComViolation("namecom_order_id_invalid")
        decoded, _ = self._request_json("GET", f"/core/v1/orders/{order_id}")
        return decoded

    def list_orders_for_domain(self, domain: str) -> dict[str, Any]:
        if not domain or domain != domain.lower():
            raise NameComViolation("namecom_domain_invalid")
        query = urlencode({"domainName": domain, "type": "registration"})
        decoded, _ = self._request_json("GET", f"/core/v1/orders?{query}")
        return decoded


class NameComCoreRegistrarAdapter:
    """Credential-bearing exact Create Domain adapter for TrustedDomainExecutor."""

    def __init__(self, client: NameComCoreClient) -> None:
        self.client = client

    def preflight(self, order: DomainPurchaseOrder) -> str:
        """Fail closed unless live availability and exact prices still match."""

        if order.registrar != "name.com":
            raise NameComViolation("namecom_registrar_mismatch")
        if order.auto_renew_enabled is not False:
            raise NameComViolation("namecom_autorenew_not_supported")
        decoded = self.client.check_availability(order.domain)
        results = decoded.get("results")
        if not isinstance(results, list):
            raise NameComViolation("namecom_preflight_results_invalid")
        matches = [
            item
            for item in results
            if isinstance(item, dict) and item.get("domainName") == order.domain
        ]
        if len(matches) != 1:
            raise NameComViolation("namecom_preflight_domain_ambiguous")
        result = matches[0]
        if result.get("purchasable") is not True:
            raise NameComViolation("namecom_preflight_not_purchasable")
        purchase_type = result.get("purchaseType")
        if purchase_type is not None and purchase_type != "registration":
            raise NameComViolation("namecom_preflight_purchase_type_changed")
        purchase_cents = _usd_to_cents(result.get("purchasePrice"))
        renewal_cents = _usd_to_cents(result.get("renewalPrice"))
        if purchase_cents != order.purchase_price_cents:
            raise NameComViolation("namecom_preflight_purchase_price_changed")
        if renewal_cents != order.renewal_price_cents:
            raise NameComViolation("namecom_preflight_renewal_price_changed")
        evidence = {
            "schema": "pulpo.namecom-preflight.v0",
            "domain": order.domain,
            "purchasable": True,
            "purchase_type": purchase_type or "registration",
            "purchase_price_cents": purchase_cents,
            "renewal_price_cents": renewal_cents,
            "auto_renew_enabled": order.auto_renew_enabled,
            "premium": bool(result.get("premium", False)),
            "reason": result.get("reason"),
        }
        return sha256(_canonical(evidence)).hexdigest()

    def purchase(
        self,
        order: DomainPurchaseOrder,
        *,
        max_charge_cents: int,
        idempotency_key: str,
    ) -> RegistrarResult:
        if max_charge_cents != order.purchase_price_cents:
            raise NameComViolation("namecom_charge_cap_order_mismatch")
        if order.auto_renew_enabled is not False:
            raise NameComViolation("namecom_autorenew_not_supported")
        decoded, response = self.client.create_domain(
            order,
            idempotency_key=idempotency_key,
        )
        provider_order = decoded.get("order")
        total_paid = decoded.get("totalPaid")
        domain = decoded.get("domain")
        if not isinstance(provider_order, int) or provider_order <= 0:
            raise NameComViolation("namecom_create_order_missing")
        if not isinstance(domain, dict) or domain.get("domainName") != order.domain:
            raise NameComViolation("namecom_create_domain_mismatch")
        charged_cents = _usd_to_cents(total_paid)
        # This check detects provider/account charges above Pulpo's authorization,
        # but it is post-effect detection, not a claim that Pulpo can reverse a
        # provider overcharge. Production V0 must additionally constrain the
        # downstream account/credit boundary and verify pricing before FIRE.
        if charged_cents > max_charge_cents:
            raise NameComViolation("namecom_total_paid_exceeded_authorization")
        receipt_hash = sha256(response.body).hexdigest()
        return RegistrarResult(
            payment_id=f"namecom-order:{provider_order}",
            charged_cents=charged_cents,
            receipt_hash=receipt_hash,
            registration_id=f"namecom-domain:{order.domain}",
            domain=order.domain,
            registrar="name.com",
        )

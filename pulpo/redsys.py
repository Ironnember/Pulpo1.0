"""Bounded Redsys sandbox payment proof surface for Pulpo.

This module is intentionally narrower than a production Redsys integration.
It proves the governance seam around one exact sandbox payment object while
leaving card handling and Redsys signing-key custody outside the intelligence
and canonical authority objects.

No production endpoint is accepted. A provider response is evidence only; it
does not become reconciliation or authority merely because Redsys returned it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
from typing import Any, Callable, Mapping

from .execution_context import (
    ExecutionContext,
    ExecutionContextCheck,
    bind_resource_to_execution_context,
    consume_context_bound_permit,
)
from .kernel import GovernanceKernel, Intent


REDSYS_SANDBOX_ORIGIN = "https://sis-t.redsys.es:25443"
REDSYS_PRODUCTION_ORIGIN = "https://sis.redsys.es"
REDSYS_SANDBOX_PAYMENT_PATH = "/sis/rest/trataPeticionREST"


class RedsysViolation(RuntimeError):
    """Raised when the bounded Redsys proof contract is violated."""


class RedsysExternalRealityUnknown(RedsysViolation):
    """Raised after authority consumption when provider reality is ambiguous."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class RedsysPayment:
    merchant_code: str
    terminal: str
    order_id: str
    amount_cents: int
    currency: str
    transaction_type: str
    principal: str
    session_id: str
    expires_at_ns: int
    operation_mode: str = "moto"
    environment: str = "sandbox"
    schema: str = "pulpo.redsys-payment.v0"

    def __post_init__(self) -> None:
        strings = (
            self.merchant_code,
            self.terminal,
            self.order_id,
            self.currency,
            self.transaction_type,
            self.principal,
            self.session_id,
            self.operation_mode,
            self.environment,
            self.schema,
        )
        if any(not isinstance(value, str) or not value for value in strings):
            raise ValueError("Redsys payment identity fields must be non-empty strings")
        if isinstance(self.amount_cents, bool) or not isinstance(self.amount_cents, int):
            raise TypeError("amount_cents must be an integer")
        if self.amount_cents <= 0:
            raise ValueError("amount_cents must be positive")
        if isinstance(self.expires_at_ns, bool) or not isinstance(self.expires_at_ns, int):
            raise TypeError("expires_at_ns must be an integer")
        if self.expires_at_ns <= 0:
            raise ValueError("expires_at_ns must be positive")
        if self.operation_mode != "moto":
            raise ValueError("only the bounded Redsys MOTO proof mode is supported")
        if self.environment != "sandbox":
            raise ValueError("only the Redsys sandbox environment is supported")
        if self.schema != "pulpo.redsys-payment.v0":
            raise ValueError("unsupported Redsys payment schema")

    @property
    def payment_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()

    @property
    def expected_context(self) -> ExecutionContext:
        return ExecutionContext(
            surface="redsys",
            authority_scope=(
                f"merchant:{self.merchant_code}:terminal:{self.terminal}:"
                f"mode:{self.operation_mode}:environment:{self.environment}"
            ),
            principal=self.principal,
            connection=f"origin:{REDSYS_SANDBOX_ORIGIN}",
        )


@dataclass(frozen=True)
class RedsysProviderReceipt:
    provider_reference: str
    result: str
    response_hash: str
    payment_hash: str
    authority_effect: str = "none"


@dataclass(frozen=True)
class RedsysExecutionResult:
    context_check: ExecutionContextCheck
    receipt: RedsysProviderReceipt


@dataclass(frozen=True)
class RedsysResponseShape:
    outcome: str
    error_code: str | None
    response_hash: str
    top_level_keys: tuple[str, ...]
    authority_effect: str = "none"


def classify_rest_response_shape(response: Mapping[str, Any]) -> RedsysResponseShape:
    """Classify a Redsys REST response without converting it into authority.

    Redsys documents two top-level response forms: a signed wrapper for a
    processed operation, and an unsigned errorCode object when a request
    could not be processed. Any other shape remains unknown.
    """

    if not isinstance(response, Mapping):
        raise RedsysViolation("redsys_response_invalid")
    normalized = dict(response)
    keys = tuple(sorted(str(key) for key in normalized))
    response_hash = sha256(_canonical(normalized)).hexdigest()
    lower = {str(key).casefold(): value for key, value in normalized.items()}
    error_code = lower.get("errorcode")
    if isinstance(error_code, str) and error_code:
        return RedsysResponseShape(
            "unprocessed_error",
            error_code,
            response_hash,
            keys,
        )
    required = {
        "ds_signatureversion",
        "ds_merchantparameters",
        "ds_signature",
    }
    if required.issubset(lower):
        return RedsysResponseShape(
            "signed_processed",
            None,
            response_hash,
            keys,
        )
    return RedsysResponseShape(
        "unrecognized",
        None,
        response_hash,
        keys,
    )


def payment_intent(payment: RedsysPayment) -> Intent:
    """Bind the exact sandbox payment and execution context into one Pulpo intent."""

    return Intent(
        principal=payment.principal,
        action="redsys_payment",
        resource=bind_resource_to_execution_context(
            f"redsys:payment:{payment.payment_hash}",
            payment.expected_context,
        ),
        cost=payment.amount_cents,
        session_id=payment.session_id,
    )


def refund_intent(payment: RedsysPayment) -> Intent:
    """Model refund authority as a distinct consequence class."""

    return Intent(
        principal=payment.principal,
        action="redsys_refund",
        resource=bind_resource_to_execution_context(
            f"redsys:refund:{payment.payment_hash}",
            payment.expected_context,
        ),
        cost=payment.amount_cents,
        session_id=payment.session_id,
    )


class RedsysSandboxGateway:
    """Consume exact Pulpo authority before one bounded sandbox transmission.

    The transport is injected so the proof matrix can establish zero-call denial
    behavior without external I/O. The live proof must place the actual Redsys
    signer/card-handling mechanism behind this boundary, not inside intelligence.
    """

    def __init__(
        self,
        *,
        origin: str = REDSYS_SANDBOX_ORIGIN,
        transport: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]],
    ) -> None:
        if origin != REDSYS_SANDBOX_ORIGIN:
            raise RedsysViolation("redsys_production_origin_forbidden")
        if not callable(transport):
            raise TypeError("transport must be callable")
        self.origin = origin
        self._transport = transport

    @staticmethod
    def _request_payload(payment: RedsysPayment) -> dict[str, Any]:
        return {
            "merchant_code": payment.merchant_code,
            "terminal": payment.terminal,
            "order_id": payment.order_id,
            "amount_cents": payment.amount_cents,
            "currency": payment.currency,
            "transaction_type": payment.transaction_type,
            "operation_mode": payment.operation_mode,
            "environment": payment.environment,
            "payment_hash": payment.payment_hash,
        }

    @staticmethod
    def _validate_provider_response(
        payment: RedsysPayment,
        response: Mapping[str, Any],
    ) -> RedsysProviderReceipt:
        if not isinstance(response, Mapping):
            raise RedsysViolation("redsys_response_invalid")
        expected = {
            "merchant_code": payment.merchant_code,
            "terminal": payment.terminal,
            "order_id": payment.order_id,
            "amount_cents": payment.amount_cents,
            "currency": payment.currency,
            "transaction_type": payment.transaction_type,
            "operation_mode": payment.operation_mode,
            "environment": payment.environment,
            "payment_hash": payment.payment_hash,
        }
        for key, value in expected.items():
            if response.get(key) != value:
                raise RedsysViolation("redsys_response_object_mismatch")
        provider_reference = response.get("provider_reference")
        result = response.get("result")
        if not isinstance(provider_reference, str) or not provider_reference:
            raise RedsysViolation("redsys_provider_reference_missing")
        if result not in {"approved", "declined"}:
            raise RedsysViolation("redsys_result_invalid")
        response_hash = sha256(_canonical(dict(response))).hexdigest()
        return RedsysProviderReceipt(
            provider_reference=provider_reference,
            result=result,
            response_hash=response_hash,
            payment_hash=payment.payment_hash,
        )

    def execute_payment(
        self,
        *,
        kernel: GovernanceKernel,
        permit: str | None,
        payment: RedsysPayment,
        observed_context: ExecutionContext | None,
        now_ns: int,
    ) -> RedsysExecutionResult:
        if not isinstance(kernel, GovernanceKernel):
            raise TypeError("kernel must be GovernanceKernel")
        if not isinstance(payment, RedsysPayment):
            raise TypeError("payment must be RedsysPayment")
        if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns <= 0:
            raise ValueError("now_ns must be a positive integer")
        if now_ns >= payment.expires_at_ns:
            raise RedsysViolation("redsys_payment_expired")
        if not isinstance(permit, str) or not permit:
            raise RedsysViolation("redsys_permit_required")

        intent = payment_intent(payment)
        check, consumed = consume_context_bound_permit(
            kernel,
            permit,
            intent,
            observed_context,
        )
        if not consumed:
            raise RedsysViolation(
                check.reason if check.outcome != "match" else "redsys_permit_rejected"
            )

        payload = self._request_payload(payment)
        try:
            response = self._transport(
                self.origin,
                REDSYS_SANDBOX_PAYMENT_PATH,
                payload,
            )
        except Exception as exc:
            raise RedsysExternalRealityUnknown(
                "redsys_external_reality_unknown"
            ) from exc

        receipt = self._validate_provider_response(payment, response)
        return RedsysExecutionResult(check, receipt)


def exact_context_matches(payment: RedsysPayment, observed_context: ExecutionContext) -> bool:
    """Convenience comparator for deterministic proof assertions."""

    return hmac.compare_digest(
        payment.expected_context.context_hash,
        observed_context.context_hash,
    )

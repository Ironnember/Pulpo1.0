#!/usr/bin/env python3
"""One-shot live Redsys sandbox proof for Pulpo Issue #234.

This script is intentionally bound to one frozen sandbox payment object. It:
1. creates one canonical Pulpo permit for that exact object;
2. consumes it through RedsysSandboxGateway;
3. sends one signed Redsys MOTO sandbox request;
4. verifies the signed Redsys response;
5. emits only secret-safe evidence.

There is no retry loop. Network/provider ambiguity is terminal.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pulpo.kernel import GovernanceKernel, Policy
from pulpo.redsys import (
    REDSYS_SANDBOX_ORIGIN,
    RedsysExternalRealityUnknown,
    RedsysPayment,
    RedsysSandboxGateway,
    classify_rest_response_shape,
    payment_intent,
)


EXPECTED_PAYMENT_HASH = "a446649f6d45487da4ec208515467d2e4447008e914856b1647ec732ec64d78d"
SIGNATURE_VERSION = "HMAC_SHA512_V2"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _derive_operation_key(signing_key: str, order_id: str) -> bytes:
    aes_key = signing_key[:16].encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(order_id.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(bytes(16))).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted)


def _sign(signing_key: str, order_id: str, merchant_parameters: str) -> str:
    operation_key = _derive_operation_key(signing_key, order_id)
    digest = hmac.new(
        operation_key,
        merchant_parameters.encode("ascii"),
        hashlib.sha512,
    ).digest()
    return _b64url_encode(digest)


def _casefold_get(mapping: dict[str, Any], name: str) -> Any:
    target = name.casefold()
    for key, value in mapping.items():
        if key.casefold() == target:
            return value
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "redirect forbidden in one-shot Redsys proof",
            headers,
            fp,
        )


def _post_once(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "pulpo-redsys-sandbox-proof-v0",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=20) as response:
        body = response.read()
        if getattr(response, "status", 200) != 200:
            raise RuntimeError(f"unexpected HTTP status {response.status}")
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Redsys response wrapper must be an object")
    return value


def _live_transport(origin: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    signing_key = os.environ["REDSYS_SANDBOX_SIGNING_KEY"]
    pan = os.environ["REDSYS_SANDBOX_PAN"]
    expiry = os.environ["REDSYS_SANDBOX_EXPIRY"]
    cvv = os.environ["REDSYS_SANDBOX_CVV"]

    if origin != REDSYS_SANDBOX_ORIGIN:
        raise RuntimeError("sandbox origin mismatch")
    if path != "/sis/rest/trataPeticionREST":
        raise RuntimeError("sandbox path mismatch")
    if payload.get("payment_hash") != EXPECTED_PAYMENT_HASH:
        raise RuntimeError("payment hash mismatch before provider call")
    if payload.get("operation_mode") != "moto":
        raise RuntimeError("operation mode mismatch before provider call")

    provider_parameters = {
        "DS_MERCHANT_AMOUNT": str(payload["amount_cents"]),
        "DS_MERCHANT_CURRENCY": str(payload["currency"]),
        "DS_MERCHANT_CVV2": cvv,
        "DS_MERCHANT_DIRECTPAYMENT": "moto",
        "DS_MERCHANT_EXPIRYDATE": expiry,
        "DS_MERCHANT_MERCHANTCODE": str(payload["merchant_code"]),
        "DS_MERCHANT_ORDER": str(payload["order_id"]),
        "DS_MERCHANT_PAN": pan,
        "DS_MERCHANT_TERMINAL": str(payload["terminal"]),
        "DS_MERCHANT_TRANSACTIONTYPE": str(payload["transaction_type"]),
    }
    merchant_parameters = _b64url_encode(
        json.dumps(provider_parameters, separators=(",", ":")).encode("utf-8")
    )
    signature = _sign(
        signing_key,
        str(payload["order_id"]),
        merchant_parameters,
    )
    wrapper = {
        "Ds_SignatureVersion": SIGNATURE_VERSION,
        "Ds_MerchantParameters": merchant_parameters,
        "Ds_Signature": signature,
    }

    raw_response = _post_once(origin + path, wrapper)
    response_shape = classify_rest_response_shape(raw_response)
    print(
        json.dumps(
            {
                "schema": "pulpo.redsys-provider-response-shape.v0",
                "payment_hash": payload["payment_hash"],
                "response_shape": response_shape.outcome,
                "error_code": response_shape.error_code,
                "response_hash": response_shape.response_hash,
                "top_level_keys": response_shape.top_level_keys,
                "authority_effect": response_shape.authority_effect,
            },
            sort_keys=True,
        )
    )
    if response_shape.outcome == "unprocessed_error":
        raise RuntimeError(
            f"Redsys request not processed: {response_shape.error_code}"
        )
    if response_shape.outcome != "signed_processed":
        raise RuntimeError("Redsys response shape unrecognized")

    response_version = _casefold_get(raw_response, "Ds_SignatureVersion")
    response_parameters = _casefold_get(raw_response, "Ds_MerchantParameters")
    response_signature = _casefold_get(raw_response, "Ds_Signature")
    if response_version != SIGNATURE_VERSION:
        raise RuntimeError("Redsys response signature version mismatch")
    if not isinstance(response_parameters, str) or not isinstance(response_signature, str):
        raise RuntimeError("Redsys signed response fields missing")

    decoded = json.loads(_b64url_decode(response_parameters).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("Redsys response parameters must decode to an object")
    response_order = _casefold_get(decoded, "Ds_Order")
    if not isinstance(response_order, str):
        response_order = str(response_order)
    expected_signature = _sign(signing_key, response_order, response_parameters)
    if not hmac.compare_digest(expected_signature, response_signature):
        raise RuntimeError("Redsys response signature invalid")

    response_code = str(_casefold_get(decoded, "Ds_Response"))
    approved = response_code.isdigit() and 0 <= int(response_code) <= 99
    authorisation = _casefold_get(decoded, "Ds_AuthorisationCode")
    provider_reference = (
        f"authorisation:{authorisation}"
        if isinstance(authorisation, str) and authorisation
        else f"response:{response_code}"
    )

    normalized = {
        "merchant_code": str(_casefold_get(decoded, "Ds_MerchantCode")),
        "terminal": str(_casefold_get(decoded, "Ds_Terminal")),
        "order_id": str(_casefold_get(decoded, "Ds_Order")),
        "amount_cents": int(str(_casefold_get(decoded, "Ds_Amount"))),
        "currency": str(_casefold_get(decoded, "Ds_Currency")),
        "transaction_type": str(_casefold_get(decoded, "Ds_TransactionType")),
        "operation_mode": "moto",
        "environment": "sandbox",
        "payment_hash": payload["payment_hash"],
        "provider_reference": provider_reference,
        "result": "approved" if approved else "declined",
        "redsys_response_code": response_code,
    }
    return normalized


def main() -> int:
    now_ns = time.time_ns()
    payment = RedsysPayment(
        merchant_code="999008881",
        terminal="872",
        order_id="180920260001",
        amount_cents=123,
        currency="978",
        transaction_type="0",
        principal="agent:commerce",
        session_id="redsys-sandbox-live-moto-1",
        expires_at_ns=1789722000000000000,
        operation_mode="moto",
        environment="sandbox",
    )
    if payment.payment_hash != EXPECTED_PAYMENT_HASH:
        raise RuntimeError(
            f"frozen payment hash mismatch: {payment.payment_hash}"
        )
    if now_ns >= payment.expires_at_ns:
        raise RuntimeError("frozen Redsys sandbox object expired before FIRE")

    kernel = GovernanceKernel(
        Policy(frozenset({"redsys_payment"}), 3_000),
        secret=os.urandom(32),
        clock=time.time_ns,
    )
    intent = payment_intent(payment)
    decision = kernel.evaluate(intent)
    if decision.outcome != "allow" or decision.permit is None:
        raise RuntimeError(f"Pulpo authorization failed: {decision.reason}")

    gateway = RedsysSandboxGateway(transport=_live_transport)
    try:
        result = gateway.execute_payment(
            kernel=kernel,
            permit=decision.permit,
            payment=payment,
            observed_context=payment.expected_context,
            now_ns=time.time_ns(),
        )
    except RedsysExternalRealityUnknown:
        print(
            json.dumps(
                {
                    "schema": "pulpo.redsys-live-proof.result.v0",
                    "payment_hash": payment.payment_hash,
                    "outcome": "EXTERNAL_REALITY_UNKNOWN",
                    "automatic_retry": False,
                },
                sort_keys=True,
            )
        )
        raise

    safe = {
        "schema": "pulpo.redsys-live-proof.result.v0",
        "payment_hash": payment.payment_hash,
        "context_outcome": result.context_check.outcome,
        "provider_result": result.receipt.result,
        "provider_reference": result.receipt.provider_reference,
        "response_hash": result.receipt.response_hash,
        "authority_effect_of_provider_receipt": result.receipt.authority_effect,
        "automatic_retry": False,
        "permit_replay_after_fire": kernel.consume(decision.permit, intent),
    }
    print(json.dumps(safe, sort_keys=True))
    if safe["permit_replay_after_fire"] is not False:
        raise RuntimeError("consumed permit unexpectedly replayable")
    if result.receipt.result != "approved":
        raise RuntimeError("Redsys sandbox provider did not approve frozen payment")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

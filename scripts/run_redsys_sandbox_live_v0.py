#!/usr/bin/env python3
"""One-shot live Redsys sandbox proof for Pulpo Issue #234.

This script is intentionally bound to one frozen sandbox payment object. It:
1. requires one externally signed Pulpo approval envelope for that exact object;
2. mints and consumes one permit through durable kernel state;
3. sends one signed Redsys MOTO sandbox request;
4. verifies the signed Redsys response;
5. emits only secret-safe provider evidence.

It refuses to run inside GitHub Actions. The live ceremony requires a stable
non-CI state path so approval and permit replay denial survive process restart.

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
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pulpo.authority import ApprovalEnvelope, AuthorityTrust, P256ApprovalVerifier
from pulpo.state import SQLiteKernelState
from pulpo.redsys import (
    REDSYS_SANDBOX_ORIGIN,
    RedsysExternalRealityUnknown,
    RedsysPayment,
    RedsysSandboxGateway,
    authorize_payment_with_external_approval,
    classify_rest_response_shape,
)


EXPECTED_PAYMENT_HASH = "f96f419575a4e8a18973ba1f18954bb31719bcca8f58712071ffc66e3f4f7f6f"
EXPECTED_AUTHORITY_KEY_FINGERPRINT = "b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127"
SIGNATURE_VERSION = "HMAC_SHA512_V2"



def _required_json_env(name: str) -> dict[str, Any]:
    raw = os.environ.get(name)
    if not raw:
        raise RuntimeError(f"missing required external authority input: {name}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {name}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{name} must contain one JSON object")
    return value


def _load_external_authority() -> tuple[AuthorityTrust, P256ApprovalVerifier, ApprovalEnvelope]:
    trust = AuthorityTrust(**_required_json_env("PULPO_REDSYS_AUTHORITY_TRUST_JSON"))
    envelope = ApprovalEnvelope(**_required_json_env("PULPO_REDSYS_APPROVAL_ENVELOPE_JSON"))
    if trust.algorithm != "ecdsa-p256-sha256":
        raise RuntimeError("Redsys live proof requires P-256 authority trust")
    if trust.key_fingerprint != EXPECTED_AUTHORITY_KEY_FINGERPRINT:
        raise RuntimeError("authority trust fingerprint does not match accepted HSM key")
    if envelope.trust_hash != trust.trust_hash:
        raise RuntimeError("approval envelope trust hash does not match pinned trust")

    public_hex = os.environ.get("PULPO_REDSYS_AUTHORITY_PUBLIC_KEY_HEX", "")
    try:
        public_key = bytes.fromhex(public_hex)
    except ValueError as exc:
        raise RuntimeError("authority public key must be hex") from exc
    if len(public_key) != 65 or public_key[:1] != b"\x04":
        raise RuntimeError("authority public key must be an uncompressed P-256 SEC1 point")
    if hashlib.sha256(public_key).hexdigest() != EXPECTED_AUTHORITY_KEY_FINGERPRINT:
        raise RuntimeError("authority public key does not match accepted HSM fingerprint")

    verifier = P256ApprovalVerifier(
        authority_id=trust.authority_id,
        verifier_id=trust.verifier_id,
        key_id=trust.key_id,
        public_key=public_key,
    )
    if verifier.algorithm != trust.algorithm or verifier.key_fingerprint != trust.key_fingerprint:
        raise RuntimeError("authority verifier does not match pinned trust")
    return trust, verifier, envelope


def _durable_state_path() -> Path:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        raise RuntimeError("live Redsys proof requires durable non-CI runtime state")
    raw = os.environ.get("PULPO_REDSYS_KERNEL_STATE_PATH", "")
    if not raw:
        raise RuntimeError("PULPO_REDSYS_KERNEL_STATE_PATH is required")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise RuntimeError("Redsys kernel state path must be absolute")
    resolved = path.resolve()
    for root in (Path("/tmp"), Path("/var/tmp")):
        if resolved == root or root in resolved.parents:
            raise RuntimeError("Redsys kernel state may not use an ephemeral temp path")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        temp = Path(runner_temp).expanduser().resolve()
        if resolved == temp or temp in resolved.parents:
            raise RuntimeError("Redsys kernel state may not use RUNNER_TEMP")
    if not resolved.parent.exists() or not resolved.parent.is_dir():
        raise RuntimeError("Redsys kernel state parent directory must already exist")
    return resolved

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
        order_id="220920260001",
        amount_cents=123,
        currency="978",
        transaction_type="0",
        principal="agent:commerce",
        session_id="redsys-sandbox-live-moto-3",
        expires_at_ns=1792065600000000000,
        operation_mode="moto",
        environment="sandbox",
    )
    if payment.payment_hash != EXPECTED_PAYMENT_HASH:
        raise RuntimeError(
            f"frozen payment hash mismatch: {payment.payment_hash}"
        )
    if now_ns >= payment.expires_at_ns:
        raise RuntimeError("frozen Redsys sandbox object expired before FIRE")

    state = SQLiteKernelState(_durable_state_path())
    try:
        trust, verifier, envelope = _load_external_authority()
        kernel, intent, permit = authorize_payment_with_external_approval(
            payment,
            envelope,
            trust=trust,
            verifier=verifier,
            clock=time.time_ns,
            state=state,
        )

        gateway = RedsysSandboxGateway(transport=_live_transport)
        try:
            result = gateway.execute_payment(
                kernel=kernel,
                permit=permit,
                payment=payment,
                observed_context=payment.expected_context,
                now_ns=time.time_ns(),
            )
        except RedsysExternalRealityUnknown:
            print(
                json.dumps(
                    {
                        "schema": "pulpo.redsys-live-proof.result.v1",
                        "payment_hash": payment.payment_hash,
                        "approval_envelope_hash": envelope.envelope_hash,
                        "authority_key_fingerprint": trust.key_fingerprint,
                        "outcome": "EXTERNAL_REALITY_UNKNOWN",
                        "automatic_retry": False,
                    },
                    sort_keys=True,
                )
            )
            raise

        safe = {
            "schema": "pulpo.redsys-live-proof.result.v1",
            "payment_hash": payment.payment_hash,
            "approval_envelope_hash": envelope.envelope_hash,
            "approval_id": envelope.approval_id,
            "authority_key_fingerprint": trust.key_fingerprint,
            "context_outcome": result.context_check.outcome,
            "provider_result": result.receipt.result,
            "provider_reference": result.receipt.provider_reference,
            "response_hash": result.receipt.response_hash,
            "authority_effect_of_provider_receipt": result.receipt.authority_effect,
            "reconciliation_status": "PROVIDER_EVIDENCE_ONLY",
            "automatic_retry": False,
            "permit_replay_after_fire": kernel.consume(permit, intent),
        }
        print(json.dumps(safe, sort_keys=True))
        if safe["permit_replay_after_fire"] is not False:
            raise RuntimeError("consumed permit unexpectedly replayable")
        if result.receipt.result != "approved":
            raise RuntimeError("Redsys sandbox provider did not approve frozen payment")
        return 0
    finally:
        state.close()


if __name__ == "__main__":
    raise SystemExit(main())

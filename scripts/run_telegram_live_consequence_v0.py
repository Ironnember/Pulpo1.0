#!/usr/bin/env python3
"""Run one externally authorized Telegram sendMessage consequence.

This wrapper is intentionally narrow. It reuses canonical Pulpo authority and
Telegram execution code and refuses provider transmission unless all of the
following are supplied on the local operator surface:

- exact numeric bot identity and numeric private-test chat;
- pinned external authority trust + public verification key;
- two independently signed approval envelopes, one for capability activation
  and one for the exact message object;
- explicit PULPO_TELEGRAM_FIRE=1;
- the Telegram bot token entered through a hidden prompt at execution time.

No token is accepted through argv, committed files, or printed evidence.
Provider success is emitted only as a provider claim; it is not upgraded to
independent reconciliation evidence by this wrapper.
"""

from __future__ import annotations

from dataclasses import asdict
from getpass import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
CUSTODY_SRC = ROOT / "custody-service" / "src"
if str(CUSTODY_SRC) not in sys.path:
    sys.path.insert(0, str(CUSTODY_SRC))

from pulpo import GovernanceKernel, Policy  # noqa: E402
from pulpo.authority import ApprovalEnvelope, AuthorityTrust, P256ApprovalVerifier  # noqa: E402
from pulpo.telegram import (  # noqa: E402
    TELEGRAM_ACTIVATE_ACTION,
    TELEGRAM_SEND_ACTION,
    GovernedTelegramSender,
    TelegramOutboundMessage,
)
from pulpo_custody_service.telegram_transport import TelegramBotApiTransport  # noqa: E402


SCHEMA = "pulpo.telegram-live-consequence.v0"
PRINCIPAL = "agent:telegram-live-proof"
SESSION_ID = "telegram-live-consequence-v0"
MESSAGE_TEXT = "Pulpo external consequence proof v0 — governed one-use Telegram send."


class CeremonyBlocked(RuntimeError):
    pass


def _required(name: str, environ: Mapping[str, str]) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise CeremonyBlocked(f"missing required local input: {name}")
    return value


def _positive_int(name: str, environ: Mapping[str, str]) -> int:
    raw = _required(name, environ)
    try:
        value = int(raw)
    except ValueError as exc:
        raise CeremonyBlocked(f"{name} must be an integer") from exc
    if value <= 0:
        raise CeremonyBlocked(f"{name} must be positive")
    return value


def _nonzero_int(name: str, environ: Mapping[str, str]) -> int:
    raw = _required(name, environ)
    try:
        value = int(raw)
    except ValueError as exc:
        raise CeremonyBlocked(f"{name} must be an integer") from exc
    if value == 0:
        raise CeremonyBlocked(f"{name} must not be zero")
    return value


def _json_env(name: str, environ: Mapping[str, str]) -> dict[str, object]:
    raw = _required(name, environ)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CeremonyBlocked(f"{name} must contain valid JSON") from exc
    if not isinstance(value, dict):
        raise CeremonyBlocked(f"{name} must contain a JSON object")
    return value


def _fire_requested(environ: Mapping[str, str]) -> bool:
    return environ.get("PULPO_TELEGRAM_FIRE", "") == "1"


def _message(environ: Mapping[str, str]) -> TelegramOutboundMessage:
    return TelegramOutboundMessage(
        bot_id=_positive_int("PULPO_TELEGRAM_EXPECTED_BOT_ID", environ),
        chat_id=_nonzero_int("PULPO_TELEGRAM_ALLOWED_CHAT_ID", environ),
        text=MESSAGE_TEXT,
    )


def _trust(environ: Mapping[str, str]) -> AuthorityTrust:
    return AuthorityTrust(**_json_env("PULPO_AUTHORITY_TRUST_JSON", environ))


def _approval(name: str, environ: Mapping[str, str]) -> ApprovalEnvelope:
    return ApprovalEnvelope(**_json_env(name, environ))


def _verifier(trust: AuthorityTrust, environ: Mapping[str, str]) -> P256ApprovalVerifier:
    raw = _required("PULPO_AUTHORITY_PUBLIC_KEY_HEX", environ)
    try:
        public_key = bytes.fromhex(raw)
    except ValueError as exc:
        raise CeremonyBlocked("PULPO_AUTHORITY_PUBLIC_KEY_HEX must be hexadecimal") from exc
    verifier = P256ApprovalVerifier(
        authority_id=trust.authority_id,
        verifier_id=trust.verifier_id,
        key_id=trust.key_id,
        public_key=public_key,
    )
    if verifier.algorithm != trust.algorithm:
        raise CeremonyBlocked("authority algorithm does not match pinned trust")
    if verifier.key_fingerprint != trust.key_fingerprint:
        raise CeremonyBlocked("authority public key does not match pinned trust")
    return verifier


def frozen_object(environ: Mapping[str, str]) -> dict[str, object]:
    message = _message(environ)
    return {
        "schema": SCHEMA,
        "principal": PRINCIPAL,
        "session_id": SESSION_ID,
        "bot_id": message.bot_id,
        "chat_id": message.chat_id,
        "text": message.text,
        "message_hash": message.message_hash,
        "activation_resource": message.activation_resource,
        "message_resource": message.resource,
        "cost": 0,
        "provider_method": "sendMessage",
        "automatic_retry": False,
    }


def main() -> int:
    env = dict(os.environ)
    message = _message(env)
    frozen = frozen_object(env)
    print(json.dumps({**frozen, "authority_effect": "none", "provider_effect": "none"}, sort_keys=True))

    if not _fire_requested(env):
        print("telegram_live_consequence=BLOCKED:explicit_fire_required")
        return 3

    trust = _trust(env)
    verifier = _verifier(trust, env)
    policy = Policy(
        frozenset({TELEGRAM_ACTIVATE_ACTION, TELEGRAM_SEND_ACTION}),
        0,
        frozenset({TELEGRAM_ACTIVATE_ACTION, TELEGRAM_SEND_ACTION}),
        authority_trust=trust,
    )
    kernel = GovernanceKernel(policy, approval_verifier=verifier)
    sender = GovernedTelegramSender(
        kernel,
        TelegramBotApiTransport(
            bot_token=getpass("Telegram bot token (hidden): "),
            expected_bot_id=message.bot_id,
            allowed_chat_id=message.chat_id,
        ),
    )

    activation_intent = message.activation_intent(principal=PRINCIPAL, session_id=SESSION_ID)
    send_intent = message.intent(principal=PRINCIPAL, session_id=SESSION_ID)

    activation_approval = _approval("PULPO_TELEGRAM_ACTIVATION_APPROVAL_JSON", env)
    message_approval = _approval("PULPO_TELEGRAM_MESSAGE_APPROVAL_JSON", env)

    activation = kernel.evaluate_with_approval(activation_intent, activation_approval)
    if activation.outcome != "allow" or not activation.permit:
        raise CeremonyBlocked(f"activation approval denied: {activation.reason}")

    send = kernel.evaluate_with_approval(send_intent, message_approval)
    if send.outcome != "allow" or not send.permit:
        raise CeremonyBlocked(f"message approval denied: {send.reason}")

    provider_claim = sender.execute(
        message,
        activation_permit=activation.permit,
        message_permit=send.permit,
        principal=PRINCIPAL,
        session_id=SESSION_ID,
    )

    if not kernel.verify_audit():
        raise CeremonyBlocked("canonical audit verification failed after provider transmission")

    audit_tail = kernel.audit[-1]["hash"] if kernel.audit else "0" * 64
    output = {
        "schema": SCHEMA,
        "frozen_object": frozen,
        "activation_intent_hash": kernel.intent_hash(activation_intent),
        "message_intent_hash": kernel.intent_hash(send_intent),
        "policy_hash": kernel.policy_hash,
        "activation_approval_id": activation_approval.approval_id,
        "message_approval_id": message_approval.approval_id,
        "activation_envelope_hash": activation_approval.envelope_hash,
        "message_envelope_hash": message_approval.envelope_hash,
        "provider_claim": dict(provider_claim),
        "canonical_audit_valid": True,
        "canonical_audit_tail": audit_tail,
        "provider_effect": "provider_claim_only",
        "independent_reconciliation": "required",
        "automatic_retry": False,
    }
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CeremonyBlocked as exc:
        print(f"telegram_live_consequence=BLOCKED:{exc}", file=sys.stderr)
        raise SystemExit(2)

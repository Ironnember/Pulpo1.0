#!/usr/bin/env python3
"""Secret-safe local handoff for one real governed Telegram test message.

The Telegram bot token is collected with ``getpass`` from the operator's local
TTY. It is never accepted as a command-line argument, environment variable,
repository value, or printed evidence field.

This is a test handoff, not a production bot runtime and not proof of independent
authority. The local operator explicitly confirms one exact low-risk message.
"""

from __future__ import annotations

import argparse
from getpass import getpass
import json
from pathlib import Path
import secrets
import sys
import tempfile

from pulpo import AgentGrant, GovernanceKernel, Policy, SQLiteKernelState
from pulpo.telegram import (
    GovernedTelegramSender,
    TELEGRAM_SEND_ACTION,
    TelegramOutboundMessage,
    TelegramSendRejected,
)
from pulpo_custody_service.telegram_transport import (
    TelegramBotApiTransport,
    TelegramProviderError,
    TelegramTransportConfigError,
)


PRINCIPAL = "agent:telegram-live-probe-v0"
DEFAULT_MESSAGE = "Pulpo governed Telegram proof v0"


def _parse_nonzero_int(value: str, *, field: str, positive: bool = False) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if parsed == 0 or (positive and parsed < 0):
        qualifier = "positive" if positive else "non-zero"
        raise ValueError(f"{field} must be {qualifier}")
    return parsed


def _prompt_int(label: str, *, field: str, positive: bool = False) -> int:
    while True:
        raw = input(label).strip()
        try:
            return _parse_nonzero_int(raw, field=field, positive=positive)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send one exact Telegram test message through a local Pulpo one-use permit."
    )
    parser.add_argument(
        "--bot-id",
        type=int,
        help="Expected numeric Telegram bot ID. If omitted, prompt locally.",
    )
    parser.add_argument(
        "--chat-id",
        type=int,
        help="Pinned numeric private test chat ID. If omitted, prompt locally.",
    )
    parser.add_argument(
        "--message",
        default=DEFAULT_MESSAGE,
        help="Exact plain-text test message. Defaults to a fixed Pulpo proof message.",
    )
    return parser.parse_args()


def _reopen_and_prove_spent(
    *,
    state_path: Path,
    policy: Policy,
    kernel_secret: bytes,
    permit: str,
    message: TelegramOutboundMessage,
    session_id: str,
) -> tuple[bool, bool]:
    reopened_state = SQLiteKernelState(state_path)
    try:
        reopened_kernel = GovernanceKernel(
            policy,
            secret=kernel_secret,
            state=reopened_state,
        )
        intent = message.intent(principal=PRINCIPAL, session_id=session_id)
        replay_succeeded = reopened_kernel.consume(permit, intent)
        audit_valid = reopened_kernel.verify_audit()
        return replay_succeeded, audit_valid
    finally:
        reopened_state.close()


def main() -> int:
    args = _arguments()
    if args.bot_id is not None and args.bot_id <= 0:
        print("--bot-id must be positive", file=sys.stderr)
        return 2
    if args.chat_id == 0:
        print("--chat-id must be non-zero", file=sys.stderr)
        return 2
    if not isinstance(args.message, str) or not args.message:
        print("--message must be non-empty", file=sys.stderr)
        return 2

    bot_id = args.bot_id or _prompt_int(
        "Expected Telegram bot ID: ",
        field="bot ID",
        positive=True,
    )
    chat_id = args.chat_id or _prompt_int(
        "Private numeric Telegram test chat ID: ",
        field="chat ID",
    )

    try:
        message = TelegramOutboundMessage(chat_id, args.message)
    except ValueError as exc:
        print(f"message rejected before authority: {exc}", file=sys.stderr)
        return 2

    token = getpass("Telegram TEST bot token (hidden; never paste it into chat): ").strip()
    if not token:
        print("no Telegram bot token supplied", file=sys.stderr)
        return 2

    try:
        transport = TelegramBotApiTransport(
            bot_token=token,
            expected_bot_id=bot_id,
            allowed_chat_id=chat_id,
        )
    except TelegramTransportConfigError as exc:
        print(f"custody configuration rejected: {exc}", file=sys.stderr)
        return 2
    finally:
        # Remove the additional local reference as soon as custody construction
        # has completed. The transport retains the token privately in memory.
        token = ""

    resource_prefix = f"telegram:sendMessage:{chat_id}:"
    grant = AgentGrant(
        principal=PRINCIPAL,
        allowed_actions=frozenset({TELEGRAM_SEND_ACTION}),
        resource_prefixes=(resource_prefix,),
        max_cost=0,
    )
    policy = Policy(
        allowed_actions=frozenset({TELEGRAM_SEND_ACTION}),
        max_cost=0,
        agent_grants=(grant,),
    )
    kernel_secret = secrets.token_bytes(32)
    session_id = f"telegram-live-probe:{secrets.token_hex(12)}"

    with tempfile.TemporaryDirectory(prefix="pulpo-telegram-live-v0-") as directory:
        state_path = Path(directory) / "kernel.sqlite3"
        state = SQLiteKernelState(state_path)
        try:
            kernel = GovernanceKernel(
                policy,
                secret=kernel_secret,
                state=state,
            )
            sender = GovernedTelegramSender(kernel, transport)
            decision = sender.evaluate(
                message,
                principal=PRINCIPAL,
                session_id=session_id,
            )
            if decision.outcome != "allow" or not decision.permit:
                print(
                    json.dumps(
                        {
                            "result": "DENIED_BEFORE_PROVIDER",
                            "reason": decision.reason,
                            "message_hash": message.message_hash,
                            "intent_hash": decision.intent_hash,
                            "authority_effect": "none",
                        },
                        sort_keys=True,
                    )
                )
                return 3

            confirmation = f"SEND {message.message_hash[:12]}"
            print("\nFrozen live test object:")
            print(f"  bot_id: {bot_id}")
            print(f"  chat_id: {chat_id}")
            print(f"  message_hash: {message.message_hash}")
            print(f"  intent_hash: {decision.intent_hash}")
            print(f"  text: {message.text}")
            print("  maximum provider transmissions authorized by this permit: 1")
            typed = input(f"Type exactly '{confirmation}' to release the one test send: ").strip()
            if typed != confirmation:
                print("local operator did not release the external effect; no provider call made")
                return 4

            provider_claim = None
            provider_status = "UNKNOWN"
            provider_error = None
            try:
                provider_claim = sender.execute(
                    message,
                    permit=decision.permit,
                    principal=PRINCIPAL,
                    session_id=session_id,
                )
                provider_status = "PROVIDER_CLAIM_RECEIVED"
            except TelegramSendRejected as exc:
                provider_status = "DENIED_BEFORE_PROVIDER"
                provider_error = str(exc)
            except TelegramProviderError as exc:
                # A timeout/network/provider error does not prove no consequence.
                # Do not retry automatically; the permit has already been spent.
                provider_status = "EXTERNAL_REALITY_UNKNOWN"
                provider_error = str(exc)
            finally:
                state.close()

            replay_succeeded, audit_valid = _reopen_and_prove_spent(
                state_path=state_path,
                policy=policy,
                kernel_secret=kernel_secret,
                permit=decision.permit,
                message=message,
                session_id=session_id,
            )

            evidence = {
                "schema": "pulpo.telegram-live-handoff.v0",
                "provider_status": provider_status,
                "provider_claim": provider_claim,
                "provider_error": provider_error,
                "message_hash": message.message_hash,
                "intent_hash": decision.intent_hash,
                "principal": PRINCIPAL,
                "session_id": session_id,
                "replay_succeeded_after_state_reopen": replay_succeeded,
                "audit_valid_after_state_reopen": audit_valid,
                "automatic_retry_performed": False,
                "token_projected_into_evidence": False,
                "authority_scope": "local_operator_confirmed_single_low_risk_test_message",
                "independent_observation": False,
            }
            print("\nSanitized Pulpo live handoff evidence:")
            print(json.dumps(evidence, indent=2, sort_keys=True))

            if replay_succeeded or not audit_valid:
                return 5
            if provider_status == "PROVIDER_CLAIM_RECEIVED":
                return 0
            # Unknown external reality is deliberately non-successful and must
            # be reconciled before any new send is authorized.
            return 6
        finally:
            # close() is idempotent enough for sqlite here; if execute closed it
            # above this finalizer simply tolerates the already closed object.
            try:
                state.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

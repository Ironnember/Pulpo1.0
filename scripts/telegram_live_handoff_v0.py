#!/usr/bin/env python3
"""Secret-safe local handoff for one real governed Telegram test message.

The Telegram bot token is collected with ``getpass`` from the operator's local
TTY. It is never accepted as a command-line argument, environment variable,
repository value, or printed evidence field.

If a bot ID or chat ID is not supplied, the script may use Telegram's read-only
``getMe`` / ``getUpdates`` methods locally to discover identifiers. Discovery
prints numeric identifiers and chat type only; message text is never printed or
forwarded to a model.

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
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from pulpo import AgentGrant, GovernanceKernel, Policy, SQLiteKernelState
from pulpo.telegram import (
    GovernedTelegramSender,
    TELEGRAM_SEND_ACTION,
    TelegramOutboundMessage,
    TelegramSendRejected,
)
from pulpo_custody_service.telegram_transport import (
    TELEGRAM_API_ORIGIN,
    TELEGRAM_TIMEOUT_SECONDS,
    TelegramBotApiTransport,
    TelegramProviderError,
    TelegramTransportConfigError,
)


PRINCIPAL = "agent:telegram-live-probe-v0"
DEFAULT_MESSAGE = "Pulpo governed Telegram proof v0"
_MAX_DISCOVERY_BYTES = 1_000_000


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
        help="Expected numeric Telegram bot ID. If omitted, discover locally with getMe.",
    )
    parser.add_argument(
        "--chat-id",
        type=int,
        help="Pinned numeric private test chat ID. If omitted, discover candidates with getUpdates.",
    )
    parser.add_argument(
        "--message",
        default=DEFAULT_MESSAGE,
        help="Exact plain-text test message. Defaults to a fixed Pulpo proof message.",
    )
    return parser.parse_args()


def _telegram_read(token: str, method: str) -> Any:
    """Call one read-only Bot API method without projecting token or user text."""

    if method not in {"getMe", "getUpdates"}:
        raise ValueError("unsupported Telegram discovery method")
    url = f"{TELEGRAM_API_ORIGIN}/bot{token}/{method}"
    request = urllib_request.Request(
        url,
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(request, timeout=TELEGRAM_TIMEOUT_SECONDS) as response:
            raw = response.read(_MAX_DISCOVERY_BYTES + 1)
    except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, OSError):
        raise TelegramProviderError("telegram local discovery request failed") from None
    if len(raw) > _MAX_DISCOVERY_BYTES:
        raise TelegramProviderError("telegram local discovery response exceeded limit")
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise TelegramProviderError("telegram local discovery response invalid") from None
    if not isinstance(decoded, dict) or decoded.get("ok") is not True:
        raise TelegramProviderError("telegram local discovery was rejected")
    return decoded.get("result")


def _discover_bot_id(token: str) -> int:
    result = _telegram_read(token, "getMe")
    if not isinstance(result, dict):
        raise TelegramProviderError("telegram getMe result missing")
    bot_id = result.get("id")
    if isinstance(bot_id, bool) or not isinstance(bot_id, int) or bot_id <= 0:
        raise TelegramProviderError("telegram getMe bot identity invalid")
    return bot_id


def _candidate_chats(token: str) -> list[tuple[int, str]]:
    """Return unique numeric chat IDs/types from pending updates, never text."""

    result = _telegram_read(token, "getUpdates")
    if not isinstance(result, list):
        raise TelegramProviderError("telegram getUpdates result invalid")
    candidates: dict[int, str] = {}
    for update in result:
        if not isinstance(update, dict):
            continue
        message_objects = []
        for key in ("message", "edited_message", "channel_post", "edited_channel_post"):
            value = update.get(key)
            if isinstance(value, dict):
                message_objects.append(value)
        callback = update.get("callback_query")
        if isinstance(callback, dict) and isinstance(callback.get("message"), dict):
            message_objects.append(callback["message"])
        for message in message_objects:
            chat = message.get("chat")
            if not isinstance(chat, dict):
                continue
            chat_id = chat.get("id")
            chat_type = chat.get("type")
            if isinstance(chat_id, bool) or not isinstance(chat_id, int) or chat_id == 0:
                continue
            candidates[chat_id] = chat_type if isinstance(chat_type, str) else "unknown"
    return sorted(candidates.items(), key=lambda item: item[0])


def _choose_discovered_chat(token: str) -> int:
    candidates = _candidate_chats(token)
    if not candidates:
        raise TelegramProviderError(
            "no pending numeric Telegram chats found; send /start to the test bot and rerun, "
            "or supply --chat-id locally"
        )
    print("\nCandidate chats from pending Telegram updates (message text is not displayed):")
    candidate_ids = {chat_id for chat_id, _ in candidates}
    for chat_id, chat_type in candidates:
        print(f"  {chat_id}  type={chat_type}")
    if len(candidates) == 1:
        only_id = candidates[0][0]
        typed = input(f"Use chat {only_id}? Type exactly '{only_id}' to confirm: ").strip()
        if typed != str(only_id):
            raise TelegramProviderError("local chat selection was not confirmed")
        return only_id
    while True:
        chosen = _prompt_int(
            "Choose one listed numeric private test chat ID: ",
            field="chat ID",
        )
        if chosen in candidate_ids:
            return chosen
        print("chat ID was not present in the displayed pending-update candidates", file=sys.stderr)


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

    token = getpass("Telegram TEST bot token (hidden; never paste it into chat): ").strip()
    if not token:
        print("no Telegram bot token supplied", file=sys.stderr)
        return 2

    try:
        bot_id = args.bot_id if args.bot_id is not None else _discover_bot_id(token)
        if args.bot_id is None:
            print(f"Discovered Telegram bot ID: {bot_id}")
        chat_id = args.chat_id if args.chat_id is not None else _choose_discovered_chat(token)

        try:
            message = TelegramOutboundMessage(chat_id, args.message)
        except ValueError as exc:
            print(f"message rejected before authority: {exc}", file=sys.stderr)
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
    except TelegramProviderError as exc:
        print(f"local Telegram discovery failed closed: {exc}", file=sys.stderr)
        return 2
    finally:
        # Remove the additional local reference as soon as discovery/custody
        # construction has completed. The transport, if constructed, retains the
        # token privately in process memory.
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

#!/usr/bin/env python3
"""Secret-safe one-shot live roundtrip for @PulpoGovernanceBot.

This script is intentionally a local operator ceremony, not a persistent bot
runtime. It reads one pending private ``/start`` update, projects it through the
capability-stripped Telegram ingress, and releases exactly one plain-text reply
through the existing Pulpo one-use permit gate and custody-side Telegram
transport.

The Telegram bot token is collected with ``getpass`` from the local TTY. It is
never accepted as a command-line argument, environment variable, repository
value, or printed evidence field.

A successful provider response is only a Telegram provider claim. It is not
independent observation or final reconciliation.
"""

from __future__ import annotations

from getpass import getpass
import json
from pathlib import Path
import secrets
import sys
import tempfile
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from pulpo import AgentGrant, GovernanceKernel, Policy, PulpoOrchestrator, SQLiteKernelState
from pulpo.mcp_boundary import freeze_mcp_snapshot
from pulpo.telegram import (
    GovernedTelegramSender,
    TELEGRAM_SEND_ACTION,
    TelegramOutboundMessage,
    TelegramSendRejected,
)
from pulpo.telegram_ingress import BOT_USERNAME, TelegramIngress, TelegramIngressError
from pulpo_custody_service.telegram_transport import (
    TELEGRAM_API_ORIGIN,
    TELEGRAM_TIMEOUT_SECONDS,
    TelegramBotApiTransport,
    TelegramProviderError,
    TelegramTransportConfigError,
)


PRINCIPAL = "agent:telegram-live-roundtrip-v0"
_MAX_DISCOVERY_BYTES = 1_000_000


def _telegram_read(token: str, method: str) -> Any:
    """Call one allowlisted read-only Bot API method with sanitized failures."""

    if method not in {"getMe", "getUpdates"}:
        raise ValueError("unsupported Telegram discovery method")
    payload: dict[str, object] = {}
    if method == "getUpdates":
        payload = {"timeout": 0, "allowed_updates": ["message"]}
    request = urllib_request.Request(
        f"{TELEGRAM_API_ORIGIN}/bot{token}/{method}",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
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
    username = result.get("username")
    is_bot = result.get("is_bot")
    if isinstance(bot_id, bool) or not isinstance(bot_id, int) or bot_id <= 0:
        raise TelegramProviderError("telegram getMe bot identity invalid")
    if is_bot is not True or username != BOT_USERNAME:
        raise TelegramProviderError("telegram getMe bot identity mismatch")
    return bot_id


def _pending_start_updates(token: str) -> list[dict[str, Any]]:
    """Return valid pending private /start updates without printing message text."""

    result = _telegram_read(token, "getUpdates")
    if not isinstance(result, list):
        raise TelegramProviderError("telegram getUpdates result invalid")
    candidates: list[dict[str, Any]] = []
    accepted = {"/start", f"/start@{BOT_USERNAME}"}
    for update in result:
        if not isinstance(update, dict):
            continue
        update_id = update.get("update_id")
        message = update.get("message")
        if isinstance(update_id, bool) or not isinstance(update_id, int) or update_id < 0:
            continue
        if not isinstance(message, dict):
            continue
        chat = message.get("chat")
        sender = message.get("from")
        text = message.get("text")
        if not isinstance(chat, dict) or not isinstance(sender, dict):
            continue
        chat_id = chat.get("id")
        sender_id = sender.get("id")
        chat_type = chat.get("type")
        if (
            isinstance(chat_id, bool)
            or not isinstance(chat_id, int)
            or chat_id <= 0
            or isinstance(sender_id, bool)
            or not isinstance(sender_id, int)
            or sender_id != chat_id
            or chat_type != "private"
            or text not in accepted
        ):
            continue
        candidates.append(update)
    return sorted(candidates, key=lambda item: item["update_id"])


def _candidate_summary(candidates: list[dict[str, Any]]) -> list[dict[str, int]]:
    """Project only numeric identifiers for local candidate selection."""

    summary: list[dict[str, int]] = []
    for update in candidates:
        message = update["message"]
        summary.append(
            {
                "update_id": update["update_id"],
                "chat_id": message["chat"]["id"],
            }
        )
    return summary


def _choose_start_update(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    if not candidates:
        raise TelegramProviderError(
            "no pending private /start update found; send /start to @PulpoGovernanceBot and rerun"
        )

    latest_by_chat: dict[int, dict[str, Any]] = {}
    for update in candidates:
        chat_id = update["message"]["chat"]["id"]
        latest_by_chat[chat_id] = update

    summary = _candidate_summary(list(latest_by_chat.values()))
    print("Pending private /start candidates (message text is not displayed):")
    for item in summary:
        print(f"  chat_id={item['chat_id']} update_id={item['update_id']}")

    if len(summary) == 1:
        chosen = summary[0]
        typed = input(
            f"Type exactly '{chosen['chat_id']}' to select this private chat: "
        ).strip()
        if typed != str(chosen["chat_id"]):
            raise TelegramProviderError("local Telegram chat selection was not confirmed")
        return latest_by_chat[chosen["chat_id"]]

    allowed = {item["chat_id"] for item in summary}
    while True:
        typed = input("Choose one listed numeric private chat ID: ").strip()
        try:
            chat_id = int(typed)
        except ValueError:
            print("chat ID must be numeric", file=sys.stderr)
            continue
        if chat_id in allowed:
            return latest_by_chat[chat_id]
        print("chat ID was not present in the displayed candidates", file=sys.stderr)


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
    token = getpass("Telegram bot token (hidden; do not paste it into chat): ").strip()
    if not token:
        print("no Telegram bot token supplied", file=sys.stderr)
        return 2

    transport = None
    try:
        bot_id = _discover_bot_id(token)
        candidates = _pending_start_updates(token)
        update = _choose_start_update(candidates)
        chat_id = update["message"]["chat"]["id"]
        transport = TelegramBotApiTransport(
            bot_token=token,
            expected_bot_id=bot_id,
            allowed_chat_id=chat_id,
        )
    except (TelegramProviderError, TelegramTransportConfigError) as exc:
        print(f"Telegram discovery/custody failed closed: {exc}", file=sys.stderr)
        return 2
    finally:
        # Drop the script-level reference immediately after the custody object is
        # constructed. The transport retains the token privately in process memory.
        token = ""

    assert transport is not None
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
    session_id = f"telegram-live-roundtrip:{secrets.token_hex(12)}"

    with tempfile.TemporaryDirectory(prefix="pulpo-telegram-roundtrip-v0-") as directory:
        state_path = Path(directory) / "kernel.sqlite3"
        state = SQLiteKernelState(state_path)
        try:
            kernel = GovernanceKernel(policy, secret=kernel_secret, state=state)
            snapshot = freeze_mcp_snapshot(PulpoOrchestrator(kernel))
            ingress = TelegramIngress(snapshot, allowed_chat_ids=frozenset({chat_id}))
            try:
                projection = ingress.handle_update(update)
            except TelegramIngressError as exc:
                print(f"Telegram ingress failed closed: {exc}", file=sys.stderr)
                return 3

            if (
                projection.get("outcome") != "read"
                or projection.get("command") != "start"
                or projection.get("reply_allowed") is not True
                or projection.get("authority_effect") != "none"
                or projection.get("canonical_state_mutation") is not False
            ):
                print("pending update did not project to the bounded /start response", file=sys.stderr)
                return 3

            response_text = projection.get("text")
            if not isinstance(response_text, str) or not response_text:
                print("bounded /start projection produced no reply text", file=sys.stderr)
                return 3

            message = TelegramOutboundMessage(chat_id, response_text)
            confirmation = f"SEND {message.message_hash[:12]}"
            print("\nFrozen Telegram roundtrip object:")
            print(f"  bot: @{BOT_USERNAME}")
            print(f"  bot_id: {bot_id}")
            print(f"  chat_id: {chat_id}")
            print(f"  source_update_id: {projection['source_update_id']}")
            print(f"  ingress_outcome: {projection['outcome']}")
            print(f"  ingress_authority_effect: {projection['authority_effect']}")
            print(f"  reply_message_hash: {message.message_hash}")
            print(f"  reply_text: {message.text}")
            print("  maximum provider transmissions authorized by this ceremony: 1")
            typed = input(f"Type exactly '{confirmation}' to release this one reply: ").strip()
            if typed != confirmation:
                print("local operator did not release the external effect; no provider call made")
                return 4

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
                return 5

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
                "schema": "pulpo.telegram-live-roundtrip.v0",
                "bot_username": f"@{BOT_USERNAME}",
                "source_update_id": projection["source_update_id"],
                "source_chat_id": chat_id,
                "ingress_outcome": projection["outcome"],
                "ingress_authority_effect": projection["authority_effect"],
                "ingress_canonical_state_mutation": projection["canonical_state_mutation"],
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
                "authority_scope": "local_operator_confirmed_single_low_risk_reply",
                "independent_observation": False,
            }
            print("\nSanitized Pulpo live roundtrip evidence:")
            print(json.dumps(evidence, indent=2, sort_keys=True))

            if replay_succeeded or not audit_valid:
                return 6
            if provider_status == "PROVIDER_CLAIM_RECEIVED":
                return 0
            return 7
        finally:
            try:
                state.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

"""Capability-stripped Telegram ingress for Pulpo.

Telegram is a communication surface, not an authority source. This module accepts
Telegram update documents and projects either bounded read responses or an
opaque request proposal. It retains only a frozen primitive Pulpo snapshot and a
frozen allowlist of private Telegram chat identifiers. It never receives a
kernel, orchestrator, authority client, executor, state backend, policy object,
clock, ledger, provider credential, or bot token.

The allowlist controls disclosure and request intake only. It does not create or
increase Pulpo authority.

`TELEGRAM_MESSAGE != AUTHORITY`
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .mcp_boundary import MCPReadSnapshot


BOT_USERNAME = "PulpoGovernanceBot"
AUTHORITY_COMMANDS = frozenset({"approve", "authorize", "grant", "permit"})


class TelegramIngressError(ValueError):
    """Raised when a Telegram update cannot cross the bounded ingress surface."""


@dataclass(frozen=True, slots=True)
class TelegramMessage:
    update_id: int
    chat_id: int
    sender_id: int
    text: str
    chat_type: str

    def __post_init__(self) -> None:
        if isinstance(self.update_id, bool) or not isinstance(self.update_id, int) or self.update_id < 0:
            raise TelegramIngressError("telegram_update_id_invalid")
        if self.chat_type != "private":
            raise TelegramIngressError("telegram_private_chat_required")
        if isinstance(self.chat_id, bool) or not isinstance(self.chat_id, int) or self.chat_id <= 0:
            raise TelegramIngressError("telegram_chat_id_invalid")
        if isinstance(self.sender_id, bool) or not isinstance(self.sender_id, int) or self.sender_id <= 0:
            raise TelegramIngressError("telegram_sender_id_invalid")
        if not isinstance(self.text, str) or not self.text or self.text != self.text.strip():
            raise TelegramIngressError("telegram_text_invalid")


def _parse_update(update: Mapping[str, Any]) -> TelegramMessage:
    if not isinstance(update, Mapping):
        raise TelegramIngressError("telegram_update_invalid")
    try:
        update_id = update["update_id"]
        message = update["message"]
        chat = message["chat"]
        sender = message["from"]
        text = message["text"]
        chat_id = chat["id"]
        chat_type = chat["type"]
        sender_id = sender["id"]
    except (KeyError, TypeError) as exc:
        raise TelegramIngressError("telegram_update_invalid") from exc
    return TelegramMessage(
        update_id=update_id,
        chat_id=chat_id,
        sender_id=sender_id,
        text=text,
        chat_type=chat_type,
    )


def _command(text: str) -> tuple[str | None, str]:
    if not text.startswith("/"):
        return None, text
    first, separator, remainder = text.partition(" ")
    token = first[1:]
    command, mention_separator, mention = token.partition("@")
    if not command:
        raise TelegramIngressError("telegram_command_invalid")
    if mention_separator and mention.lower() != BOT_USERNAME.lower():
        raise TelegramIngressError("telegram_bot_mention_mismatch")
    return command.lower(), remainder.strip() if separator else ""


def _request_id(message: TelegramMessage, request_text: str) -> str:
    canonical = json.dumps(
        {
            "chat_id": message.chat_id,
            "request_text": request_text,
            "sender_id": message.sender_id,
            "update_id": message.update_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class TelegramIngress:
    """Project allowlisted Telegram messages without canonical write capability."""

    __slots__ = ("_snapshot", "_allowed_chat_ids")

    def __init__(
        self,
        snapshot: MCPReadSnapshot,
        *,
        allowed_chat_ids: frozenset[int],
    ) -> None:
        if type(snapshot) is not MCPReadSnapshot:
            raise TypeError("MCPReadSnapshot required")
        if type(allowed_chat_ids) is not frozenset or not allowed_chat_ids:
            raise TelegramIngressError("telegram_allowed_chats_invalid")
        for chat_id in allowed_chat_ids:
            if isinstance(chat_id, bool) or not isinstance(chat_id, int) or chat_id <= 0:
                raise TelegramIngressError("telegram_allowed_chats_invalid")
        self._snapshot = snapshot
        self._allowed_chat_ids = allowed_chat_ids

    @staticmethod
    def _base(message: TelegramMessage, command: str | None) -> dict[str, Any]:
        return {
            "schema": "pulpo.telegram-response.v0",
            "source": "telegram",
            "bot_username": f"@{BOT_USERNAME}",
            "source_update_id": message.update_id,
            "source_chat_id": message.chat_id,
            "source_sender_id": message.sender_id,
            "command": command,
            "reply_allowed": True,
            "canonical_state_mutation": False,
            "governed_effect": "none",
            "authority_effect": "none",
        }

    @staticmethod
    def _ignored(message: TelegramMessage, reason: str) -> dict[str, Any]:
        response = TelegramIngress._base(message, None)
        response.update(
            outcome="ignored",
            reason=reason,
            reply_allowed=False,
        )
        return response

    def handle_update(self, update: Mapping[str, Any]) -> dict[str, Any]:
        """Handle one Telegram update without changing canonical Pulpo state."""

        message = _parse_update(update)

        # In a Telegram private chat the sender identity and chat identity are
        # expected to bind to the same user. Treat disagreement as an untrusted
        # projection rather than trying to infer identity.
        if message.sender_id != message.chat_id:
            return self._ignored(message, "telegram_sender_chat_mismatch")

        # This allowlist is a disclosure/request-intake boundary only. Matching
        # it never upgrades a Telegram message into approval or authority.
        if message.chat_id not in self._allowed_chat_ids:
            return self._ignored(message, "telegram_chat_not_allowlisted")

        command, argument = _command(message.text)
        response = self._base(message, command)

        if command in AUTHORITY_COMMANDS:
            response.update(
                outcome="denied",
                reason="telegram_not_authority_source",
                text="Denied: Telegram messages cannot create Pulpo authority, approvals, grants, or permits.",
            )
            return response

        if command is None:
            response.update(
                outcome="no_proposal",
                reason="telegram_command_required",
                text="Telegram text cannot create authority. Use /request to submit a non-authoritative proposal or /help for commands.",
            )
            return response

        if command == "request":
            if not argument:
                response.update(
                    outcome="no_proposal",
                    reason="telegram_request_empty",
                    text="Usage: /request <request text>. The resulting object is a proposal only and creates no authority.",
                )
                return response
            request_id = _request_id(message, argument)
            response.update(
                outcome="proposal",
                text=f"Request recorded as non-authoritative proposal {request_id[:12]}. Separate Pulpo governance is required before any consequence.",
                proposal={
                    "schema": "pulpo.telegram-request.v0",
                    "request_id": request_id,
                    "source": "telegram",
                    "bot_username": f"@{BOT_USERNAME}",
                    "source_update_id": message.update_id,
                    "source_chat_id": message.chat_id,
                    "source_sender_id": message.sender_id,
                    "request_text": argument,
                    "policy_hash": self._snapshot.policy_hash,
                    "freshness": "frozen",
                    "requires_governance": True,
                    "canonical_state_mutation": False,
                    "governed_effect": "none",
                    "authority_effect": "none",
                },
            )
            return response

        if command == "status":
            response.update(
                outcome="read",
                text=(
                    "Pulpo governance interface: bounded Telegram ingress active. "
                    f"Frozen audit_valid={self._snapshot.audit_valid}; audit_records={self._snapshot.audit_records}. "
                    "Telegram is not an authority source."
                ),
            )
            return response

        if command == "evidence":
            response.update(
                outcome="read",
                text="Returning bounded frozen evidence metadata; this response cannot authorize execution.",
                evidence={
                    "schema": "pulpo.telegram-evidence.v0",
                    "source_schema": self._snapshot.source_schema,
                    "policy_hash": self._snapshot.policy_hash,
                    "audit_valid": self._snapshot.audit_valid,
                    "audit_records": self._snapshot.audit_records,
                    "audit_tip": self._snapshot.audit_tip,
                    "freshness": "frozen",
                    "canonical_state_mutation": False,
                    "governed_effect": "none",
                    "authority_effect": "none",
                },
            )
            return response

        if command in {"start", "help"}:
            response.update(
                outcome="read",
                text=(
                    "Pulpo Governance commands: /start, /status, /request, /evidence, /help. "
                    "Messages may propose or read bounded evidence; they cannot create authority or permits."
                ),
            )
            return response

        response.update(
            outcome="no_proposal",
            reason="telegram_command_unknown",
            text="Unknown command. Use /help. No authority or canonical state was changed.",
        )
        return response


def snapshot_from_document(document: Mapping[str, Any]) -> MCPReadSnapshot:
    """Reconstruct the capability-free frozen snapshot used by this ingress."""

    if not isinstance(document, Mapping):
        raise TelegramIngressError("telegram_snapshot_invalid")
    try:
        snapshot = MCPReadSnapshot(**dict(document))
    except (TypeError, ValueError) as exc:
        raise TelegramIngressError("telegram_snapshot_invalid") from exc
    return snapshot


def proposal_json(response: Mapping[str, Any]) -> str:
    """Serialize a proposal response for an explicitly chosen trusted handoff."""

    if not isinstance(response, Mapping) or response.get("outcome") != "proposal":
        raise TelegramIngressError("telegram_proposal_response_required")
    proposal = response.get("proposal")
    if not isinstance(proposal, Mapping):
        raise TelegramIngressError("telegram_proposal_response_required")
    return json.dumps(dict(proposal), sort_keys=True, separators=(",", ":"))

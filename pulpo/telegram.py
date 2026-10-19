"""Exact Telegram sendMessage projection for the external capability proof.

This module holds no Telegram bot token and performs no network I/O. It only
freezes the exact outbound consequence object and delegates authorization to the
canonical GovernanceKernel.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol

from .kernel import Decision, GovernanceKernel, Intent


TELEGRAM_ACTIVATE_ACTION = "activate_capability"
TELEGRAM_SEND_ACTION = "telegram_send_message"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _normalize_chat_id(chat_id: int | str) -> int | str:
    if isinstance(chat_id, bool):
        raise ValueError("telegram chat_id must not be boolean")
    if isinstance(chat_id, int):
        return chat_id
    if not isinstance(chat_id, str):
        raise ValueError("telegram chat_id must be an integer or string")
    value = chat_id.strip()
    if not value:
        raise ValueError("telegram chat_id must be non-empty")
    if value.startswith("@"):
        if len(value) < 2:
            raise ValueError("telegram username chat_id is invalid")
        return value
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError("telegram string chat_id must be numeric or start with @") from exc


def _normalize_bot_id(bot_id: int) -> int:
    if isinstance(bot_id, bool) or not isinstance(bot_id, int) or bot_id <= 0:
        raise ValueError("telegram bot_id must be a positive integer")
    return bot_id


@dataclass(frozen=True)
class TelegramOutboundMessage:
    """Exact outbound Telegram consequence object for plain sendMessage v0."""

    bot_id: int
    chat_id: int | str
    text: str
    schema: str = "pulpo.telegram-send-message.v0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "bot_id", _normalize_bot_id(self.bot_id))
        object.__setattr__(self, "chat_id", _normalize_chat_id(self.chat_id))
        if self.schema != "pulpo.telegram-send-message.v0":
            raise ValueError("unsupported telegram message schema")
        if not isinstance(self.text, str) or not self.text:
            raise ValueError("telegram text must be non-empty")
        if len(self.text) > 4_096:
            raise ValueError("telegram text exceeds sendMessage v0 limit")

    @property
    def message_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()

    @property
    def activation_resource(self) -> str:
        return f"telegram:bot:{self.bot_id}:chat:{self.chat_id}:capability:sendMessage"

    @property
    def resource(self) -> str:
        return (
            f"telegram:bot:{self.bot_id}:chat:{self.chat_id}:"
            f"sendMessage:sha256:{self.message_hash}"
        )

    def activation_intent(self, *, principal: str, session_id: str) -> Intent:
        return Intent(
            principal=principal,
            action=TELEGRAM_ACTIVATE_ACTION,
            resource=self.activation_resource,
            cost=0,
            session_id=session_id,
        )

    def intent(self, *, principal: str, session_id: str) -> Intent:
        return Intent(
            principal=principal,
            action=TELEGRAM_SEND_ACTION,
            resource=self.resource,
            cost=0,
            session_id=session_id,
        )


class TelegramTransport(Protocol):
    expected_bot_id: int
    allowed_chat_id: int

    def send_message(self, message: TelegramOutboundMessage) -> Mapping[str, object]: ...


class TelegramSendRejected(RuntimeError):
    pass


class GovernedTelegramSender:
    """Execution gate that consumes exact activation and message permits."""

    def __init__(self, kernel: GovernanceKernel, transport: TelegramTransport) -> None:
        self._kernel = kernel
        self._transport = transport

    def evaluate_activation(
        self,
        message: TelegramOutboundMessage,
        *,
        principal: str,
        session_id: str,
    ) -> Decision:
        return self._kernel.evaluate(
            message.activation_intent(principal=principal, session_id=session_id)
        )

    def evaluate(self, message: TelegramOutboundMessage, *, principal: str, session_id: str) -> Decision:
        return self._kernel.evaluate(message.intent(principal=principal, session_id=session_id))

    def _validate_transport_scope(self, message: TelegramOutboundMessage) -> None:
        if getattr(self._transport, "expected_bot_id", None) != message.bot_id:
            raise TelegramSendRejected("telegram transport bot identity mismatch")
        if getattr(self._transport, "allowed_chat_id", None) != message.chat_id:
            raise TelegramSendRejected("telegram transport destination mismatch")

    def execute(
        self,
        message: TelegramOutboundMessage,
        *,
        activation_permit: str,
        message_permit: str,
        principal: str,
        session_id: str,
    ) -> Mapping[str, object]:
        self._validate_transport_scope(message)
        activation_intent = message.activation_intent(
            principal=principal,
            session_id=session_id,
        )
        message_intent = message.intent(principal=principal, session_id=session_id)
        if not isinstance(activation_permit, str) or not activation_permit:
            raise TelegramSendRejected("telegram activation permit missing")
        if not self._kernel.consume(activation_permit, activation_intent):
            raise TelegramSendRejected("telegram activation permit rejected")
        if not isinstance(message_permit, str) or not message_permit:
            raise TelegramSendRejected("telegram message permit missing")
        if not self._kernel.consume(message_permit, message_intent):
            raise TelegramSendRejected("telegram message permit rejected")
        return self._transport.send_message(message)

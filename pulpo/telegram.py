"""Telegram transport projection for the canonical Pulpo governance kernel.

This module intentionally holds no Telegram bot token and performs no network
I/O. Intelligence may construct an outbound message proposal, but the proposal
becomes consequence-capable only when the existing GovernanceKernel issues and
successfully consumes a permit bound to the exact chat and message bytes.

A real Telegram transport must live on the execution/custody side of the trust
boundary and must not be exposed to the intelligence process.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol

from .kernel import Decision, GovernanceKernel, Intent


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


@dataclass(frozen=True)
class TelegramOutboundMessage:
    """Exact outbound Telegram sendMessage consequence object.

    V0 deliberately supports only ``chat_id`` and plain ``text``. Parse modes,
    keyboards, reply parameters, media, payments, moderation, and administrative
    actions remain outside this proof until they receive their own exact-object
    projection and policy treatment.
    """

    chat_id: int | str
    text: str
    schema: str = "pulpo.telegram-send-message.v0"

    def __post_init__(self) -> None:
        normalized = _normalize_chat_id(self.chat_id)
        object.__setattr__(self, "chat_id", normalized)
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
    def resource(self) -> str:
        return f"telegram:sendMessage:{self.chat_id}:{self.message_hash}"

    def intent(self, *, principal: str, session_id: str) -> Intent:
        return Intent(
            principal=principal,
            action=TELEGRAM_SEND_ACTION,
            resource=self.resource,
            cost=0,
            session_id=session_id,
        )


class TelegramTransport(Protocol):
    """Execution-side capability. The implementation may possess the bot token."""

    def send_message(self, message: TelegramOutboundMessage) -> Mapping[str, object]: ...


class TelegramSendRejected(RuntimeError):
    """Raised before transport invocation when the exact permit cannot be consumed."""


class GovernedTelegramSender:
    """Thin execution gate over the existing Pulpo kernel.

    This is not a second router or policy engine. ``evaluate`` delegates to the
    canonical GovernanceKernel. ``execute`` recomputes the exact intent and
    invokes the transport only after one-use permit consumption succeeds.
    """

    def __init__(self, kernel: GovernanceKernel, transport: TelegramTransport) -> None:
        self._kernel = kernel
        self._transport = transport

    def evaluate(self, message: TelegramOutboundMessage, *, principal: str, session_id: str) -> Decision:
        return self._kernel.evaluate(message.intent(principal=principal, session_id=session_id))

    def execute(
        self,
        message: TelegramOutboundMessage,
        *,
        permit: str,
        principal: str,
        session_id: str,
    ) -> Mapping[str, object]:
        intent = message.intent(principal=principal, session_id=session_id)
        if not isinstance(permit, str) or not permit:
            raise TelegramSendRejected("telegram permit missing")
        if not self._kernel.consume(permit, intent):
            raise TelegramSendRejected("telegram permit rejected")
        return self._transport.send_message(message)

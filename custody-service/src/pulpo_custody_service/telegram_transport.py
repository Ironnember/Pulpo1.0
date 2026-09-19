"""Custody-only Telegram Bot API transport for the external capability proof.

The bot token remains execution-side. Provider responses are provider claims,
not independent reconciliation evidence.
"""

from __future__ import annotations

import json
import os
from typing import Mapping
from urllib import error as urllib_error
from urllib import request as urllib_request

from pulpo.telegram import TelegramOutboundMessage
from pulpo.transport_contract import TransportPolicy, require_https_origin, require_response_size


TELEGRAM_API_ORIGIN = "https://api.telegram.org"
TELEGRAM_TIMEOUT_SECONDS = 5
_TRANSPORT_POLICY = TransportPolicy(read_timeout_seconds=TELEGRAM_TIMEOUT_SECONDS)
_MAX_RESPONSE_BYTES = _TRANSPORT_POLICY.max_response_bytes


class TelegramTransportConfigError(RuntimeError):
    pass


class TelegramProviderError(RuntimeError):
    pass


class TelegramExternalRealityUnknown(TelegramProviderError):
    """A transmission may have occurred and must not be retried automatically."""

    classification = "EXTERNAL_REALITY_UNKNOWN"
    reconciliation_required = True

    def __init__(self, message_hash: str) -> None:
        super().__init__(self.classification)
        self.message_hash = message_hash


def _required(name: str, environ: Mapping[str, str]) -> str:
    value = environ.get(name, "")
    if not value:
        raise TelegramTransportConfigError(f"missing required environment variable: {name}")
    return value


def _positive_int(name: str, environ: Mapping[str, str]) -> int:
    raw = _required(name, environ)
    try:
        value = int(raw)
    except ValueError as exc:
        raise TelegramTransportConfigError(f"{name} must be an integer") from exc
    if value <= 0:
        raise TelegramTransportConfigError(f"{name} must be positive")
    return value


def _chat_id(name: str, environ: Mapping[str, str]) -> int:
    raw = _required(name, environ)
    try:
        value = int(raw)
    except ValueError as exc:
        raise TelegramTransportConfigError(f"{name} must be a numeric chat ID") from exc
    if value == 0:
        raise TelegramTransportConfigError(f"{name} must not be zero")
    return value


def _token_bot_id(token: str) -> int:
    prefix, separator, secret = token.partition(":")
    if not separator or not prefix.isdigit() or not secret or any(character.isspace() for character in token):
        raise TelegramTransportConfigError("PULPO_TELEGRAM_BOT_TOKEN has invalid structure")
    value = int(prefix)
    if value <= 0:
        raise TelegramTransportConfigError("PULPO_TELEGRAM_BOT_TOKEN has invalid bot identity")
    return value


class TelegramBotApiTransport:
    """One pinned bot identity, one numeric destination, plain sendMessage only."""

    def __init__(self, *, bot_token: str, expected_bot_id: int, allowed_chat_id: int) -> None:
        if not isinstance(bot_token, str) or not bot_token:
            raise TelegramTransportConfigError("Telegram bot token is required")
        if isinstance(expected_bot_id, bool) or not isinstance(expected_bot_id, int) or expected_bot_id <= 0:
            raise TelegramTransportConfigError("expected Telegram bot ID must be positive")
        if isinstance(allowed_chat_id, bool) or not isinstance(allowed_chat_id, int) or allowed_chat_id == 0:
            raise TelegramTransportConfigError("allowed Telegram chat ID must be a non-zero integer")
        if _token_bot_id(bot_token) != expected_bot_id:
            raise TelegramTransportConfigError("Telegram bot token identity does not match pinned bot ID")
        self._bot_token = bot_token
        self.expected_bot_id = expected_bot_id
        self.allowed_chat_id = allowed_chat_id

    def __repr__(self) -> str:
        return (
            "TelegramBotApiTransport("
            f"expected_bot_id={self.expected_bot_id!r}, "
            f"allowed_chat_id={self.allowed_chat_id!r}, bot_token=<redacted>)"
        )

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> "TelegramBotApiTransport":
        env = dict(os.environ if environ is None else environ)
        return cls(
            bot_token=_required("PULPO_TELEGRAM_BOT_TOKEN", env),
            expected_bot_id=_positive_int("PULPO_TELEGRAM_EXPECTED_BOT_ID", env),
            allowed_chat_id=_chat_id("PULPO_TELEGRAM_ALLOWED_CHAT_ID", env),
        )

    def send_message(self, message: TelegramOutboundMessage) -> Mapping[str, object]:
        if not isinstance(message, TelegramOutboundMessage):
            raise TelegramProviderError("telegram message object invalid")
        if message.bot_id != self.expected_bot_id:
            raise TelegramProviderError("telegram bot identity is outside custody scope")
        if not isinstance(message.chat_id, int) or isinstance(message.chat_id, bool):
            raise TelegramProviderError("telegram custody v0 requires a numeric chat ID")
        if message.chat_id != self.allowed_chat_id:
            raise TelegramProviderError("telegram destination is outside custody scope")

        payload = json.dumps(
            {"chat_id": message.chat_id, "text": message.text},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        origin = require_https_origin(
            TELEGRAM_API_ORIGIN,
            allowed=frozenset({TELEGRAM_API_ORIGIN}),
        )
        request = urllib_request.Request(
            f"{origin}/bot{self._bot_token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=TELEGRAM_TIMEOUT_SECONDS) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, OSError):
            raise TelegramExternalRealityUnknown(message.message_hash) from None

        try:
            require_response_size(len(raw), policy=_TRANSPORT_POLICY)
        except ValueError:
            raise TelegramExternalRealityUnknown(message.message_hash)
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            raise TelegramExternalRealityUnknown(message.message_hash) from None
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise TelegramProviderError("telegram provider rejected request")
        result = decoded.get("result")
        if not isinstance(result, dict):
            raise TelegramExternalRealityUnknown(message.message_hash)
        chat = result.get("chat")
        if not isinstance(chat, dict) or chat.get("id") != self.allowed_chat_id:
            raise TelegramExternalRealityUnknown(message.message_hash)
        message_id = result.get("message_id")
        provider_date = result.get("date")
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
            raise TelegramExternalRealityUnknown(message.message_hash)
        if isinstance(provider_date, bool) or not isinstance(provider_date, int) or provider_date <= 0:
            raise TelegramExternalRealityUnknown(message.message_hash)
        return {
            "provider": "telegram_bot_api",
            "method": "sendMessage",
            "provider_message_id": message_id,
            "provider_chat_id": self.allowed_chat_id,
            "provider_date": provider_date,
            "message_hash": message.message_hash,
            "claim_class": "provider_claim",
        }

"""Minimal Telegram transport for the capability-free Pulpo operations bot."""

from __future__ import annotations

import json
import os
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .ops_bot import OpsBot


MAX_UPDATE_BYTES = 1_048_576


def _telegram_call(token: str, method: str, payload: dict[str, object]) -> dict[str, object]:
    data = urlencode(payload).encode()
    request = Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urlopen(request, timeout=35) as response:
        raw = response.read(MAX_UPDATE_BYTES + 1)
    if len(raw) > MAX_UPDATE_BYTES:
        raise RuntimeError("telegram response exceeded size limit")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError("telegram request failed closed")
    return value


def _allowed_chat_ids() -> frozenset[int]:
    raw = os.environ.get("PULPO_TELEGRAM_ALLOWED_CHAT_IDS", "")
    values = frozenset(int(item.strip()) for item in raw.split(",") if item.strip())
    if not values:
        raise RuntimeError("PULPO_TELEGRAM_ALLOWED_CHAT_IDS is required")
    return values


def main() -> None:
    token = os.environ.get("PULPO_TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("PULPO_TELEGRAM_BOT_TOKEN is required")
    allowed = _allowed_chat_ids()
    bot = OpsBot()
    offset = 0

    while True:
        result = _telegram_call(token, "getUpdates", {"timeout": 25, "offset": offset})
        updates = result.get("result")
        if not isinstance(updates, list):
            raise RuntimeError("telegram returned malformed updates")
        for update in updates:
            if not isinstance(update, dict) or not isinstance(update.get("update_id"), int):
                continue
            offset = max(offset, update["update_id"] + 1)
            message = update.get("message")
            if not isinstance(message, dict):
                continue
            chat = message.get("chat")
            chat_id = chat.get("id") if isinstance(chat, dict) else None
            text = message.get("text")
            if not isinstance(chat_id, int) or chat_id not in allowed or not isinstance(text, str):
                continue
            try:
                reply = bot.handle_message(text, session_id=f"telegram:{chat_id}")
                response_text = reply.text
            except Exception as exc:
                response_text = f"denied: {type(exc).__name__}: {exc}"
            _telegram_call(token, "sendMessage", {"chat_id": chat_id, "text": response_text})
        if not updates:
            time.sleep(1)


if __name__ == "__main__":
    main()

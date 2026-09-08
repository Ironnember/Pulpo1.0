import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib import error as urllib_error

from pulpo_custody_service.telegram_transport import TelegramProviderError


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "telegram_live_handoff_v0.py"
SPEC = importlib.util.spec_from_file_location("telegram_live_handoff_v0", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


class TelegramLiveHandoffDiscoveryTests(unittest.TestCase):
    def test_get_me_discovers_numeric_bot_id(self) -> None:
        token = "123456:TEST_TOKEN_NOT_REAL"
        payload = b'{"ok":true,"result":{"id":123456,"is_bot":true,"first_name":"Test"}}'
        with patch.object(handoff.urllib_request, "urlopen", return_value=FakeResponse(payload)) as urlopen:
            self.assertEqual(123456, handoff._discover_bot_id(token))
        request = urlopen.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://api.telegram.org/bot"))
        self.assertTrue(request.full_url.endswith("/getMe"))

    def test_candidate_chat_discovery_never_prints_or_returns_message_text(self) -> None:
        updates = [
            {
                "update_id": 1,
                "message": {
                    "text": "PRIVATE MESSAGE MUST NOT BE PRINTED",
                    "chat": {"id": 42, "type": "private"},
                },
            },
            {
                "update_id": 2,
                "channel_post": {
                    "caption": "PRIVATE CAPTION MUST NOT BE PRINTED",
                    "chat": {"id": -10099, "type": "channel"},
                },
            },
        ]
        output = io.StringIO()
        with patch.object(handoff, "_telegram_read", return_value=updates):
            with contextlib.redirect_stdout(output):
                candidates = handoff._candidate_chats("123456:TEST_TOKEN_NOT_REAL")
        self.assertEqual([(-10099, "channel"), (42, "private")], candidates)
        self.assertEqual("", output.getvalue())
        rendered = repr(candidates)
        self.assertNotIn("PRIVATE MESSAGE", rendered)
        self.assertNotIn("PRIVATE CAPTION", rendered)

    def test_discovery_network_error_is_sanitized_without_token(self) -> None:
        token = "123456:TEST_TOKEN_NOT_REAL"
        with patch.object(
            handoff.urllib_request,
            "urlopen",
            side_effect=urllib_error.URLError(f"sensitive {token}"),
        ):
            with self.assertRaises(TelegramProviderError) as raised:
                handoff._telegram_read(token, "getUpdates")
        self.assertEqual("telegram local discovery request failed", str(raised.exception))
        self.assertNotIn(token, str(raised.exception))

    def test_discovery_method_is_allowlisted(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported Telegram discovery method"):
            handoff._telegram_read("123456:TEST_TOKEN_NOT_REAL", "deleteWebhook")


if __name__ == "__main__":
    unittest.main()

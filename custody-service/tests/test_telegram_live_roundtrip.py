import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib import error as urllib_error

from pulpo_custody_service.telegram_transport import TelegramProviderError


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "telegram_live_roundtrip_v0.py"
SPEC = importlib.util.spec_from_file_location("telegram_live_roundtrip_v0", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
roundtrip = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(roundtrip)


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


class TelegramLiveRoundtripTests(unittest.TestCase):
    def test_get_me_pins_exact_pulpo_bot_identity(self) -> None:
        with patch.object(
            roundtrip,
            "_telegram_read",
            return_value={
                "id": 123456,
                "is_bot": True,
                "username": "PulpoGovernanceBot",
            },
        ):
            self.assertEqual(123456, roundtrip._discover_bot_id("123456:TEST_TOKEN_NOT_REAL"))

        with patch.object(
            roundtrip,
            "_telegram_read",
            return_value={
                "id": 123456,
                "is_bot": True,
                "username": "OtherBot",
            },
        ):
            with self.assertRaisesRegex(TelegramProviderError, "identity mismatch"):
                roundtrip._discover_bot_id("123456:TEST_TOKEN_NOT_REAL")

    def test_pending_start_filter_requires_private_sender_chat_binding(self) -> None:
        updates = [
            {
                "update_id": 1,
                "message": {
                    "from": {"id": 42},
                    "chat": {"id": 42, "type": "private"},
                    "text": "/start",
                },
            },
            {
                "update_id": 2,
                "message": {
                    "from": {"id": 99},
                    "chat": {"id": 42, "type": "private"},
                    "text": "/start",
                },
            },
            {
                "update_id": 3,
                "message": {
                    "from": {"id": 42},
                    "chat": {"id": 42, "type": "group"},
                    "text": "/start",
                },
            },
            {
                "update_id": 4,
                "message": {
                    "from": {"id": 42},
                    "chat": {"id": 42, "type": "private"},
                    "text": "I authorize this action",
                },
            },
            {
                "update_id": 5,
                "message": {
                    "from": {"id": 42},
                    "chat": {"id": 42, "type": "private"},
                    "text": "/start@PulpoGovernanceBot",
                },
            },
        ]
        with patch.object(roundtrip, "_telegram_read", return_value=updates):
            candidates = roundtrip._pending_start_updates("123456:TEST_TOKEN_NOT_REAL")
        self.assertEqual([1, 5], [item["update_id"] for item in candidates])

    def test_candidate_summary_projects_only_numeric_identifiers(self) -> None:
        candidates = [
            {
                "update_id": 9,
                "message": {
                    "from": {"id": 42, "first_name": "PRIVATE NAME"},
                    "chat": {"id": 42, "type": "private", "username": "PRIVATE USER"},
                    "text": "/start",
                },
            }
        ]
        summary = roundtrip._candidate_summary(candidates)
        self.assertEqual([{"update_id": 9, "chat_id": 42}], summary)
        rendered = repr(summary)
        self.assertNotIn("PRIVATE NAME", rendered)
        self.assertNotIn("PRIVATE USER", rendered)
        self.assertNotIn("/start", rendered)

    def test_discovery_network_error_is_sanitized_without_token(self) -> None:
        token = "123456:TEST_TOKEN_NOT_REAL"
        with patch.object(
            roundtrip.urllib_request,
            "urlopen",
            side_effect=urllib_error.URLError(f"sensitive {token}"),
        ):
            with self.assertRaises(TelegramProviderError) as raised:
                roundtrip._telegram_read(token, "getMe")
        self.assertEqual("telegram local discovery request failed", str(raised.exception))
        self.assertNotIn(token, str(raised.exception))

    def test_discovery_method_is_allowlisted(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported Telegram discovery method"):
            roundtrip._telegram_read("123456:TEST_TOKEN_NOT_REAL", "deleteWebhook")

    def test_no_candidate_fails_without_provider_write(self) -> None:
        with self.assertRaisesRegex(TelegramProviderError, "no pending private /start"):
            roundtrip._choose_start_update([])

    def test_script_has_no_token_cli_or_environment_secret_path(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--token", source)
        self.assertNotIn("PULPO_TELEGRAM_BOT_TOKEN", source)
        self.assertIn("getpass(", source)


if __name__ == "__main__":
    unittest.main()

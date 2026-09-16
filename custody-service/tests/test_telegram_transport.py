import json
import unittest
from unittest.mock import patch
from urllib import error as urllib_error

from pulpo.telegram import TelegramOutboundMessage
from pulpo_custody_service.telegram_transport import (
    TELEGRAM_API_ORIGIN,
    TELEGRAM_TIMEOUT_SECONDS,
    TelegramBotApiTransport,
    TelegramExternalRealityUnknown,
    TelegramProviderError,
    TelegramTransportConfigError,
)


FAKE_TOKEN = "123456:TEST_TOKEN_NOT_REAL"


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


def provider_response(*, chat_id: int = 123, message_id: int = 77, date: int = 1_788_000_000) -> bytes:
    return json.dumps({"ok": True, "result": {"message_id": message_id, "date": date, "chat": {"id": chat_id, "type": "private"}, "text": "provider echo"}}).encode()


class TelegramBotApiTransportTests(unittest.TestCase):
    def transport(self) -> TelegramBotApiTransport:
        return TelegramBotApiTransport(bot_token=FAKE_TOKEN, expected_bot_id=123456, allowed_chat_id=123)

    def test_environment_requires_token_bot_identity_and_numeric_chat(self) -> None:
        with self.assertRaisesRegex(TelegramTransportConfigError, "PULPO_TELEGRAM_BOT_TOKEN"):
            TelegramBotApiTransport.from_environ({})
        with self.assertRaisesRegex(TelegramTransportConfigError, "numeric chat ID"):
            TelegramBotApiTransport.from_environ({"PULPO_TELEGRAM_BOT_TOKEN": FAKE_TOKEN, "PULPO_TELEGRAM_EXPECTED_BOT_ID": "123456", "PULPO_TELEGRAM_ALLOWED_CHAT_ID": "@public-channel"})

    def test_token_identity_is_pinned_and_repr_is_redacted(self) -> None:
        with self.assertRaisesRegex(TelegramTransportConfigError, "does not match"):
            TelegramBotApiTransport(bot_token=FAKE_TOKEN, expected_bot_id=999999, allowed_chat_id=123)
        rendered = repr(self.transport())
        self.assertNotIn(FAKE_TOKEN, rendered)
        self.assertIn("<redacted>", rendered)

    def test_out_of_scope_chat_is_rejected_before_network(self) -> None:
        with patch("pulpo_custody_service.telegram_transport.urllib_request.urlopen", side_effect=AssertionError("network must not be called")):
            with self.assertRaisesRegex(TelegramProviderError, "outside custody scope"):
                self.transport().send_message(
                    TelegramOutboundMessage(123456, 999, "do not send")
                )

    def test_out_of_scope_bot_is_rejected_before_network(self) -> None:
        with patch(
            "pulpo_custody_service.telegram_transport.urllib_request.urlopen",
            side_effect=AssertionError("network must not be called"),
        ):
            with self.assertRaisesRegex(TelegramProviderError, "bot identity"):
                self.transport().send_message(
                    TelegramOutboundMessage(999999, 123, "do not send")
                )

    def test_send_message_shape_uses_official_https_endpoint_and_minimized_claim(self) -> None:
        captured = {}
        message = TelegramOutboundMessage(123456, 123, "governed hello")

        def fake_urlopen(request, *, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(provider_response())

        with patch("pulpo_custody_service.telegram_transport.urllib_request.urlopen", side_effect=fake_urlopen):
            claim = self.transport().send_message(message)

        request = captured["request"]
        self.assertEqual("POST", request.get_method())
        self.assertEqual(f"{TELEGRAM_API_ORIGIN}/bot{FAKE_TOKEN}/sendMessage", request.full_url)
        self.assertEqual(TELEGRAM_TIMEOUT_SECONDS, captured["timeout"])
        self.assertEqual({"chat_id": 123, "text": "governed hello"}, json.loads(request.data))
        self.assertEqual("provider_claim", claim["claim_class"])
        self.assertEqual(message.message_hash, claim["message_hash"])
        self.assertNotIn(FAKE_TOKEN, repr(claim))
        self.assertNotIn(message.text, repr(claim))

    def test_network_ambiguity_is_unknown_sanitized_and_not_retried(self) -> None:
        message = TelegramOutboundMessage(123456, 123, "governed hello")
        with patch(
            "pulpo_custody_service.telegram_transport.urllib_request.urlopen",
            side_effect=urllib_error.URLError(f"sensitive {FAKE_TOKEN}"),
        ) as urlopen:
            with self.assertRaises(TelegramExternalRealityUnknown) as raised:
                self.transport().send_message(message)
        self.assertEqual("EXTERNAL_REALITY_UNKNOWN", str(raised.exception))
        self.assertEqual(message.message_hash, raised.exception.message_hash)
        self.assertTrue(raised.exception.reconciliation_required)
        self.assertEqual(1, urlopen.call_count)
        self.assertNotIn(FAKE_TOKEN, str(raised.exception))

    def test_provider_denial_is_explicit_and_destination_mismatch_is_unknown(self) -> None:
        message = TelegramOutboundMessage(123456, 123, "governed hello")
        with patch("pulpo_custody_service.telegram_transport.urllib_request.urlopen", return_value=FakeResponse(b'{"ok":false,"description":"denied"}')):
            with self.assertRaisesRegex(TelegramProviderError, "provider rejected"):
                self.transport().send_message(message)
        with patch("pulpo_custody_service.telegram_transport.urllib_request.urlopen", return_value=FakeResponse(provider_response(chat_id=999))):
            with self.assertRaises(TelegramExternalRealityUnknown):
                self.transport().send_message(message)

    def test_malformed_success_response_is_external_reality_unknown(self) -> None:
        message = TelegramOutboundMessage(123456, 123, "governed hello")
        for payload in (
            b"not-json",
            b'{"ok":true}',
            provider_response(message_id=0),
            provider_response(date=0),
        ):
            with self.subTest(payload=payload):
                with patch(
                    "pulpo_custody_service.telegram_transport.urllib_request.urlopen",
                    return_value=FakeResponse(payload),
                ):
                    with self.assertRaises(TelegramExternalRealityUnknown):
                        self.transport().send_message(message)


if __name__ == "__main__":
    unittest.main()

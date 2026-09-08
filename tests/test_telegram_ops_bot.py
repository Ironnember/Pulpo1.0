import os
import unittest
from unittest.mock import patch

from pulpo.telegram_ops_bot import _allowed_chat_ids


class TelegramTransportTests(unittest.TestCase):
    def test_chat_allowlist_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                _allowed_chat_ids()

    def test_chat_allowlist_parses_exact_ids(self):
        with patch.dict(os.environ, {"PULPO_TELEGRAM_ALLOWED_CHAT_IDS": "123, 456"}, clear=True):
            self.assertEqual(_allowed_chat_ids(), frozenset({123, 456}))


if __name__ == "__main__":
    unittest.main()

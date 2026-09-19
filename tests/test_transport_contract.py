import unittest

from pulpo.transport_contract import (
    TransportPolicy,
    TransportPolicyError,
    require_https_origin,
    require_response_size,
    redact_secret,
)


class TransportContractTests(unittest.TestCase):
    def test_only_pinned_https_origin_is_accepted(self):
        allowed = frozenset({"https://api.example"})
        self.assertEqual("https://api.example", require_https_origin("https://api.example", allowed=allowed))
        for origin in ("http://api.example", "https://attacker.example", "https://api.example/path"):
            with self.assertRaises(TransportPolicyError):
                require_https_origin(origin, allowed=allowed)

    def test_bounds_and_redaction_are_explicit(self):
        self.assertEqual(5.0, TransportPolicy().read_timeout_seconds)
        self.assertEqual("<redacted>", redact_secret("secret"))
        require_response_size(1, policy=TransportPolicy())
        with self.assertRaises(TransportPolicyError):
            require_response_size(1_000_001, policy=TransportPolicy())
        with self.assertRaises(ValueError):
            TransportPolicy(max_response_bytes=0)


if __name__ == "__main__":
    unittest.main()

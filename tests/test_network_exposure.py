import json
import unittest

from pulpo.network_exposure import (
    Listener,
    NetworkExposureError,
    evaluate_listeners,
    parse_allowlist,
    parse_linux_ss,
    parse_windows_json,
)


class NetworkExposureTests(unittest.TestCase):
    def test_empty_allowlist_rejects_every_listener(self):
        report = evaluate_listeners(
            [
                Listener("tcp", "127.0.0.1", 8080),
                Listener("tcp", "0.0.0.0", 9000),
            ],
            allowed=(),
            system="linux",
        )
        self.assertFalse(report.passed)
        self.assertEqual(2, len(report.unexpected))

    def test_exact_loopback_allowlist_allows_only_exact_listener(self):
        report = evaluate_listeners(
            [
                Listener("tcp", "127.0.0.1", 8080),
                Listener("tcp", "127.0.0.1", 8081),
            ],
            allowed=[Listener("tcp", "127.0.0.1", 8080)],
            system="linux",
        )
        self.assertFalse(report.passed)
        self.assertEqual((Listener("tcp", "127.0.0.1", 8081),), report.unexpected)

    def test_wildcard_binding_is_external(self):
        self.assertTrue(Listener("tcp", "0.0.0.0", 443).externally_reachable_binding)
        self.assertTrue(Listener("tcp", "::", 443).externally_reachable_binding)
        self.assertFalse(Listener("tcp", "127.0.0.1", 443).externally_reachable_binding)
        self.assertFalse(Listener("tcp", "::1", 443).externally_reachable_binding)

    def test_parse_allowlist_supports_ipv4_and_ipv6(self):
        parsed = parse_allowlist(["tcp:127.0.0.1:8080", "udp:[::1]:5353"])
        self.assertEqual(
            (
                Listener("tcp", "127.0.0.1", 8080),
                Listener("udp", "::1", 5353),
            ),
            parsed,
        )

    def test_invalid_allowlist_fails_closed(self):
        with self.assertRaises(NetworkExposureError):
            parse_allowlist(["tcp:0.0.0.0:not-a-port"])

    def test_parse_linux_ss(self):
        observed = parse_linux_ss(
            "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"python\",pid=1,fd=3))\n"
            "udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"svc\",pid=2,fd=4))\n"
        )
        self.assertEqual(
            (
                Listener("tcp", "127.0.0.1", 8080),
                Listener("udp", "0.0.0.0", 5353),
            ),
            observed,
        )

    def test_parse_windows_json(self):
        observed = parse_windows_json(
            '[{"protocol":"tcp","address":"127.0.0.1","port":8080},'
            '{"protocol":"udp","address":"::","port":5353}]'
        )
        self.assertEqual(
            (
                Listener("tcp", "127.0.0.1", 8080),
                Listener("udp", "::", 5353),
            ),
            observed,
        )

    def test_evidence_is_machine_readable_and_classifies_exposure(self):
        report = evaluate_listeners(
            [Listener("tcp", "0.0.0.0", 8443)],
            system="linux",
        )
        payload = json.loads(report.to_json())
        self.assertEqual("pulpo.network-exposure.v1", payload["schema"])
        self.assertFalse(payload["passed"])
        self.assertTrue(payload["unexpected"][0]["externally_reachable_binding"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

from pulpo.namecom_core import NameComResponse, NameComViolation


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_namecom_sandbox_readiness.py"
SPEC = importlib.util.spec_from_file_location("namecom_readiness_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeDelegate:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        payload = json.loads(body)
        domain = payload["domainNames"][0]
        return NameComResponse(
            200,
            {"Content-Type": "application/json"},
            json.dumps(
                {
                    "results": [
                        {
                            "domainName": domain,
                            "purchasable": True,
                            "purchaseType": "registration",
                            "premium": False,
                            "purchasePrice": 9.99,
                            "renewalPrice": 12.99,
                        }
                    ]
                }
            ).encode(),
        )


class ReadOnlyNameComTransportTests(unittest.TestCase):
    def setUp(self):
        self.delegate = FakeDelegate()
        self.transport = MODULE.ReadOnlyNameComTransport(self.delegate)
        self.body = json.dumps(
            {"domainNames": ["pulpo-readiness.example"], "purchaseType": "registration"},
            separators=(",", ":"),
        ).encode()
        self.headers = {
            "Authorization": "Basic redacted",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def test_exact_sandbox_availability_request_is_the_only_allowed_provider_call(self):
        response = self.transport.request(
            "POST",
            MODULE.READ_ONLY_URL,
            self.headers,
            self.body,
        )
        self.assertEqual(200, response.status)
        self.assertEqual([("POST", MODULE.READ_ONLY_URL)], self.transport.calls)
        self.assertEqual(1, len(self.delegate.calls))

    def test_create_domain_endpoint_is_blocked_before_delegate_network_call(self):
        with self.assertRaisesRegex(NameComViolation, "forbids_provider_write"):
            self.transport.request(
                "POST",
                "https://api.dev.name.com/core/v1/domains",
                self.headers,
                self.body,
            )
        self.assertEqual([], self.delegate.calls)

    def test_non_availability_methods_are_blocked_before_network(self):
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method), self.assertRaisesRegex(
                NameComViolation,
                "forbids_provider_write",
            ):
                self.transport.request(method, MODULE.READ_ONLY_URL, self.headers, self.body)
        self.assertEqual([], self.delegate.calls)

    def test_availability_scope_cannot_be_broadened(self):
        invalid_payloads = (
            {"domainNames": ["a.example", "b.example"], "purchaseType": "registration"},
            {"domainNames": ["a.example"], "purchaseType": "transfer"},
            {"domainNames": ["a.example"], "purchaseType": "registration", "extra": True},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaisesRegex(
                NameComViolation,
                "scope_invalid",
            ):
                self.transport.request(
                    "POST",
                    MODULE.READ_ONLY_URL,
                    self.headers,
                    json.dumps(payload).encode(),
                )
        self.assertEqual([], self.delegate.calls)

    def test_write_idempotency_header_is_rejected(self):
        headers = dict(self.headers)
        headers["X-Idempotency-Key"] = "write-key"
        with self.assertRaisesRegex(NameComViolation, "write_header_forbidden"):
            self.transport.request("POST", MODULE.READ_ONLY_URL, headers, self.body)
        self.assertEqual([], self.delegate.calls)


if __name__ == "__main__":
    unittest.main()

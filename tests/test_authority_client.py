from dataclasses import asdict
import inspect
import unittest

from pulpo import ApprovalEnvelope, AuthorityApprovalRequest, AuthorityClient


class _FakeResponse:
    status = 200

    def __init__(self, url, body):
        self.url = url
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def geturl(self):
        return self.url

    def read(self, _limit):
        return self.body


class _CapturingOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.response


class AuthorityClientTests(unittest.TestCase):
    def setUp(self):
        self.request = AuthorityApprovalRequest(
            principal="agent:publisher",
            action="push",
            resource="repo:origin/main",
            cost=0,
            session_id="session:1",
            intent_hash="a" * 64,
            policy_hash="b" * 64,
            deployment_id="deployment:production",
            requested_ttl_ns=1_000,
        )
        self.calls = []

        def transport(method, path, body):
            self.calls.append((method, path, body))
            if method == "POST":
                return {
                    "request_id": "request:1",
                    "approval_url": "https://authority.example.com/human/approval/request:1",
                }
            return {"status": "pending"}

        self.client = AuthorityClient("https://authority.example.com", transport=transport)

    def test_client_exposes_only_request_and_poll(self):
        public = {
            name
            for name, value in inspect.getmembers(AuthorityClient, predicate=inspect.isfunction)
            if not name.startswith("_")
        }
        self.assertEqual({"request_approval", "poll_approval"}, public)

    def test_request_and_poll_use_only_fixed_worker_paths(self):
        request_id, approval_url = self.client.request_approval(self.request)
        poll = self.client.poll_approval(request_id)
        self.assertEqual("https://authority.example.com/human/approval/request:1", approval_url)
        self.assertEqual("pending", poll.status)
        self.assertEqual(
            [
                ("POST", "/v1/approval-requests", asdict(self.request)),
                ("GET", "/v1/approval-requests/request%3A1", None),
            ],
            self.calls,
        )

    def test_default_transport_adds_fresh_worker_authorization(self):
        issued = []

        def authorization_provider():
            value = f"Bearer worker-token-{len(issued) + 1}"
            issued.append(value)
            return value

        client = AuthorityClient(
            "https://authority.example.com",
            authorization_provider=authorization_provider,
        )
        opener = _CapturingOpener(
            _FakeResponse(
                "https://authority.example.com/v1/approval-requests/request%3A1",
                b'{"status":"pending"}',
            )
        )
        client._opener = opener

        self.assertEqual("pending", client.poll_approval("request:1").status)
        self.assertEqual("pending", client.poll_approval("request:1").status)
        self.assertEqual(2, len(opener.requests))
        self.assertEqual(
            ["Bearer worker-token-1", "Bearer worker-token-2"],
            [request.get_header("Authorization") for request, _ in opener.requests],
        )

    def test_worker_authorization_failure_and_invalid_framing_fail_before_http(self):
        def unavailable():
            raise RuntimeError("identity provider unavailable")

        for provider, message in (
            (unavailable, "worker authorization unavailable"),
            (lambda: "worker-token", "worker authorization is invalid"),
            (lambda: "Bearer ", "worker authorization is invalid"),
            (lambda: " Bearer worker", "worker authorization is invalid"),
        ):
            with self.subTest(message=message):
                client = AuthorityClient(
                    "https://authority.example.com",
                    authorization_provider=provider,
                )
                opener = _CapturingOpener(
                    _FakeResponse(
                        "https://authority.example.com/v1/approval-requests/request%3A1",
                        b'{"status":"pending"}',
                    )
                )
                client._opener = opener
                with self.assertRaisesRegex(RuntimeError, message):
                    client.poll_approval("request:1")
                self.assertEqual([], opener.requests)

    def test_custom_transport_cannot_silently_ignore_authorization_provider(self):
        with self.assertRaisesRegex(ValueError, "default HTTPS transport"):
            AuthorityClient(
                "https://authority.example.com",
                transport=lambda *_: {"status": "pending"},
                authorization_provider=lambda: "Bearer worker-token",
            )

    def test_approved_poll_parses_exact_envelope(self):
        envelope = ApprovalEnvelope(
            approval_id="approval:1",
            authority_id="authority:founder",
            verifier_id="verifier:ed25519",
            key_id="key:service:v1",
            deployment_id="deployment:production",
            trust_hash="c" * 64,
            session_id="session:1",
            principal="agent:publisher",
            intent_hash="a" * 64,
            policy_hash="b" * 64,
            nonce="nonce:1",
            issued_at_ns=1,
            expires_at_ns=2,
            signature="00" * 64,
        )
        client = AuthorityClient(
            "https://authority.example.com",
            transport=lambda *_: {"status": "approved", "envelope": asdict(envelope)},
        )
        self.assertEqual(envelope, client.poll_approval("request:1").envelope)

    def test_non_https_and_cross_origin_human_urls_fail_closed(self):
        with self.assertRaises(ValueError):
            AuthorityClient("http://authority.example.com")
        client = AuthorityClient(
            "https://authority.example.com",
            transport=lambda *_: {
                "request_id": "request:1",
                "approval_url": "https://attacker.example/human/approval/request:1",
            },
        )
        with self.assertRaisesRegex(ValueError, "cross-origin"):
            client.request_approval(self.request)
        for invalid in (
            "https://user@authority.example.com",
            "https://authority.example.com?redirect=attacker",
            "https://authority.example.com#fragment",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                AuthorityClient(invalid)


if __name__ == "__main__":
    unittest.main()

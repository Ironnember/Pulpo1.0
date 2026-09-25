import json
import unittest
from unittest.mock import patch
from urllib import error as urllib_error

from pulpo.agentcore import AGENTCORE_PROTOCOL_VERSION, AgentCoreGatewayCall
from pulpo_custody_service.agentcore_transport import (
    AGENTCORE_TIMEOUT_SECONDS,
    AgentCoreExternalRealityUnknown,
    AgentCoreGatewayHttpTransport,
    AgentCoreProviderError,
    AgentCoreTransportConfigError,
)


GATEWAY_ARN = "arn:aws:bedrock-agentcore:us-west-2:111122223333:gateway/pulpo-proof"
GATEWAY_ENDPOINT = "https://pulpo-proof.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp"
FAKE_TOKEN = "TOKEN_NOT_REAL"


class FakeHeaders:
    def __init__(self, content_type="application/json"):
        self.content_type = content_type

    def get(self, name, default=""):
        if name.lower() == "content-type":
            return self.content_type
        return default


class FakeResponse:
    def __init__(self, payload: bytes, content_type="application/json") -> None:
        self.payload = payload
        self.headers = FakeHeaders(content_type)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


class AgentCoreGatewayHttpTransportTests(unittest.TestCase):
    def transport(self):
        return AgentCoreGatewayHttpTransport(
            gateway_arn=GATEWAY_ARN,
            gateway_endpoint=GATEWAY_ENDPOINT,
            bearer_token=FAKE_TOKEN,
        )

    def call(self, **arguments):
        values = {"record_id": "A-17", "status": "verified"}
        values.update(arguments)
        return AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            values,
        )

    def test_environment_requires_exact_gateway_and_custody_token(self):
        with self.assertRaisesRegex(AgentCoreTransportConfigError, "PULPO_AGENTCORE_GATEWAY_ARN"):
            AgentCoreGatewayHttpTransport.from_environ({})
        with self.assertRaisesRegex(AgentCoreTransportConfigError, "PULPO_AGENTCORE_GATEWAY_ENDPOINT"):
            AgentCoreGatewayHttpTransport.from_environ(
                {"PULPO_AGENTCORE_GATEWAY_ARN": GATEWAY_ARN}
            )
        with self.assertRaisesRegex(AgentCoreTransportConfigError, "PULPO_AGENTCORE_BEARER_TOKEN"):
            AgentCoreGatewayHttpTransport.from_environ(
                {
                    "PULPO_AGENTCORE_GATEWAY_ARN": GATEWAY_ARN,
                    "PULPO_AGENTCORE_GATEWAY_ENDPOINT": GATEWAY_ENDPOINT,
                }
            )

    def test_secret_is_redacted_from_repr(self):
        rendered = repr(self.transport())
        self.assertNotIn(FAKE_TOKEN, rendered)
        self.assertIn("<redacted>", rendered)

    def test_out_of_scope_gateway_is_rejected_before_network(self):
        other = AgentCoreGatewayCall.create(
            "arn:aws:bedrock-agentcore:us-west-2:111122223333:gateway/other",
            GATEWAY_ENDPOINT,
            "update_record",
            {"record_id": "A-17"},
        )
        with patch(
            "pulpo_custody_service.agentcore_transport.urllib_request.urlopen",
            side_effect=AssertionError("network must not be called"),
        ):
            with self.assertRaisesRegex(AgentCoreProviderError, "outside custody scope"):
                self.transport().call_tool(other)

    def test_request_shape_matches_current_agentcore_mcp_contract(self):
        captured = {}
        call = self.call()

        def fake_urlopen(request, *, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": f"pulpo-{call.call_hash[:24]}",
                        "result": {"content": [{"type": "text", "text": "ok"}]},
                    }
                ).encode()
            )

        with patch(
            "pulpo_custody_service.agentcore_transport.urllib_request.urlopen",
            side_effect=fake_urlopen,
        ):
            claim = self.transport().call_tool(call)

        request = captured["request"]
        self.assertEqual("POST", request.get_method())
        self.assertEqual(GATEWAY_ENDPOINT, request.full_url)
        self.assertEqual(AGENTCORE_TIMEOUT_SECONDS, captured["timeout"])
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(f"Bearer {FAKE_TOKEN}", headers["authorization"])
        self.assertEqual(AGENTCORE_PROTOCOL_VERSION, headers["mcp-protocol-version"])
        self.assertEqual("tools/call", headers["mcp-method"])
        self.assertEqual("update_record", headers["mcp-name"])
        body = json.loads(request.data)
        self.assertEqual("2.0", body["jsonrpc"])
        self.assertEqual("tools/call", body["method"])
        self.assertEqual("update_record", body["params"]["name"])
        self.assertEqual(call.arguments, body["params"]["arguments"])
        self.assertEqual(
            AGENTCORE_PROTOCOL_VERSION,
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        )
        self.assertEqual("provider_claim", claim["claim_class"])
        self.assertEqual(call.call_hash, claim["call_hash"])
        self.assertNotIn(FAKE_TOKEN, repr(claim))
        self.assertNotIn("A-17", repr(claim))

    def test_network_ambiguity_is_unknown_sanitized_and_not_retried(self):
        call = self.call()
        with patch(
            "pulpo_custody_service.agentcore_transport.urllib_request.urlopen",
            side_effect=urllib_error.URLError(f"sensitive {FAKE_TOKEN}"),
        ) as urlopen:
            with self.assertRaises(AgentCoreExternalRealityUnknown) as raised:
                self.transport().call_tool(call)

        self.assertEqual("EXTERNAL_REALITY_UNKNOWN", str(raised.exception))
        self.assertEqual(call.call_hash, raised.exception.call_hash)
        self.assertTrue(raised.exception.reconciliation_required)
        self.assertEqual(1, urlopen.call_count)
        self.assertNotIn(FAKE_TOKEN, str(raised.exception))

    def test_jsonrpc_error_is_provider_denial_not_success(self):
        call = self.call()
        response = FakeResponse(
            b'{"jsonrpc":"2.0","id":"x","error":{"code":-32000,"message":"denied"}}'
        )
        with patch(
            "pulpo_custody_service.agentcore_transport.urllib_request.urlopen",
            return_value=response,
        ):
            with self.assertRaisesRegex(AgentCoreProviderError, "JSON-RPC error"):
                self.transport().call_tool(call)

    def test_malformed_or_incomplete_success_is_unknown(self):
        call = self.call()
        for payload in (
            b"not-json",
            b'{"jsonrpc":"2.0","id":"x"}',
        ):
            with self.subTest(payload=payload):
                with patch(
                    "pulpo_custody_service.agentcore_transport.urllib_request.urlopen",
                    return_value=FakeResponse(payload),
                ):
                    with self.assertRaises(AgentCoreExternalRealityUnknown):
                        self.transport().call_tool(call)

    def test_sse_response_is_provider_claim_only(self):
        call = self.call()
        raw = b'event: message\ndata: {"jsonrpc":"2.0","id":"x","result":{"content":[]}}\n\n'
        with patch(
            "pulpo_custody_service.agentcore_transport.urllib_request.urlopen",
            return_value=FakeResponse(raw, "text/event-stream"),
        ):
            claim = self.transport().call_tool(call)
        self.assertEqual("provider_claim", claim["claim_class"])
        self.assertEqual(call.call_hash, claim["call_hash"])


if __name__ == "__main__":
    unittest.main()

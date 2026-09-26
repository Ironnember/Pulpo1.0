"""Custody-only Amazon Bedrock AgentCore Gateway transport.

The inbound authorization token remains execution-side. Gateway responses are
provider claims, not independent reconciliation evidence.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from typing import Mapping
from urllib import error as urllib_error
from urllib import request as urllib_request

from pulpo.agentcore import AgentCoreGatewayCall, AGENTCORE_PROTOCOL_VERSION


AGENTCORE_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 1_000_000


class AgentCoreTransportConfigError(RuntimeError):
    pass


class AgentCoreProviderError(RuntimeError):
    pass


class AgentCoreExternalRealityUnknown(AgentCoreProviderError):
    """A gateway transmission may have occurred and must not be retried automatically."""

    classification = "EXTERNAL_REALITY_UNKNOWN"
    reconciliation_required = True

    def __init__(self, call_hash: str) -> None:
        super().__init__(self.classification)
        self.call_hash = call_hash


def _required(name: str, environ: Mapping[str, str]) -> str:
    value = environ.get(name, "")
    if not isinstance(value, str) or not value:
        raise AgentCoreTransportConfigError(f"missing required environment variable: {name}")
    return value


class AgentCoreGatewayHttpTransport:
    """One pinned AgentCore Gateway using custody-held bearer authorization."""

    def __init__(
        self,
        *,
        gateway_arn: str,
        gateway_endpoint: str,
        bearer_token: str,
    ) -> None:
        if not isinstance(gateway_arn, str) or not gateway_arn.startswith("arn:"):
            raise AgentCoreTransportConfigError("AgentCore gateway ARN is invalid")
        if not isinstance(bearer_token, str) or not bearer_token or any(c.isspace() for c in bearer_token):
            raise AgentCoreTransportConfigError("AgentCore bearer token is invalid")
        probe = AgentCoreGatewayCall.create(
            gateway_arn,
            gateway_endpoint,
            "_pulpo_scope_probe",
            {},
        )
        self.expected_gateway_arn = probe.gateway_arn
        self.expected_gateway_endpoint = probe.gateway_endpoint
        self._bearer_token = bearer_token

    def __repr__(self) -> str:
        return (
            "AgentCoreGatewayHttpTransport("
            f"expected_gateway_arn={self.expected_gateway_arn!r}, "
            f"expected_gateway_endpoint={self.expected_gateway_endpoint!r}, "
            "bearer_token=<redacted>)"
        )

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "AgentCoreGatewayHttpTransport":
        env = dict(os.environ if environ is None else environ)
        return cls(
            gateway_arn=_required("PULPO_AGENTCORE_GATEWAY_ARN", env),
            gateway_endpoint=_required("PULPO_AGENTCORE_GATEWAY_ENDPOINT", env),
            bearer_token=_required("PULPO_AGENTCORE_BEARER_TOKEN", env),
        )

    def call_tool(
        self,
        call: AgentCoreGatewayCall,
        *,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        if not isinstance(call, AgentCoreGatewayCall):
            raise AgentCoreProviderError("AgentCore call object invalid")
        if call.gateway_arn != self.expected_gateway_arn:
            raise AgentCoreProviderError("AgentCore gateway ARN is outside custody scope")
        if call.gateway_endpoint != self.expected_gateway_endpoint:
            raise AgentCoreProviderError("AgentCore gateway endpoint is outside custody scope")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise AgentCoreProviderError("AgentCore custody idempotency key missing")

        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": f"pulpo-{idempotency_key[:24]}",
                "method": "tools/call",
                "params": {
                    "name": call.tool_name,
                    "arguments": call.arguments,
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": AGENTCORE_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "pulpo-custody",
                            "version": "0.1.0",
                        },
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        request = urllib_request.Request(
            call.gateway_endpoint,
            data=payload,
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {self._bearer_token}",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": AGENTCORE_PROTOCOL_VERSION,
                "Mcp-Method": "tools/call",
                "Mcp-Name": call.tool_name,
            },
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=AGENTCORE_TIMEOUT_SECONDS) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, OSError):
            raise AgentCoreExternalRealityUnknown(call.call_hash) from None

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise AgentCoreExternalRealityUnknown(call.call_hash)

        content_type = ""
        try:
            content_type = response.headers.get("Content-Type", "")
        except AttributeError:
            pass

        if "text/event-stream" in content_type:
            if not raw.strip():
                raise AgentCoreExternalRealityUnknown(call.call_hash)
        else:
            try:
                decoded = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
                raise AgentCoreExternalRealityUnknown(call.call_hash) from None
            if not isinstance(decoded, dict):
                raise AgentCoreExternalRealityUnknown(call.call_hash)
            error = decoded.get("error")
            if error is not None:
                raise AgentCoreProviderError("AgentCore gateway returned JSON-RPC error")
            if "result" not in decoded:
                raise AgentCoreExternalRealityUnknown(call.call_hash)

        return {
            "provider": "amazon_bedrock_agentcore_gateway",
            "method": "tools/call",
            "gateway_arn": call.gateway_arn,
            "tool_name": call.tool_name,
            "call_hash": call.call_hash,
            "request_id": f"pulpo-{idempotency_key[:24]}",
            "response_sha256": sha256(raw).hexdigest(),
            "claim_class": "provider_claim",
        }

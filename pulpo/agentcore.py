"""Exact Amazon Bedrock AgentCore Gateway projection for external custody proof.

This module holds no AWS credentials and performs no network I/O. It freezes the
exact gateway tool call and delegates authorization to the canonical
GovernanceKernel.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

from .kernel import Decision, GovernanceKernel, Intent


AGENTCORE_ACTIVATE_ACTION = "activate_capability"
AGENTCORE_INVOKE_ACTION = "agentcore_gateway_invoke_tool"
AGENTCORE_PROTOCOL_VERSION = "2026-07-28"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _normalize_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("agentcore gateway endpoint must be non-empty")
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("agentcore gateway endpoint must be https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("agentcore gateway endpoint must not contain credentials, query, or fragment")
    if parsed.path not in ("", "/mcp"):
        raise ValueError("agentcore gateway endpoint must identify the MCP endpoint")
    path = "/mcp"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"https://{parsed.hostname}{port}{path}"


@dataclass(frozen=True)
class AgentCoreGatewayCall:
    """Exact MCP tools/call object for one AgentCore Gateway consequence."""

    gateway_arn: str
    gateway_endpoint: str
    tool_name: str
    arguments_json: str
    protocol_version: str = AGENTCORE_PROTOCOL_VERSION
    schema: str = "pulpo.agentcore-gateway-call.v0"

    def __post_init__(self) -> None:
        if not isinstance(self.gateway_arn, str) or not self.gateway_arn.startswith("arn:"):
            raise ValueError("agentcore gateway ARN must be canonical ARN text")
        object.__setattr__(self, "gateway_endpoint", _normalize_endpoint(self.gateway_endpoint))
        if not isinstance(self.tool_name, str) or not self.tool_name or self.tool_name != self.tool_name.strip():
            raise ValueError("agentcore tool name must be canonical non-empty text")
        if self.protocol_version != AGENTCORE_PROTOCOL_VERSION:
            raise ValueError("unsupported AgentCore MCP protocol version")
        if self.schema != "pulpo.agentcore-gateway-call.v0":
            raise ValueError("unsupported agentcore gateway call schema")
        if not isinstance(self.arguments_json, str) or not self.arguments_json:
            raise ValueError("agentcore arguments_json must be canonical JSON text")
        try:
            decoded = json.loads(self.arguments_json)
        except json.JSONDecodeError as exc:
            raise ValueError("agentcore arguments_json must be valid JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("agentcore tool arguments must be a JSON object")
        canonical = _canonical(decoded).decode("utf-8")
        if canonical != self.arguments_json:
            raise ValueError("agentcore arguments_json must use canonical JSON encoding")

    @classmethod
    def create(
        cls,
        gateway_arn: str,
        gateway_endpoint: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> "AgentCoreGatewayCall":
        if not isinstance(arguments, Mapping):
            raise ValueError("agentcore tool arguments must be a mapping")
        canonical_arguments = _canonical(dict(arguments)).decode("utf-8")
        return cls(
            gateway_arn=gateway_arn,
            gateway_endpoint=gateway_endpoint,
            tool_name=tool_name,
            arguments_json=canonical_arguments,
        )

    @property
    def arguments(self) -> Mapping[str, Any]:
        return json.loads(self.arguments_json)

    @property
    def call_hash(self) -> str:
        return sha256(
            _canonical(
                {
                    "schema": self.schema,
                    "gateway_arn": self.gateway_arn,
                    "gateway_endpoint": self.gateway_endpoint,
                    "protocol_version": self.protocol_version,
                    "method": "tools/call",
                    "tool_name": self.tool_name,
                    "arguments": self.arguments,
                }
            )
        ).hexdigest()

    @property
    def activation_resource(self) -> str:
        return f"{self.gateway_arn}:capability:mcp:tools/call"

    @property
    def resource(self) -> str:
        return f"{self.gateway_arn}:tool:{self.tool_name}:sha256:{self.call_hash}"

    def activation_intent(self, *, principal: str, session_id: str) -> Intent:
        return Intent(
            principal=principal,
            action=AGENTCORE_ACTIVATE_ACTION,
            resource=self.activation_resource,
            cost=0,
            session_id=session_id,
        )

    def intent(self, *, principal: str, session_id: str) -> Intent:
        return Intent(
            principal=principal,
            action=AGENTCORE_INVOKE_ACTION,
            resource=self.resource,
            cost=0,
            session_id=session_id,
        )


class AgentCoreGatewayTransport(Protocol):
    expected_gateway_arn: str
    expected_gateway_endpoint: str

    def call_tool(self, call: AgentCoreGatewayCall) -> Mapping[str, object]: ...


class AgentCoreInvocationRejected(RuntimeError):
    pass


class GovernedAgentCoreGatewayInvoker:
    """Execution gate consuming exact activation + exact invocation permits."""

    def __init__(self, kernel: GovernanceKernel, transport: AgentCoreGatewayTransport) -> None:
        self._kernel = kernel
        self._transport = transport

    def evaluate_activation(
        self,
        call: AgentCoreGatewayCall,
        *,
        principal: str,
        session_id: str,
    ) -> Decision:
        return self._kernel.evaluate(
            call.activation_intent(principal=principal, session_id=session_id)
        )

    def evaluate(
        self,
        call: AgentCoreGatewayCall,
        *,
        principal: str,
        session_id: str,
    ) -> Decision:
        return self._kernel.evaluate(call.intent(principal=principal, session_id=session_id))

    def _validate_transport_scope(self, call: AgentCoreGatewayCall) -> None:
        if getattr(self._transport, "expected_gateway_arn", None) != call.gateway_arn:
            raise AgentCoreInvocationRejected("agentcore transport gateway ARN mismatch")
        if getattr(self._transport, "expected_gateway_endpoint", None) != call.gateway_endpoint:
            raise AgentCoreInvocationRejected("agentcore transport endpoint mismatch")

    def execute(
        self,
        call: AgentCoreGatewayCall,
        *,
        activation_permit: str,
        invocation_permit: str,
        principal: str,
        session_id: str,
    ) -> Mapping[str, object]:
        self._validate_transport_scope(call)
        activation_intent = call.activation_intent(
            principal=principal,
            session_id=session_id,
        )
        invocation_intent = call.intent(
            principal=principal,
            session_id=session_id,
        )
        if not isinstance(activation_permit, str) or not activation_permit:
            raise AgentCoreInvocationRejected("agentcore activation permit missing")
        if not self._kernel.consume(activation_permit, activation_intent):
            raise AgentCoreInvocationRejected("agentcore activation permit rejected")
        if not isinstance(invocation_permit, str) or not invocation_permit:
            raise AgentCoreInvocationRejected("agentcore invocation permit missing")
        if not self._kernel.consume(invocation_permit, invocation_intent):
            raise AgentCoreInvocationRejected("agentcore invocation permit rejected")
        return self._transport.call_tool(call)

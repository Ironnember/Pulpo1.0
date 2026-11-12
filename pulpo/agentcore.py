"""Exact Amazon Bedrock AgentCore Gateway projection for external custody proof.

This module holds no AWS credentials and performs no network I/O. It freezes the
exact gateway tool call, delegates authority to the canonical GovernanceKernel,
then routes execution through Pulpo's existing durable custody transmission
lifecycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from .custody import CustodyViolation, SQLiteGovernanceCustody
from .custody_executor import (
    ExternalConsequenceUnknown,
    GovernedConsequenceRef,
    TrustedConsequenceExecutor,
)
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


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


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

    def call_tool(
        self,
        call: AgentCoreGatewayCall,
        *,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...


class AgentCoreInvocationRejected(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentCoreAttempt:
    attempt_id: str
    call_hash: str
    target_hash: str
    policy_hash: str
    authorization_hash: str
    schema: str = "pulpo.agentcore-attempt.v0"


@dataclass(frozen=True)
class AgentCoreProviderClaim:
    attempt_id: str
    call_hash: str
    provider_request_id: str
    idempotency_key: str
    provider_claim: Mapping[str, object]
    claim_hash: str
    reconciliation_required: bool = True
    schema: str = "pulpo.agentcore-provider-claim.v0"


class GovernedAgentCoreGatewayInvoker:
    """Govern exact AgentCore execution through canonical durable custody.

    Two distinct Pulpo permits remain required: one for capability activation and
    one for the exact tools/call object. Both are consumed before custody mints a
    durable attempt. The call hash is the custody object hash, so a restart and
    fresh approval cannot create a second attempt for the same consequence.
    """

    def __init__(
        self,
        kernel: GovernanceKernel,
        transport: AgentCoreGatewayTransport,
        *,
        custody: SQLiteGovernanceCustody | None = None,
        executor_id: str = "executor:agentcore-v0",
        evidence_projector: Callable[[], None] | None = None,
    ) -> None:
        self._kernel = kernel
        self._transport = transport
        self._custody = custody
        self._executor = (
            TrustedConsequenceExecutor(
                custody,
                executor_id=executor_id,
                evidence_projector=evidence_projector,
            )
            if custody is not None
            else None
        )

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

    def authorize_attempt(
        self,
        call: AgentCoreGatewayCall,
        *,
        activation_permit: str,
        invocation_permit: str,
        principal: str,
        session_id: str,
    ) -> AgentCoreAttempt:
        self._validate_transport_scope(call)
        if self._custody is None:
            raise AgentCoreInvocationRejected("agentcore durable custody required")

        activation_intent = call.activation_intent(
            principal=principal,
            session_id=session_id,
        )
        invocation_intent = call.intent(
            principal=principal,
            session_id=session_id,
        )
        target_id = f"agentcore:{call.call_hash}"
        target = self._kernel.lock_target(target_id, invocation_intent)
        resolution = self._kernel.resolve_locked_target(target.target_id, target.target_hash)
        if resolution.outcome != "match" or resolution.target is None:
            raise AgentCoreInvocationRejected(f"agentcore target rejected:{resolution.reason}")

        if not isinstance(activation_permit, str) or not activation_permit:
            raise AgentCoreInvocationRejected("agentcore activation permit missing")
        if not self._kernel.consume(activation_permit, activation_intent):
            raise AgentCoreInvocationRejected("agentcore activation permit rejected")
        if not isinstance(invocation_permit, str) or not invocation_permit:
            raise AgentCoreInvocationRejected("agentcore invocation permit missing")
        if not self._kernel.consume(invocation_permit, invocation_intent):
            raise AgentCoreInvocationRejected("agentcore invocation permit rejected")

        audit = self._kernel.audit
        if not audit or audit[-1].get("event") != "permit_consumed":
            raise AgentCoreInvocationRejected("agentcore canonical consumption evidence missing")
        canonical_audit_tip = audit[-1]["hash"]

        permit_hash = sha256(
            _canonical(
                {
                    "activation_permit_sha256": sha256(activation_permit.encode()).hexdigest(),
                    "invocation_permit_sha256": sha256(invocation_permit.encode()).hexdigest(),
                }
            )
        ).hexdigest()
        authorization_hash = _hash(
            {
                "schema": "pulpo.agentcore-custody-authorization.v0",
                "call_hash": call.call_hash,
                "target_hash": target.target_hash,
                "activation_intent_hash": self._kernel.intent_hash(activation_intent),
                "invocation_intent_hash": self._kernel.intent_hash(invocation_intent),
                "policy_hash": self._kernel.policy_hash,
                "permit_hash": permit_hash,
                "canonical_audit_tip": canonical_audit_tip,
            }
        )

        head = self._custody.snapshot()
        try:
            authorized = self._custody.authorize_attempt(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                object_hash=call.call_hash,
                target_hash=target.target_hash,
                permit_hash=permit_hash,
                authorization_hash=authorization_hash,
            )
        except CustodyViolation as exc:
            raise AgentCoreInvocationRejected(f"agentcore custody authorization rejected:{exc}") from exc

        return AgentCoreAttempt(
            attempt_id=authorized.attempt_id,
            call_hash=call.call_hash,
            target_hash=target.target_hash,
            policy_hash=self._kernel.policy_hash,
            authorization_hash=authorization_hash,
        )

    def execute_attempt(
        self,
        attempt: AgentCoreAttempt,
        call: AgentCoreGatewayCall,
    ) -> AgentCoreProviderClaim:
        self._validate_transport_scope(call)
        if self._executor is None:
            raise AgentCoreInvocationRejected("agentcore durable custody required")
        if call.call_hash != attempt.call_hash:
            raise AgentCoreInvocationRejected("agentcore call object mismatch")

        provider_request_id = (
            f"agentcore:{attempt.attempt_id}:tools-call:{call.call_hash}"
        )
        try:
            transmitted = self._executor.execute(
                GovernedConsequenceRef(attempt.attempt_id, call.call_hash),
                provider_request_id=provider_request_id,
                transmit=lambda idempotency_key: self._transport.call_tool(
                    call,
                    idempotency_key=idempotency_key,
                ),
            )
        except ExternalConsequenceUnknown:
            raise
        except CustodyViolation as exc:
            raise AgentCoreInvocationRejected(f"agentcore execution rejected:{exc}") from exc

        provider_claim = transmitted.result
        if not isinstance(provider_claim, Mapping):
            raise AgentCoreInvocationRejected("agentcore provider claim invalid")
        claim_material = {
            "schema": "pulpo.agentcore-provider-claim.v0",
            "attempt_id": attempt.attempt_id,
            "call_hash": call.call_hash,
            "provider_request_id": transmitted.provider_request_id,
            "idempotency_key": transmitted.idempotency_key,
            "provider_claim": dict(provider_claim),
        }
        return AgentCoreProviderClaim(
            attempt_id=attempt.attempt_id,
            call_hash=call.call_hash,
            provider_request_id=transmitted.provider_request_id,
            idempotency_key=transmitted.idempotency_key,
            provider_claim=dict(provider_claim),
            claim_hash=_hash(claim_material),
        )

    def execute(
        self,
        call: AgentCoreGatewayCall,
        *,
        activation_permit: str,
        invocation_permit: str,
        principal: str,
        session_id: str,
    ) -> AgentCoreProviderClaim:
        attempt = self.authorize_attempt(
            call,
            activation_permit=activation_permit,
            invocation_permit=invocation_permit,
            principal=principal,
            session_id=session_id,
        )
        return self.execute_attempt(attempt, call)

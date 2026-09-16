"""Fail-closed binding between an authorized intent and observed execution context.

The execution surface is not an authority source. A context-sensitive adapter
must derive ``ExecutionContext`` from provider/account introspection that is
independent of caller-supplied routing arguments, bind that requirement into the
intent resource before authorization, and verify the observation before permit
consumption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
from typing import Any

from .kernel import GovernanceKernel, Intent


_CONTEXT_SCHEMA = "pulpo.execution-context.v0"
_RESOURCE_PREFIX = f"{_CONTEXT_SCHEMA}:"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class ExecutionContext:
    """Exact authority domain observed at an execution surface.

    ``surface`` identifies the provider or capability family (for example,
    ``slack`` or ``github``). ``authority_scope`` identifies the exact tenant,
    workspace, account, organization, project, database, or equivalent authority
    domain. Optional principal/connection fields tighten the binding when those
    identities can be independently observed.
    """

    surface: str
    authority_scope: str
    principal: str = ""
    connection: str = ""
    schema: str = _CONTEXT_SCHEMA

    def __post_init__(self) -> None:
        values = (self.surface, self.authority_scope, self.principal, self.connection, self.schema)
        if any(not isinstance(value, str) for value in values):
            raise TypeError("execution context fields must be strings")
        if not self.surface or not self.authority_scope:
            raise ValueError("execution context surface and authority scope are required")
        if self.schema != _CONTEXT_SCHEMA:
            raise ValueError("unsupported execution context schema")

    @property
    def context_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class ExecutionContextCheck:
    """Non-authoritative evidence from one pre-execution context comparison."""

    outcome: str
    reason: str
    expected_context_hash: str | None
    observed_context_hash: str | None
    authority_effect: str = "none"


def bind_resource_to_execution_context(resource: str, context: ExecutionContext) -> str:
    """Bind one resource to an exact execution context inside the intent hash."""

    if not isinstance(resource, str) or not resource:
        raise ValueError("resource must be a non-empty string")
    if not isinstance(context, ExecutionContext):
        raise TypeError("context must be an ExecutionContext")
    return f"{_RESOURCE_PREFIX}{context.context_hash}:{resource}"


def required_execution_context_hash(resource: str) -> str | None:
    """Return the exact context hash embedded in a bound intent resource."""

    if not isinstance(resource, str) or not resource.startswith(_RESOURCE_PREFIX):
        return None
    remainder = resource[len(_RESOURCE_PREFIX) :]
    digest, separator, payload = remainder.partition(":")
    if not separator or not payload or len(digest) != 64:
        return None
    try:
        int(digest, 16)
    except ValueError:
        return None
    return digest


def verify_execution_context(
    intent: Intent,
    observed_context: ExecutionContext | None,
) -> ExecutionContextCheck:
    """Fail closed unless independent context observation matches the bound intent."""

    expected = required_execution_context_hash(intent.resource)
    if expected is None:
        return ExecutionContextCheck("deny", "execution_context_binding_missing", None, None)
    if observed_context is None:
        return ExecutionContextCheck("deny", "execution_context_observation_missing", expected, None)
    if not isinstance(observed_context, ExecutionContext):
        return ExecutionContextCheck("deny", "execution_context_observation_invalid", expected, None)

    observed = observed_context.context_hash
    if not hmac.compare_digest(expected, observed):
        return ExecutionContextCheck("deny", "execution_context_mismatch", expected, observed)
    return ExecutionContextCheck("match", "execution_context_exact_match", expected, observed)


def consume_context_bound_permit(
    kernel: GovernanceKernel,
    permit: str,
    intent: Intent,
    observed_context: ExecutionContext | None,
) -> tuple[ExecutionContextCheck, bool]:
    """Consume a permit only after the exact bound execution context is observed.

    A mismatch never calls ``GovernanceKernel.consume``. This keeps the permit
    unspent because no execution was authorized, while ensuring a provider read
    or write can be placed strictly after this gate by a bounded adapter.
    """

    check = verify_execution_context(intent, observed_context)
    if check.outcome != "match":
        return check, False
    return check, kernel.consume(permit, intent)

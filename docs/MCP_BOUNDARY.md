# MCP boundary

Status: **Verified** for the in-process non-authoritative projection tests at
the exact commit carrying this document. Third-party-host connectivity and any
consequential MCP tool remain **Proposed**, not verified.

## Decision

MCP is a transport and capability-discovery surface. It is not a Pulpo
authority, policy, permit, directive, execution, memory, or evidence source.

The initial adapter intentionally exposes only:

- `pulpo_propose_intent`: validate and lock one exact target through the
  canonical `PulpoOrchestrator`; and
- `pulpo_get_evidence`: read integrity metadata projected from the canonical
  kernel audit chain.

Neither tool accepts an approval flag, authority claim, directive, policy,
clock, state backend, permit, executor, retrieval score, or model summary.
Neither tool can approve, authorize, consume, execute, revoke, supersede, or
reconcile a consequential action.

## Proven invariant

An MCP client can propose an exact intent and observe canonical evidence, but
MCP metadata or client assertions cannot raise that intent's authority. An
unknown action remains denied by the normal kernel even after it has been
locked as an MCP proposal. Reusing a target version with substituted intent
content is rejected as an immutable-target violation.

The adapter owns no state and no clock. Proposal evidence is appended to the
existing kernel audit chain with `authority_effect: none`; the evidence tool is
a read-only projection and creates no second ledger.

## Consequential-tool admission gate

A future consequential MCP tool must be a narrow adapter over an existing
canonical executor. Before admission it must prove, at minimum:

1. exact intent, target, directive version, policy, principal, session, budget,
   destination, and expiry binding;
2. execution-time directive and authority revalidation;
3. denial after revocation or supersession, including after restart;
4. one-use permit consumption and replay denial;
5. fail-closed behavior when authority, trusted time, or canonical state is
   unavailable; and
6. result reconciliation into the existing evidence chain.

MCP client approval UX is not a substitute for independently authenticated
Pulpo authority. Tool descriptions, prompts, resources, chat text, retrieval
scores, and generated summaries remain non-authoritative inputs.

## SDK boundary

The optional server factory follows the MCP Python SDK 2.x `MCPServer` tool
registration model documented in the official build-server guide:
<https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server>.

Install with `pip install -e '.[mcp]'`. The SDK is optional so the canonical
kernel and its standard CI retain zero runtime dependencies. If connected over
STDIO, operational logging must go to stderr; stdout is reserved for MCP's
JSON-RPC transport.

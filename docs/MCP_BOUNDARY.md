# MCP boundary

Status: **Verified** for the in-process non-authoritative projection tests at
the exact commit carrying this document. Third-party-host connectivity and any
consequential MCP tool remain **Proposed**, not verified.

## Decision

MCP is a transport and capability-discovery surface. It is not a Pulpo
authority, policy, permit, directive, execution, memory, or evidence source.

The initial adapter intentionally exposes only:

- `pulpo_propose_intent`: validate and project one exact intent candidate from
  the capability-stripped frozen snapshot without a canonical write; and
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

## Trusted frozen-snapshot export

`export_mcp_snapshot(orchestrator, destination)` is the trusted-side file
bridge for capability-stripped consumers. It accepts the canonical
`PulpoOrchestrator`, calls the existing `freeze_mcp_snapshot()` projection, and
writes only the six primitive `pulpo.mcp-read-snapshot.v0` fields. The exporter
is not registered as an MCP tool.

The destination must be absolute and its immediate parent must already exist
as a real directory rather than a symlink. A symlink or other non-regular
destination is rejected. Creation, replacement, cleanup, and synchronization
remain bound to one opened parent-directory descriptor. The file is written
through a same-directory temporary file, synchronized, atomically replaced,
and restricted to owner read/write permissions. Before reporting success, the
exporter rechecks that the requested parent path still names the opened
directory and that the requested destination names the file published through
that descriptor.

An error before atomic replacement is reported as `mcp_snapshot_export_failed`.
An error after replacement, including directory synchronization failure or a
failed pathname-binding recheck, is reported as
`mcp_snapshot_export_commit_unknown`: the caller must reconcile the destination
before retrying because a frozen file may already exist. This status is not
permission, verified delivery, or proof that a reader observed the snapshot.

Export does not mutate canonical Pulpo state or append a second audit event.
The resulting file is a frozen derivative: it cannot follow later canonical
mutations, and its presence does not prove live-current freshness, production
authentication, independent deployment, or external consequence containment.

## Governed proposal admission

`MCPProposalAdmissionController` is the trusted-side handoff from one exact
`pulpo.mcp-proposal.v2` object into the existing durable `LockedTarget` path.
It is not registered as an MCP tool and must never be mounted in the
capability-stripped plugin process.

The handoff requires the current kernel to issue a permit for
`admit_mcp_proposal` bound to the proposal hash and current policy hash. The
controller then:

1. rejects added fields, capability claims, malformed or oversized identities,
   intent-hash mismatches, and stale snapshot policy;
2. rejects an already used target identity before consuming admission
   authority;
3. consumes the exact admission permit once;
4. locks the proposal's intent through the existing orchestrator and kernel;
5. records a hash-bound admission receipt in the existing canonical audit.

The proposal, snapshot, plugin text, and admission receipt cannot authorize the
proposed action. After admission, the locked target still has to pass Pulpo's
ordinary identity, policy, budget, approval, permit, executor, and
reconciliation path. The admission receipt reports
`authority_effect=none`,
`governed_effect=canonical_target_lock_and_admission_evidence`, and
`canonical_state_mutation=true`; the preceding audit records separately prove
the admission permit was consumed.

The software proof composes this handoff with Pulpo's existing approval,
one-use permit, domain custody, bounded executor, independent reconciliation,
and non-authorizing outcome-memory components using an in-process test
authority and fake registrar. No provider is called and no credential is
created. It does not prove that the installed plugin can invoke the trusted
controller, that a production authority is independent, or that a real
external consequence is contained or verified.

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

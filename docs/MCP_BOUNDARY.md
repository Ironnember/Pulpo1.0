# MCP boundary

Status: **Verified** for the in-process non-authoritative projection tests at
the exact commit carrying this document. Third-party-host connectivity and any
consequential MCP tool remain **Proposed**, not verified.

## Decision

MCP is a transport and capability-discovery surface. It is not a Pulpo
authority, policy, permit, directive, execution, memory, or evidence source.

The capability-stripped adapter intentionally exposes only:

- `pulpo_propose_intent`: validate and copy one exact intent into an ephemeral,
  capability-free proposal; and
- `pulpo_get_evidence`: read integrity metadata projected from the canonical
  kernel audit chain into a frozen primitive snapshot.

Neither tool accepts an approval flag, authority claim, directive, policy,
clock, state backend, permit, executor, retrieval score, or model summary.
Neither tool can approve, authorize, consume, execute, revoke, supersede, or
reconcile a consequential action.

## Proven invariant

An MCP client can prepare an exact intent and observe frozen evidence, but MCP
metadata or client assertions cannot raise that intent's authority. A proposal
does not lock a canonical target, issue a permit, consult authority, or create a
governed state transition. Its policy hash is informational until canonical
Pulpo independently re-resolves and evaluates the intent.

The adapter owns no state and no clock. Repeated, changed, malformed, or
substituted proposal calls leave the canonical audit unchanged. The evidence
tool is a read-only projection and creates no second ledger.

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

## Observed frozen-snapshot reconciliation

**Verified**, 2026-09-08, against canonical main
`b44dcd40a1ad2bd5413756bd413807f54f9283da`: the operator-host durable SQLite
database passed `PRAGMA quick_check`. The canonical kernel bootstrapped against
a disposable database copy using a disposable verification-only secret and
reproduced the configured snapshot's policy hash, valid 2,589-record audit
chain, and audit tip. Export through the canonical
`PulpoOrchestrator -> export_mcp_snapshot` path produced a mode-`0600` file
byte-identical to the configured frozen object, SHA-256
`21b8a36425e63b921145dbbb15d07147fb6fbdc4fcb913cdf06045a54f26b397`.

The original durable database, configured snapshot, and runtime secrets were
not modified or read during that reconciliation. The newest stored audit event
was `2026-09-01T18:34:26.584436Z`, and no Pulpo process was running. This proves
compatibility and provenance for that exact frozen object at the observation
point. It does not prove present freshness, runtime admission, production
deployment, or external consequence.

Durable record:
<https://github.com/Ironnember/Pulpo1.0/pull/200#issuecomment-5582109586>

## Remaining trusted-runtime handoff

The export primitive intentionally does not define or expose runtime bootstrap.
The next proof must call `export_mcp_snapshot()` from an already admitted,
trusted process that owns the canonical `PulpoOrchestrator`. It must not rebuild
policy, reopen canonical state, or retain a kernel inside the MCP adapter merely
to make the export callable. Until that same-process handoff is admitted and
observed, plugin retrieval remains frozen evidence rather than live Pulpo state.

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

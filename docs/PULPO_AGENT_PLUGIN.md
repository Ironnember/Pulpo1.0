# Pulpo Agent Plugin v0

Status: **Proposed** until admitted through the protected repository path.

## Purpose

Package Pulpo's existing capability-stripped MCP projection as an Agent Plugins
1.0.0 directory without creating a new authority, policy engine, executor,
router, memory governor, state backend, or evidence ledger.

The plugin exposes the same two non-authoritative MCP tools already defined by
`pulpo.mcp_boundary`:

- `pulpo_propose_intent` constructs an exact frozen proposal; and
- `pulpo_get_evidence` returns frozen integrity metadata.

The plugin does not activate directives, issue or consume permits, mutate
canonical Pulpo state, execute provider actions, reconcile consequences, or
write governed outcome memory.

## Package layout

- `plugin.json` declares the Agent Plugins 1.0.0 package.
- `mcp.json` declares one local `stdio` MCP server.
- `pulpo/mcp_plugin.py` loads one exact frozen snapshot and delegates tool
  registration to the existing `create_mcp_server()` implementation.
- `${PLUGIN_DATA}/mcp-read-snapshot.json` is the only runtime input declared by
  the plugin configuration.

`PLUGIN_DATA` is client-managed noncanonical plugin storage. Its contents are a
derivative input and never become Pulpo authority merely because the plugin can
read them.

## Dependency and launch boundary

The host must provide Python 3.11+ and the optional MCP dependency before the
server can start:

```text
python3 -m pip install -e '.[mcp]'
```

The plugin does not install dependencies, fetch code, or modify Pulpo during
launch. `mcp.json` starts:

```text
python3 -m pulpo.mcp_plugin --snapshot ${PLUGIN_DATA}/mcp-read-snapshot.json
```

The server uses MCP `stdio`. No public endpoint, OAuth flow, remote deployment,
or production ChatGPT connectivity is claimed by this package.

## Snapshot handoff

A trusted Pulpo process may create the primitive snapshot only through the
existing `export_mcp_snapshot()` boundary. The plugin itself does not receive
that exporter or the orchestrator needed to call it.

To seed a local plugin instance, the operator may copy the exact exported file
to the client-provided `PLUGIN_DATA` directory and preserve owner-only access.
The reader fails closed for a relative path, symlinked immediate parent, linked
final file, oversized document, group/world-readable POSIX file, malformed JSON,
duplicate keys, missing fields, extra fields, or an invalid snapshot schema.

Copying a frozen derivative into plugin storage does not make it current and
does not authorize anything. Every consequential action still requires live
canonical Pulpo evaluation through the existing authority -> permit -> execution
-> evidence -> reconciliation path.

## Claim classification

**Proposed:** this repository package and its new snapshot reader until admitted.

**Verified previously at the canonical software boundary:** the underlying MCP
projection is non-mutating and the trusted exporter produces a capability-free
frozen snapshot.

**Recorded previously:** an installed local Pulpo reader successfully consumed
an exported snapshot in an isolated test topology.

**Unknown / not claimed:** current live Pulpo runtime freshness, remote MCP
hosting, ChatGPT production binding, production authentication, independent
provider containment, or external consequence verification.

## Change record

1. **Invariant addressed:** a plugin package must not gain hidden canonical write
   capability merely because its visible tools are read-only/proposal-only.
2. **Authority effect:** none.
3. **Canonical state mutation introduced or exposed:** none.
4. **Success/adversarial evidence:** exact snapshot allowlist, bounded read,
   private-file check, symlink rejection, duplicate-key rejection, malformed
   input rejection, and stdio-only launcher tests are added on this branch.
5. **Boundary not proved:** live installation and production connectivity are not
   established by repository tests.
6. **Claim classification:** Proposed until normal admission and exact-head CI.
7. **Legacy behavior:** reuses the admitted MCP projection rather than copying a
   legacy router or control path.
8. **Temporal transfer:** no authority-bearing lesson or historical capability is
   imported; no temporal authority transfer is claimed.

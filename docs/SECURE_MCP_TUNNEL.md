# Pulpo Secure MCP Tunnel Binding v0

Status: **Proposed** until admitted through the protected repository path.

## Purpose

Connect ChatGPT to Pulpo's already-admitted, capability-stripped MCP projection
without exposing Pulpo on a public inbound endpoint and without giving ChatGPT,
the tunnel daemon, or the MCP transport any Pulpo authority capability.

The transport path is:

`ChatGPT -> OpenAI-hosted Secure MCP Tunnel -> tunnel-client -> pulpo.mcp_plugin -> frozen MCP snapshot`

The authority path is unchanged. The tunnel does not receive a Pulpo kernel,
orchestrator, authority client, executor, permit, policy object, canonical state
backend, credential, or evidence ledger.

## Existing MCP surface

Only the existing admitted MCP tools are reachable through this binding:

- `pulpo_get_evidence`
- `pulpo_propose_intent`

Both remain frozen, non-authoritative projections. Consequential actions still
require canonical Pulpo evaluation outside this transport surface.

## Prerequisites

The operator must provide:

1. the official `tunnel-client` binary from `openai/tunnel-client`;
2. one OpenAI Secure MCP Tunnel ID in the exact control-plane format
   `tunnel_` followed by 32 lowercase hexadecimal characters;
3. one runtime API key in `CONTROL_PLANE_API_KEY` with Tunnels Read + Use;
4. one trusted frozen snapshot created by Pulpo's existing
   `export_mcp_snapshot()` function.

Create the tunnel from Platform Tunnels management or the separately authorized
admin-key path. Tunnel CRUD and tunnel runtime are different privileges. Do not
put an admin API key in the long-lived daemon.

## Run

Install Pulpo with MCP support:

```text
python3 -m pip install -e '.[mcp]'
```

Export the runtime key and exact tunnel ID only into the process environment:

```text
export CONTROL_PLANE_API_KEY='...'
export CONTROL_PLANE_TUNNEL_ID='tunnel_0123456789abcdef0123456789abcdef'
export PULPO_MCP_SNAPSHOT='/absolute/path/to/mcp-read-snapshot.json'
```

Then validate the complete local binding without starting the long-running poll
loop:

```text
pulpo-mcp-tunnel --doctor-only
```

If doctor succeeds, start the foreground daemon:

```text
pulpo-mcp-tunnel
```

The launcher creates an ephemeral `sample_mcp_stdio_local` profile whose MCP
command is exactly:

```text
python -m pulpo.mcp_plugin --snapshot <absolute-frozen-snapshot-path>
```

The runtime key remains referenced by `env:CONTROL_PLANE_API_KEY`; it is not
written into the generated profile or passed on a command line.

Because tunnel-client gives environment values precedence over named profiles,
the launcher removes ambient MCP/control-plane overrides before daemon startup.
It restores only the exact selected `CONTROL_PLANE_TUNNEL_ID` and runtime API
key, and removes `OPENAI_ADMIN_KEY`, `OPENAI_API_KEY`, alternate MCP bindings,
and alternate tunnel-client config/profile selectors from the child environment.
This prevents an inherited environment variable from silently changing the
reviewed transport path.

## ChatGPT side

After the tunnel daemon is healthy, configure a ChatGPT custom MCP connector
with **Connection: Tunnel** and select or paste the same tunnel ID. The tunnel
must be scoped to the intended ChatGPT workspace and the connector principal
must have Tunnels Read + Use.

First verification from ChatGPT should be read-only:

1. scan/discover tools;
2. confirm the discovered set is exactly `pulpo_get_evidence` and
   `pulpo_propose_intent`;
3. call `pulpo_get_evidence` and confirm `freshness=frozen`,
   `canonical_state_mutation=false`, `governed_effect=none`, and
   `authority_effect=none`;
4. call `pulpo_propose_intent` and confirm it returns no permit and causes no
   canonical mutation.

Do not classify ChatGPT production binding as Verified until those calls are
observed through the actual ChatGPT connector.

## Failure posture

The launcher fails closed before starting `tunnel-client` when:

- the tunnel ID is missing or does not exactly match the control-plane format;
- `CONTROL_PLANE_API_KEY` is missing;
- the snapshot path is not absolute;
- the existing Pulpo frozen-snapshot boundary rejects the file;
- the `tunnel-client` executable cannot be resolved;
- profile creation or `doctor --explain` fails.

For stdio tunnel bindings, run only one active tunnel-client process for a given
tunnel ID. Multiple active instances can route initialization and later calls to
different MCP child processes.

## Claim classification

**Verified previously:** Pulpo's admitted stdio MCP plugin installs and supports
real MCP discovery and tool calls in an isolated runtime.

**Proposed in this change:** the fail-closed Secure MCP Tunnel launcher and its
operator documentation.

**Unknown until live operator setup:** a real OpenAI tunnel ID, healthy tunnel
runtime from an operator-controlled host, ChatGPT connector discovery, and
ChatGPT-originated tool readback.

## Authority effect

`authority_effect=none`

`canonical_state_mutation=none`

`new_executor=none`

`new_router=none`

`new_ledger=none`

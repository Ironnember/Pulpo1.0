"""Capability-stripped Pulpo MCP server used by the Hermes runtime proof.

This process is deliberately built from a frozen primitive Pulpo snapshot. It
has no retained canonical kernel, orchestrator, state backend, authority client,
executor, permit consumer, or directive mutation route after construction.

The server exposes only the canonical non-mutating MCP projection:

- ``pulpo_propose_intent`` -- construct an ephemeral proposal;
- ``pulpo_get_evidence`` -- read frozen integrity metadata.

It is an intelligence/transport surface, not an authority source.
"""

from __future__ import annotations

from pathlib import Path
import sys


# Allow this experiment to run directly from a checked-out Pulpo repository
# without installing Pulpo into the Hermes environment.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pulpo import GovernanceKernel, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import create_mcp_server, freeze_mcp_snapshot


def build_server():
    """Build one capability-stripped MCP server from frozen Pulpo metadata."""

    kernel = GovernanceKernel(
        Policy(frozenset({"read"}), 0),
        secret=b"pulpo-hermes-governed-runtime-v0",
        clock=lambda: 2_000_000,
    )
    orchestrator = PulpoOrchestrator(kernel)
    snapshot = freeze_mcp_snapshot(orchestrator)

    # create_mcp_server receives only MCPReadSnapshot. The canonical kernel and
    # orchestrator remain local construction variables and are not retained by
    # the returned transport process.
    return create_mcp_server(snapshot)


def main() -> None:
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()

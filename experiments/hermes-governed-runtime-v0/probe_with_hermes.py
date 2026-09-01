"""Run the real Hermes MCP client against Pulpo's capability-stripped server.

This proof intentionally does not invoke a model. It exercises Hermes' actual
MCP configuration/probe path at a pinned upstream commit, so the first
interoperability test is deterministic and has zero model/API cost.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from hermes_cli.mcp_config import _probe_single_server


EXPECTED_TOOLS = {"pulpo_propose_intent", "pulpo_get_evidence"}
FORBIDDEN_AUTHORITY_TERMS = {
    "activate_directive",
    "revoke_directive",
    "authorize",
    "approval",
    "permit",
    "consume",
    "execute",
    "lock_target",
    "policy",
    "state",
}


def main() -> None:
    pulpo_root_raw = os.environ.get("PULPO_REPO_ROOT", "").strip()
    if not pulpo_root_raw:
        raise SystemExit("PULPO_REPO_ROOT is required")
    pulpo_root = Path(pulpo_root_raw).resolve()
    server_path = pulpo_root / "experiments" / "hermes-governed-runtime-v0" / "pulpo_mcp_server.py"
    if not server_path.is_file():
        raise SystemExit(f"Pulpo MCP proof server missing: {server_path}")

    server_config = {
        "command": sys.executable,
        "args": [str(server_path)],
        "connect_timeout": 30,
        "tools": {
            "include": sorted(EXPECTED_TOOLS),
            "prompts": False,
            "resources": False,
        },
    }

    discovered = _probe_single_server("pulpo", server_config, connect_timeout=30)
    names = {name for name, _description in discovered}

    if names != EXPECTED_TOOLS:
        raise AssertionError(
            f"Hermes discovered unexpected Pulpo MCP surface: expected={sorted(EXPECTED_TOOLS)!r} "
            f"actual={sorted(names)!r}"
        )

    normalized_names = {name.lower() for name in names}
    leaked = sorted(
        term
        for term in FORBIDDEN_AUTHORITY_TERMS
        if any(term in name for name in normalized_names)
    )
    if leaked:
        raise AssertionError(f"authority/execution-shaped MCP capability exposed: {leaked}")

    print(
        json.dumps(
            {
                "schema": "pulpo.hermes-mcp-compatibility-proof.v0",
                "hermes_mcp_client": "real",
                "model_invoked": False,
                "api_cost": 0,
                "discovered_tools": sorted(names),
                "authority_effect": "none",
                "governed_effect": "none",
                "canonical_state_mutation": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

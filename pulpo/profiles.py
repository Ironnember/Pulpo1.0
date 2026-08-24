"""Conservative starting profiles for Pulpo agents and external connectors."""

from __future__ import annotations

from dataclasses import dataclass

from .commerce import PILOT_PURCHASE_CEILING_CENTS
from .kernel import AgentGrant


ESSENTIAL_AGENT_GRANTS = (
    AgentGrant(
        principal="agent:planner",
        allowed_actions=frozenset({"read", "plan"}),
        resource_prefixes=("repo:", "docs:", "source:", "plugin:github:"),
        max_cost=10,
    ),
    AgentGrant(
        principal="agent:builder",
        allowed_actions=frozenset({"read", "write", "test"}),
        resource_prefixes=("repo:",),
        max_cost=50,
    ),
    AgentGrant(
        principal="agent:verifier",
        allowed_actions=frozenset({"read", "test", "verify"}),
        resource_prefixes=("repo:", "evidence:", "plugin:github:"),
        max_cost=20,
    ),
    AgentGrant(
        principal="agent:commerce",
        allowed_actions=frozenset({"purchase_domain"}),
        resource_prefixes=("commerce:domain:",),
        max_cost=PILOT_PURCHASE_CEILING_CENTS,
    ),
)


@dataclass(frozen=True)
class PluginProfile:
    """Planning metadata, not proof that an external plugin is connected."""

    plugin_id: str
    phase: str
    purpose: str
    resource_prefix: str
    write_requires_approval: bool = True


ESSENTIAL_PLUGIN_PROFILES = (
    PluginProfile(
        plugin_id="github",
        phase="current",
        purpose="canonical source, review, CI, and release evidence",
        resource_prefix="plugin:github:",
    ),
    PluginProfile(
        plugin_id="sentry",
        phase="next",
        purpose="runtime failures, traces, and regression evidence",
        resource_prefix="plugin:sentry:",
    ),
    PluginProfile(
        plugin_id="cloudflare",
        phase="deployment",
        purpose="edge policy, controlled ingress, and deployment boundary",
        resource_prefix="plugin:cloudflare:",
    ),
)

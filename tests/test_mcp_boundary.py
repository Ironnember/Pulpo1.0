import asyncio
import sys
import types
import unittest
from unittest.mock import patch

from pulpo import GovernanceKernel, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import MCPBoundaryError, PulpoMCPProjection, create_mcp_server


class FakeMCPServer:
    def __init__(self, name):
        self.name = name
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register


class MCPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=b"mcp-boundary-proof",
            clock=lambda: 2_000_000,
        )
        self.orchestrator = PulpoOrchestrator(self.kernel)
        self.projection = PulpoMCPProjection(self.orchestrator)

    def test_projection_rejects_parallel_state_clock_or_authority_injection(self):
        with self.assertRaises(TypeError):
            PulpoMCPProjection(self.orchestrator, object(), lambda: 2_000_000)
        with self.assertRaises(TypeError):
            self.projection.propose_intent(
                "target-1",
                "agent:builder",
                "write",
                "repo:file",
                authority="admin",
            )

    def test_mcp_proposal_locks_exact_intent_without_granting_authority(self):
        result = self.projection.propose_intent(
            "target-1",
            "agent:builder",
            "write",
            "repo:file",
            0,
            "session-1",
        )

        self.assertEqual("none", result["authority_effect"])
        self.assertNotIn("permit", result)
        self.assertEqual(64, len(result["target_hash"]))
        record = self.kernel.audit[-1]
        self.assertEqual("target_locked", record["event"])
        self.assertEqual("none", record["payload"]["authority_effect"])

        resolution, decision = self.kernel.evaluate_locked_target(
            result["target_id"],
            result["target_hash"],
            version=result["target_version"],
        )
        self.assertEqual("match", resolution.outcome)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))

    def test_target_substitution_and_invalid_payload_fail_closed(self):
        self.projection.propose_intent(
            "target-1",
            "agent:planner",
            "read",
            "repo:file",
        )
        with self.assertRaisesRegex(ValueError, "target version is immutable"):
            self.projection.propose_intent(
                "target-1",
                "agent:planner",
                "read",
                "repo:other",
            )
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_intent_invalid"):
            self.projection.propose_intent("target-2", "", "read", "repo:file")
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_intent_invalid"):
            self.projection.propose_intent("target-2", "agent:planner", "read", "repo:file", True)

    def test_evidence_tool_projects_the_existing_chain_only(self):
        self.projection.propose_intent(
            "target-1",
            "agent:planner",
            "read",
            "repo:file",
        )
        before = len(self.kernel.audit)
        evidence = self.projection.evidence_snapshot()

        self.assertTrue(evidence["audit_valid"])
        self.assertEqual(before, evidence["audit_records"])
        self.assertEqual(self.kernel.audit[-1]["hash"], evidence["audit_tip"])
        self.assertEqual(before, len(self.kernel.audit))
        self.assertEqual("none", evidence["authority_effect"])

    def test_sdk_factory_registers_only_non_authoritative_tools(self):
        mcp_package = types.ModuleType("mcp")
        mcp_server = types.ModuleType("mcp.server")
        mcp_server.MCPServer = FakeMCPServer
        mcp_package.server = mcp_server

        with patch.dict(sys.modules, {"mcp": mcp_package, "mcp.server": mcp_server}):
            server = create_mcp_server(self.orchestrator)

        self.assertEqual("pulpo", server.name)
        self.assertEqual(
            {"pulpo_propose_intent", "pulpo_get_evidence"},
            set(server.tools),
        )
        proposal = asyncio.run(
            server.tools["pulpo_propose_intent"](
                "target-1",
                "agent:planner",
                "read",
                "repo:file",
            )
        )
        self.assertEqual("none", proposal["authority_effect"])
        self.assertNotIn("permit", proposal)
        evidence = asyncio.run(server.tools["pulpo_get_evidence"]())
        self.assertTrue(evidence["audit_valid"])


if __name__ == "__main__":
    unittest.main()

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

    def test_mcp_proposal_is_ephemeral_and_cannot_mutate_canonical_state(self):
        before = list(self.kernel.audit)
        result = self.projection.propose_intent(
            "target-1",
            "agent:builder",
            "write",
            "repo:file",
            0,
            "session-1",
        )

        self.assertEqual("pulpo.mcp-proposal.v1", result["schema"])
        self.assertEqual("none", result["authority_effect"])
        self.assertEqual("none", result["governed_effect"])
        self.assertFalse(result["canonical_state_mutation"])
        self.assertNotIn("permit", result)
        self.assertNotIn("target_hash", result)
        self.assertEqual(
            {
                "principal": "agent:builder",
                "action": "write",
                "resource": "repo:file",
                "cost": 0,
                "session_id": "session-1",
            },
            result["intent"],
        )
        self.assertEqual(before, self.kernel.audit)
        self.assertIsNone(self.kernel.get_locked_target("target-1"))

    def test_repeated_or_changed_mcp_proposals_remain_non_mutating(self):
        first = self.projection.propose_intent(
            "target-1",
            "agent:planner",
            "read",
            "repo:file",
        )
        repeated = self.projection.propose_intent(
            "target-1",
            "agent:planner",
            "read",
            "repo:file",
        )
        changed = self.projection.propose_intent(
            "target-1",
            "agent:planner",
            "read",
            "repo:other",
        )

        self.assertEqual(first, repeated)
        self.assertNotEqual(first["intent_hash"], changed["intent_hash"])
        self.assertEqual([], self.kernel.audit)
        self.assertIsNone(self.kernel.get_locked_target("target-1"))

    def test_invalid_payload_fails_closed_without_state_change(self):
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_intent_invalid"):
            self.projection.propose_intent("target-2", "", "read", "repo:file")
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_intent_invalid"):
            self.projection.propose_intent("target-2", "agent:planner", "read", "repo:file", True)
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_target_invalid"):
            self.projection.propose_intent("", "agent:planner", "read", "repo:file")

        self.assertEqual([], self.kernel.audit)

    def test_evidence_tool_projects_the_existing_chain_only(self):
        before = len(self.kernel.audit)
        evidence = self.projection.evidence_snapshot()

        self.assertTrue(evidence["audit_valid"])
        self.assertEqual(before, evidence["audit_records"])
        self.assertIsNone(evidence["audit_tip"])
        self.assertEqual(before, len(self.kernel.audit))
        self.assertFalse(evidence["canonical_state_mutation"])
        self.assertEqual("none", evidence["governed_effect"])
        self.assertEqual("none", evidence["authority_effect"])

    def test_sdk_factory_registers_only_non_authoritative_non_mutating_tools(self):
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
        self.assertEqual("none", proposal["governed_effect"])
        self.assertFalse(proposal["canonical_state_mutation"])
        self.assertNotIn("permit", proposal)
        self.assertNotIn("target_hash", proposal)
        self.assertEqual([], self.kernel.audit)

        evidence = asyncio.run(server.tools["pulpo_get_evidence"]())
        self.assertTrue(evidence["audit_valid"])
        self.assertEqual([], self.kernel.audit)


if __name__ == "__main__":
    unittest.main()

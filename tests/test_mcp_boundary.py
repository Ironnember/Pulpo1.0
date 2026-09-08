import asyncio
from dataclasses import asdict
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from pulpo import GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import (
    MCPBoundaryError,
    MCPReadSnapshot,
    PulpoMCPProjection,
    create_mcp_server,
    export_mcp_snapshot,
    freeze_mcp_snapshot,
)


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
        self.snapshot = freeze_mcp_snapshot(self.orchestrator)
        self.projection = PulpoMCPProjection(self.snapshot)

    def test_projection_rejects_write_capable_dependency_or_authority_injection(self):
        with self.assertRaisesRegex(TypeError, "MCPReadSnapshot required"):
            PulpoMCPProjection(self.orchestrator)
        with self.assertRaisesRegex(TypeError, "MCPReadSnapshot required"):
            create_mcp_server(self.orchestrator)
        with self.assertRaises(TypeError):
            self.projection.propose_intent(
                "target-1",
                "agent:builder",
                "write",
                "repo:file",
                authority="admin",
            )

    def test_snapshot_contains_only_frozen_primitive_read_metadata(self):
        self.assertIs(type(self.snapshot), MCPReadSnapshot)
        self.assertFalse(hasattr(self.snapshot, "__dict__"))
        self.assertFalse(hasattr(self.snapshot, "orchestrator"))
        self.assertFalse(hasattr(self.snapshot, "kernel"))
        self.assertFalse(hasattr(self.projection, "orchestrator"))
        self.assertFalse(hasattr(self.projection, "kernel"))
        self.assertFalse(hasattr(self.projection, "__dict__"))

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

        self.assertEqual("pulpo.mcp-proposal.v2", result["schema"])
        self.assertEqual("frozen", result["freshness"])
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
        expected_intent = Intent("agent:builder", "write", "repo:file", 0, "session-1")
        self.assertEqual(GovernanceKernel.intent_hash(expected_intent), result["intent_hash"])
        self.assertEqual(self.snapshot.policy_hash, result["policy_hash"])
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

    def test_frozen_evidence_cannot_follow_later_canonical_mutation(self):
        evidence_before = self.projection.evidence_snapshot()
        self.assertEqual("pulpo.mcp-evidence.v1", evidence_before["schema"])
        self.assertEqual("frozen", evidence_before["freshness"])
        self.assertEqual(0, evidence_before["audit_records"])
        self.assertIsNone(evidence_before["audit_tip"])

        intent = Intent("agent:planner", "read", "repo:file", 0, "session-1")
        self.kernel.lock_target("canonical-target", intent)
        self.assertEqual(1, len(self.kernel.audit))

        evidence_after = self.projection.evidence_snapshot()
        self.assertEqual(evidence_before, evidence_after)
        self.assertEqual(0, evidence_after["audit_records"])
        self.assertIsNone(evidence_after["audit_tip"])
        self.assertFalse(evidence_after["canonical_state_mutation"])
        self.assertEqual("none", evidence_after["governed_effect"])
        self.assertEqual("none", evidence_after["authority_effect"])

    def test_trusted_export_is_exact_private_and_non_mutating(self):
        before = list(self.kernel.audit)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "mcp-read-snapshot.json"
            exported = export_mcp_snapshot(self.orchestrator, destination)
            document = json.loads(destination.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(destination.stat().st_mode)

        self.assertEqual(asdict(exported), document)
        self.assertEqual(
            {
                "schema",
                "source_schema",
                "policy_hash",
                "audit_valid",
                "audit_records",
                "audit_tip",
            },
            set(document),
        )
        self.assertEqual(0o600, mode)
        self.assertEqual(before, self.kernel.audit)
        for forbidden in (
            "authority",
            "credential",
            "executor",
            "kernel",
            "permit",
            "policy",
            "secret",
            "state",
        ):
            self.assertNotIn(forbidden, document)

    def test_exported_file_remains_frozen_after_canonical_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "mcp-read-snapshot.json"
            export_mcp_snapshot(self.orchestrator, destination)
            frozen = destination.read_bytes()

            self.kernel.lock_target(
                "canonical-target",
                Intent("agent:planner", "read", "repo:file", 0, "session-1"),
            )

            self.assertEqual(frozen, destination.read_bytes())
        self.assertEqual(1, len(self.kernel.audit))

    def test_export_rejects_relative_or_linked_destination(self):
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_snapshot_destination_not_absolute"):
            export_mcp_snapshot(self.orchestrator, Path("mcp-read-snapshot.json"))
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_snapshot_destination_invalid"):
            export_mcp_snapshot(self.orchestrator, Path("/"))
        with self.assertRaisesRegex(MCPBoundaryError, "mcp_snapshot_destination_invalid"):
            export_mcp_snapshot(self.orchestrator, "/tmp/snapshot\x00.json")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            protected = parent / "protected.json"
            protected.write_text("unchanged", encoding="utf-8")
            destination = parent / "mcp-read-snapshot.json"
            destination.symlink_to(protected)

            with self.assertRaisesRegex(MCPBoundaryError, "mcp_snapshot_destination_invalid"):
                export_mcp_snapshot(self.orchestrator, destination)

            self.assertEqual("unchanged", protected.read_text(encoding="utf-8"))
        self.assertEqual([], self.kernel.audit)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_export_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(MCPBoundaryError, "mcp_snapshot_parent_invalid"):
                export_mcp_snapshot(self.orchestrator, linked_parent / "snapshot.json")

            self.assertEqual([], list(real_parent.iterdir()))
        self.assertEqual([], self.kernel.audit)

    def test_export_rejects_parent_swapped_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "snapshot.json"
            opened_parent = types.SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_dev=-1,
                st_ino=-1,
            )

            with patch("pulpo.mcp_boundary.os.fstat", return_value=opened_parent):
                with self.assertRaisesRegex(MCPBoundaryError, "mcp_snapshot_parent_invalid"):
                    export_mcp_snapshot(self.orchestrator, destination)

            self.assertFalse(destination.exists())
        self.assertEqual([], self.kernel.audit)

    def test_sdk_factory_registers_only_capability_stripped_frozen_tools(self):
        mcp_package = types.ModuleType("mcp")
        mcp_server = types.ModuleType("mcp.server")
        mcp_server.MCPServer = FakeMCPServer
        mcp_package.server = mcp_server

        with patch.dict(sys.modules, {"mcp": mcp_package, "mcp.server": mcp_server}):
            server = create_mcp_server(self.snapshot)

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
        self.assertEqual("frozen", proposal["freshness"])
        self.assertEqual("none", proposal["authority_effect"])
        self.assertEqual("none", proposal["governed_effect"])
        self.assertFalse(proposal["canonical_state_mutation"])
        self.assertNotIn("permit", proposal)
        self.assertNotIn("target_hash", proposal)
        self.assertEqual([], self.kernel.audit)

        self.kernel.lock_target(
            "canonical-target",
            Intent("agent:planner", "read", "repo:file", 0, "session-1"),
        )
        evidence = asyncio.run(server.tools["pulpo_get_evidence"]())
        self.assertTrue(evidence["audit_valid"])
        self.assertEqual("frozen", evidence["freshness"])
        self.assertEqual(0, evidence["audit_records"])
        self.assertEqual(1, len(self.kernel.audit))


if __name__ == "__main__":
    unittest.main()

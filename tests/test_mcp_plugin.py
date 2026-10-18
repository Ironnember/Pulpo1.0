import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pulpo.mcp_boundary import MCPBoundaryError, MCPReadSnapshot
from pulpo.mcp_plugin import load_mcp_snapshot, main


class FakeRunnableServer:
    def __init__(self):
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)


class MCPPluginTests(unittest.TestCase):
    @staticmethod
    def snapshot_document():
        return {
            "policy_hash": "a" * 64,
            "audit_valid": True,
            "audit_records": 3,
            "audit_tip": "b" * 64,
            "source_schema": "pulpo.orchestration-evidence.v0",
            "schema": "pulpo.mcp-read-snapshot.v0",
        }

    @staticmethod
    def write_snapshot(path: Path, document=None, mode=0o600):
        if document is None:
            document = MCPPluginTests.snapshot_document()
        path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        if os.name == "posix":
            path.chmod(mode)

    def test_loads_exact_private_frozen_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mcp-read-snapshot.json"
            self.write_snapshot(path)
            snapshot = load_mcp_snapshot(path)

        self.assertIs(type(snapshot), MCPReadSnapshot)
        self.assertEqual("a" * 64, snapshot.policy_hash)
        self.assertTrue(snapshot.audit_valid)
        self.assertEqual(3, snapshot.audit_records)
        self.assertEqual("b" * 64, snapshot.audit_tip)

    def test_rejects_relative_path_and_symlinked_parent_or_file(self):
        with self.assertRaisesRegex(
            MCPBoundaryError,
            "mcp_plugin_snapshot_path_invalid",
        ):
            load_mcp_snapshot("mcp-read-snapshot.json")

        if not hasattr(os, "symlink"):
            return
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            path = real_parent / "mcp-read-snapshot.json"
            self.write_snapshot(path)

            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(
                MCPBoundaryError,
                "mcp_plugin_snapshot_parent_invalid",
            ):
                load_mcp_snapshot(linked_parent / path.name)

            linked_file = real_parent / "linked.json"
            linked_file.symlink_to(path)
            with self.assertRaisesRegex(
                MCPBoundaryError,
                "mcp_plugin_snapshot_open_failed",
            ):
                load_mcp_snapshot(linked_file)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits required")
    def test_rejects_snapshot_readable_by_group_or_world(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mcp-read-snapshot.json"
            self.write_snapshot(path, mode=0o644)
            with self.assertRaisesRegex(
                MCPBoundaryError,
                "mcp_plugin_snapshot_permissions_invalid",
            ):
                load_mcp_snapshot(path)

    def test_rejects_extra_missing_invalid_or_duplicate_snapshot_fields(self):
        variants = []

        extra = self.snapshot_document()
        extra["authority"] = "admin"
        variants.append(json.dumps(extra))

        missing = self.snapshot_document()
        del missing["policy_hash"]
        variants.append(json.dumps(missing))

        malformed_hash = self.snapshot_document()
        malformed_hash["policy_hash"] = "not-a-hash"
        variants.append(json.dumps(malformed_hash))

        valid = self.snapshot_document()
        duplicate = json.dumps(valid)[:-1] + ',"policy_hash":"' + ("c" * 64) + '"}'
        variants.append(duplicate)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mcp-read-snapshot.json"
            for raw in variants:
                path.write_text(raw + "\n", encoding="utf-8")
                if os.name == "posix":
                    path.chmod(0o600)
                with self.assertRaisesRegex(
                    MCPBoundaryError,
                    "mcp_plugin_snapshot_invalid",
                ):
                    load_mcp_snapshot(path)

    def test_main_runs_existing_mcp_server_over_stdio_only(self):
        snapshot = MCPReadSnapshot(**self.snapshot_document())
        server = FakeRunnableServer()
        with patch(
            "pulpo.mcp_plugin.load_mcp_snapshot",
            return_value=snapshot,
        ) as loader, patch(
            "pulpo.mcp_plugin.create_mcp_server",
            return_value=server,
        ) as factory:
            result = main(["--snapshot", "/tmp/pulpo-snapshot.json"])

        self.assertEqual(0, result)
        loader.assert_called_once_with("/tmp/pulpo-snapshot.json")
        factory.assert_called_once_with(snapshot)
        self.assertEqual([{"transport": "stdio"}], server.calls)

    def test_portable_plugin_manifest_and_stdio_config(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "plugin.json").read_text(encoding="utf-8"))
        mcp_config = json.loads((root / "mcp.json").read_text(encoding="utf-8"))

        self.assertEqual(
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            manifest["$schema"],
        )
        self.assertEqual("pulpo", manifest["name"])
        self.assertIn("Read-only", manifest["description"])
        self.assertNotIn("extensions", manifest)

        self.assertEqual(
            "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            mcp_config["$schema"],
        )
        self.assertEqual(
            {
                "type": "stdio",
                "command": "python3",
                "args": [
                    "-m",
                    "pulpo.mcp_plugin",
                    "--snapshot",
                    "${PLUGIN_DATA}/mcp-read-snapshot.json",
                ],
                "cwd": "${PLUGIN_ROOT}",
            },
            mcp_config["mcpServers"]["pulpo"],
        )


if __name__ == "__main__":
    unittest.main()

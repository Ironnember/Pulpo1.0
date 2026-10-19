import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pulpo.mcp_tunnel import (
    MCPTunnelBindingError,
    build_stdio_command,
    run_secure_tunnel,
    validate_tunnel_id,
)


VALID_TUNNEL_ID = "tunnel_0123456789abcdef0123456789abcdef"


class MCPTunnelBindingTests(unittest.TestCase):
    @staticmethod
    def write_snapshot(path: Path) -> None:
        path.write_text(
            '{"audit_records":0,"audit_tip":null,"audit_valid":true,'
            '"policy_hash":"' + ("a" * 64) + '",'
            '"schema":"pulpo.mcp-read-snapshot.v0",'
            '"source_schema":"pulpo.orchestration-evidence.v0"}\n',
            encoding="utf-8",
        )
        if os.name == "posix":
            path.chmod(0o600)

    def test_tunnel_id_matches_control_plane_contract_exactly(self):
        self.assertEqual(VALID_TUNNEL_ID, validate_tunnel_id(VALID_TUNNEL_ID))
        invalid = (
            None,
            "",
            " " + VALID_TUNNEL_ID,
            "bad",
            "tunnel_0123456789abcdef",
            "tunnel_0123456789abcdef0123456789abcde",
            "tunnel_0123456789abcdef0123456789abcdef0",
            "tunnel_0123456789ABCDEF0123456789ABCDEF",
            "tunnel_0123456789abcdef0123456789abcdeg",
            "tunnel_0123456789abcdef-123456789abcdef",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(MCPTunnelBindingError):
                    validate_tunnel_id(value)

    def test_stdio_command_targets_only_existing_projection(self):
        command = build_stdio_command(
            "/tmp/pulpo data/mcp-read-snapshot.json",
            python_executable="/usr/bin/python3",
        )
        self.assertIn("/usr/bin/python3", command)
        self.assertIn("pulpo.mcp_plugin", command)
        self.assertIn("--snapshot", command)
        self.assertIn("mcp-read-snapshot.json", command)
        self.assertNotIn("authority", command)
        self.assertNotIn("executor", command)
        self.assertNotIn("permit", command)

    def test_binding_fails_closed_without_runtime_key(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "mcp-read-snapshot.json"
            self.write_snapshot(snapshot)
            with patch(
                "pulpo.mcp_tunnel.resolve_tunnel_client",
                return_value="/usr/local/bin/tunnel-client",
            ):
                with self.assertRaisesRegex(
                    MCPTunnelBindingError,
                    "pulpo_tunnel_runtime_key_missing",
                ):
                    run_secure_tunnel(
                        tunnel_id=VALID_TUNNEL_ID,
                        snapshot_path=snapshot,
                        doctor_only=True,
                        env={},
                    )

    def test_binding_uses_exact_tunnel_and_sanitized_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "mcp-read-snapshot.json"
            self.write_snapshot(snapshot)
            calls = []

            def fake_run(args, **kwargs):
                calls.append((list(args), kwargs))

                class Completed:
                    returncode = 0

                return Completed()

            with patch(
                "pulpo.mcp_tunnel.resolve_tunnel_client",
                return_value="/usr/local/bin/tunnel-client",
            ), patch(
                "pulpo.mcp_tunnel.subprocess.run",
                side_effect=fake_run,
            ):
                result = run_secure_tunnel(
                    tunnel_id=VALID_TUNNEL_ID,
                    snapshot_path=snapshot,
                    doctor_only=True,
                    env={
                        "CONTROL_PLANE_API_KEY": "secret-runtime-key",
                        "CONTROL_PLANE_TUNNEL_ID": "tunnel_ffffffffffffffffffffffffffffffff",
                        "CONTROL_PLANE_BASE_URL": "https://example.invalid",
                        "MCP_COMMAND": "dangerous-command",
                        "MCP_SERVER_URL": "https://example.invalid/mcp",
                        "OPENAI_ADMIN_KEY": "admin-secret",
                        "OPENAI_API_KEY": "fallback-secret",
                        "TUNNEL_CLIENT_CONFIG": "/tmp/untrusted.yaml",
                        "PATH": "/usr/bin",
                    },
                )

        self.assertEqual(0, result)
        self.assertEqual(2, len(calls))
        init_args, init_kwargs = calls[0]
        doctor_args, doctor_kwargs = calls[1]

        self.assertEqual("init", init_args[1])
        self.assertIn("sample_mcp_stdio_local", init_args)
        self.assertIn("--tunnel-id", init_args)
        self.assertIn(VALID_TUNNEL_ID, init_args)
        self.assertIn("--mcp-command", init_args)
        self.assertIn("pulpo.mcp_plugin", " ".join(init_args))
        self.assertNotIn("secret-runtime-key", " ".join(init_args))
        self.assertNotIn("admin-secret", " ".join(init_args))
        self.assertTrue(init_kwargs["check"])

        self.assertEqual(
            [
                "/usr/local/bin/tunnel-client",
                "doctor",
                "--profile",
                "pulpo-local-stdio",
                "--explain",
            ],
            doctor_args,
        )
        runtime_env = doctor_kwargs["env"]
        self.assertEqual("secret-runtime-key", runtime_env["CONTROL_PLANE_API_KEY"])
        self.assertEqual(VALID_TUNNEL_ID, runtime_env["CONTROL_PLANE_TUNNEL_ID"])
        self.assertEqual("/usr/bin", runtime_env["PATH"])
        self.assertIn("TUNNEL_CLIENT_PROFILE_DIR", runtime_env)
        self.assertNotEqual("", runtime_env["TUNNEL_CLIENT_PROFILE_DIR"])
        for forbidden in (
            "CONTROL_PLANE_BASE_URL",
            "MCP_COMMAND",
            "MCP_SERVER_URL",
            "OPENAI_ADMIN_KEY",
            "OPENAI_API_KEY",
            "TUNNEL_CLIENT_CONFIG",
        ):
            self.assertNotIn(forbidden, runtime_env)

    def test_binding_rejects_snapshot_before_transport_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "mcp-read-snapshot.json"
            self.write_snapshot(snapshot)
            if os.name == "posix":
                snapshot.chmod(0o644)

            with patch("pulpo.mcp_tunnel.subprocess.run") as runner:
                with self.assertRaises(Exception):
                    run_secure_tunnel(
                        tunnel_id=VALID_TUNNEL_ID,
                        snapshot_path=snapshot,
                        doctor_only=True,
                        env={"CONTROL_PLANE_API_KEY": "secret-runtime-key"},
                    )
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()

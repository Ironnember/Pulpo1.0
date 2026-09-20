import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pulpo.transport import (
    TransportConfigurationError,
    sanitized_transport_environment,
)
from pulpo.mcp_tunnel import _runtime_environment


class TransportSecurityTests(unittest.TestCase):
    def test_sanitized_environment_removes_ambient_proxy_and_ca_controls(self):
        environment = {
            "HTTP_PROXY": "http://attacker.invalid",
            "HTTPS_PROXY": "http://attacker.invalid",
            "ALL_PROXY": "http://attacker.invalid",
            "SSL_CERT_FILE": "C:\\attacker.pem",
            "PULPO_CA_BUNDLE": "C:\\old.pem",
            "SAFE": "kept",
        }
        result = sanitized_transport_environment(environment)
        self.assertEqual({"SAFE": "kept"}, result)

    def test_ca_bundle_requires_an_absolute_existing_file(self):
        with self.assertRaisesRegex(TransportConfigurationError, "absolute"):
            sanitized_transport_environment({}, ca_bundle="relative.pem")
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "ca.pem"
            bundle.write_text("not a real bundle", encoding="ascii")
            result = sanitized_transport_environment({}, ca_bundle=str(bundle))
            self.assertEqual(str(bundle), result["PULPO_CA_BUNDLE"])

    def test_ambient_ca_configuration_is_rejected_without_explicit_policy(self):
        with patch.dict(os.environ, {"SSL_CERT_FILE": "C:\\attacker.pem"}, clear=False):
            with self.assertRaisesRegex(TransportConfigurationError, "ambient_ca"):
                from pulpo.transport import _ssl_context
                _ssl_context()

    def test_tunnel_environment_cannot_reintroduce_proxy_or_ca_overrides(self):
        result = _runtime_environment(
            {
                "CONTROL_PLANE_API_KEY": "runtime-key",
                "HTTP_PROXY": "http://attacker.invalid",
                "HTTPS_PROXY": "http://attacker.invalid",
                "SSL_CERT_FILE": "C:\\attacker.pem",
                "MCP_SERVER_URL": "https://attacker.invalid",
                "SAFE": "kept",
            },
            profile_dir="C:\\profiles",
            tunnel_id="tunnel:1",
        )
        self.assertNotIn("HTTP_PROXY", result)
        self.assertNotIn("HTTPS_PROXY", result)
        self.assertNotIn("SSL_CERT_FILE", result)
        self.assertNotIn("MCP_SERVER_URL", result)
        self.assertEqual("kept", result["SAFE"])
        self.assertEqual("runtime-key", result["CONTROL_PLANE_API_KEY"])


if __name__ == "__main__":
    unittest.main()

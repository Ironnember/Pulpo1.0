from __future__ import annotations

from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prepare_hardware_enrollment.py"
SPEC = importlib.util.spec_from_file_location("prepare_hardware_enrollment", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HardwareEnrollmentPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.cert = self.root / "authority.crt"
        self.key = self.root / "authority.key"
        self.cert.write_text("certificate\n")
        self.key.write_text("private-key-placeholder\n")
        self.output = self.root / "bundle"
        self.token = "one-time-bootstrap-token-v0"

    def tearDown(self):
        self.temporary.cleanup()

    def _prepare(self, **changes):
        values = {
            "output_dir": self.output,
            "tls_cert_path": self.cert,
            "tls_key_path": self.key,
            "origin": "https://authority.pulpo.ai:8443",
            "rp_id": "authority.pulpo.ai",
            "role": "primary",
            "ttl_seconds": 300,
            "token_factory": lambda _: self.token,
        }
        values.update(changes)
        return MODULE.prepare(**values)

    def test_preparation_separates_raw_token_from_server_environment(self):
        result = self._prepare()
        token_path = Path(result["token_path"])
        env_path = Path(result["environment_path"])
        url_path = Path(result["browser_url_path"])
        launch_path = Path(result["launch_path"])

        self.assertEqual(self.token + "\n", token_path.read_text())
        self.assertIn("#token=" + self.token, url_path.read_text())
        self.assertNotIn(self.token, env_path.read_text())
        self.assertNotIn(self.token, launch_path.read_text())
        self.assertIn(sha256(self.token.encode()).hexdigest(), env_path.read_text())
        self.assertEqual(0o600, stat.S_IMODE(token_path.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(env_path.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(url_path.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(launch_path.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(self.output.stat().st_mode))
        self.assertFalse(result["raw_token_printed"])
        self.assertFalse(result["dns_or_hosts_changed"])
        self.assertFalse(result["trust_store_changed"])
        self.assertFalse(result["candidate_admitted"])
        self.assertEqual("none", result["authority_effect"])

    def test_preparation_is_create_only(self):
        self._prepare()
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "must be empty"):
            self._prepare()
        self.assertEqual(self.token + "\n", (self.output / "bootstrap-token.txt").read_text())

    def test_origin_rp_and_ttl_are_locked(self):
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "HTTPS"):
            self._prepare(origin="http://authority.pulpo.ai:8443")
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "equal or be below"):
            self._prepare(origin="https://attacker.example:8443")
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "outside the allowed range"):
            self._prepare(ttl_seconds=601)

    def test_paths_must_be_absolute_and_tls_files_must_exist(self):
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "absolute"):
            MODULE.prepare(
                output_dir=Path("relative"),
                tls_cert_path=self.cert,
                tls_key_path=self.key,
                token_factory=lambda _: self.token,
            )
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "unavailable"):
            self._prepare(tls_cert_path=self.root / "missing.crt")

    def test_symlink_secret_path_is_rejected(self):
        link = self.root / "cert-link"
        os.symlink(self.cert, link)
        with self.assertRaisesRegex(MODULE.PreparationBlocked, "symlink"):
            self._prepare(tls_cert_path=link)


if __name__ == "__main__":
    unittest.main()

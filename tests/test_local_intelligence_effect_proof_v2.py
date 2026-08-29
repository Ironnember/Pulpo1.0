from pathlib import Path
import os
import tempfile
import unittest

from scripts.run_local_intelligence_effect_proof import sanitize_environment
from scripts.run_local_intelligence_effect_proof_v2 import (
    prepare_runtime_codex_home,
    v2_profile_binding,
)


class LocalIntelligenceEffectProofV2Tests(unittest.TestCase):
    def test_disposable_codex_home_is_inside_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            disposable, projection, mode = prepare_runtime_codex_home(real, runtime)
            self.assertEqual(disposable.parent, runtime.resolve())
            self.assertIsNone(projection)
            self.assertEqual(mode, "none")

    def test_auth_json_is_projected_without_copying_secret_material(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            auth = real / "auth.json"
            auth.write_text('{"token":"secret"}', encoding="utf-8")
            disposable, projection, mode = prepare_runtime_codex_home(real, runtime)
            self.assertIsNotNone(projection)
            assert projection is not None
            self.assertTrue(projection.is_symlink())
            self.assertEqual(Path(os.readlink(projection)), auth.resolve())
            self.assertEqual(mode, "symlink-readonly-target")
            self.assertEqual(disposable, runtime.resolve() / "codex-home")

    def test_environment_pins_child_to_disposable_home_and_drops_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "runtime"
            disposable = runtime / "codex-home"
            runtime.mkdir()
            disposable.mkdir()
            env = sanitize_environment(
                {
                    "HOME": "/Users/test",
                    "PATH": "/bin",
                    "OPENAI_API_KEY": "secret",
                    "AWS_SECRET_ACCESS_KEY": "secret2",
                },
                runtime,
                codex_home=disposable,
            )
            self.assertEqual(env["CODEX_HOME"], str(disposable))
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)

    def test_profile_binding_changes_when_runtime_home_changes(self):
        common = dict(
            codex_sha256="a" * 64,
            seatbelt_sha256="b" * 64,
            seatbelt_profile_sha256="c" * 64,
            real_codex_home=Path("/real/.codex"),
            auth_projection_mode="symlink-readonly-target",
        )
        one = v2_profile_binding(runtime_codex_home=Path("/tmp/one/codex-home"), **common)
        two = v2_profile_binding(runtime_codex_home=Path("/tmp/two/codex-home"), **common)
        self.assertNotEqual(one, two)

    def test_profile_binding_changes_when_real_home_or_projection_changes(self):
        base = dict(
            codex_sha256="a" * 64,
            seatbelt_sha256="b" * 64,
            seatbelt_profile_sha256="c" * 64,
            runtime_codex_home=Path("/tmp/runtime/codex-home"),
        )
        one = v2_profile_binding(
            real_codex_home=Path("/real/a/.codex"),
            auth_projection_mode="symlink-readonly-target",
            **base,
        )
        two = v2_profile_binding(
            real_codex_home=Path("/real/b/.codex"),
            auth_projection_mode="symlink-readonly-target",
            **base,
        )
        three = v2_profile_binding(
            real_codex_home=Path("/real/a/.codex"),
            auth_projection_mode="none",
            **base,
        )
        self.assertNotEqual(one, two)
        self.assertNotEqual(one, three)


if __name__ == "__main__":
    unittest.main()

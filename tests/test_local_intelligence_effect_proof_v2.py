from pathlib import Path
import tempfile
import unittest

from scripts.run_local_intelligence_effect_proof import sanitize_environment
from scripts.run_local_intelligence_effect_proof_v2 import (
    AUTH_PROJECTION_MODE,
    OBSERVER_MODE,
    REAL_CODEX_READ_MODE,
    build_v2_seatbelt_profile,
    prepare_runtime_codex_home,
    stage_runtime_auth_copy,
    v2_profile_binding,
    v2_surfaces,
)


class LocalIntelligenceEffectProofV2Tests(unittest.TestCase):
    def test_disposable_codex_home_is_inside_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            disposable, auth_source, auth_sha, mode = prepare_runtime_codex_home(real, runtime)
            self.assertEqual(disposable.parent, runtime.resolve())
            self.assertIsNone(auth_source)
            self.assertIsNone(auth_sha)
            self.assertEqual(mode, "none")

    def test_prepare_binds_auth_hash_without_copying_secret_material(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            auth = real / "auth.json"
            auth.write_text('{"token":"secret"}', encoding="utf-8")
            disposable, auth_source, auth_sha, mode = prepare_runtime_codex_home(real, runtime)
            self.assertEqual(disposable, runtime.resolve() / "codex-home")
            self.assertEqual(auth_source, auth.resolve())
            self.assertIsNotNone(auth_sha)
            self.assertEqual(mode, AUTH_PROJECTION_MODE)
            self.assertFalse((disposable / "auth.json").exists())

    def test_prepare_rejects_symlinked_auth_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            outside = root / "outside-auth.json"
            outside.write_text('{"token":"secret"}', encoding="utf-8")
            (real / "auth.json").symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "auth_source_symlink_rejected"):
                prepare_runtime_codex_home(real, runtime)

    def test_fire_stages_private_auth_copy_inside_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            auth = real / "auth.json"
            auth.write_text('{"token":"secret"}', encoding="utf-8")
            disposable, auth_source, auth_sha, _ = prepare_runtime_codex_home(real, runtime)
            staged = stage_runtime_auth_copy(auth_source, auth_sha, disposable)
            self.assertIsNotNone(staged)
            assert staged is not None
            self.assertEqual(staged.parent, disposable)
            self.assertFalse(staged.is_symlink())
            self.assertEqual(staged.read_text(encoding="utf-8"), auth.read_text(encoding="utf-8"))
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            staged.unlink()

    def test_fire_rejects_auth_source_change_after_prepare(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            auth = real / "auth.json"
            auth.write_text('{"token":"one"}', encoding="utf-8")
            disposable, auth_source, auth_sha, _ = prepare_runtime_codex_home(real, runtime)
            auth.write_text('{"token":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "auth_source_changed_after_prepare"):
                stage_runtime_auth_copy(auth_source, auth_sha, disposable)

    def test_fire_rejects_auth_source_replaced_by_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real-codex"
            runtime = root / "runtime"
            real.mkdir()
            runtime.mkdir()
            auth = real / "auth.json"
            auth.write_text('{"token":"one"}', encoding="utf-8")
            disposable, auth_source, auth_sha, _ = prepare_runtime_codex_home(real, runtime)
            outside = root / "outside-auth.json"
            outside.write_text('{"token":"one"}', encoding="utf-8")
            auth.unlink()
            auth.symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "auth_source_symlink_rejected"):
                stage_runtime_auth_copy(auth_source, auth_sha, disposable)

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

    def test_v2_profile_denies_worker_reads_from_real_codex_home(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "runtime"
            pulpo = root / ".pulpo"
            ssh = root / ".ssh"
            real = root / ".codex"
            for path in (runtime, pulpo, ssh, real):
                path.mkdir()
            profile = build_v2_seatbelt_profile(
                runtime,
                pulpo_home=pulpo,
                ssh_home=ssh,
                real_codex_home=real,
            )
            self.assertIn(f'(deny file-read* (subpath "{real.resolve()}"))', profile)

    def test_v2_surfaces_observe_exact_auth_not_real_codex_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            control = root / "control"
            target = root / "target"
            pulpo = root / ".pulpo"
            runtime = root / "runtime"
            real = root / ".codex"
            for path in (control, target, pulpo, runtime, real):
                path.mkdir()
            auth = real / "auth.json"
            auth.write_text('{"token":"secret"}', encoding="utf-8")
            surfaces = v2_surfaces(
                control_root=control,
                target_worktree=target,
                pulpo_home=pulpo,
                runtime_root=runtime,
                auth_source=auth.resolve(),
            )
            roots = {surface.root: surface.role for surface in surfaces}
            self.assertEqual(roots[str(auth.resolve())], "protected")
            self.assertNotIn(str(real.resolve()), roots)
            self.assertEqual(roots[str(runtime.resolve())], "writable")

    def test_profile_binding_changes_when_runtime_home_changes(self):
        common = dict(
            codex_sha256="a" * 64,
            seatbelt_sha256="b" * 64,
            seatbelt_profile_sha256="c" * 64,
            real_codex_home=Path("/real/.codex"),
            auth_projection_mode=AUTH_PROJECTION_MODE,
            auth_source_sha256="d" * 64,
        )
        one = v2_profile_binding(runtime_codex_home=Path("/tmp/one/codex-home"), **common)
        two = v2_profile_binding(runtime_codex_home=Path("/tmp/two/codex-home"), **common)
        self.assertNotEqual(one, two)
        self.assertIn(f"observer_mode={OBSERVER_MODE}", one)
        self.assertIn(f"real_codex_read={REAL_CODEX_READ_MODE}", one)

    def test_profile_binding_changes_when_real_home_projection_or_auth_hash_changes(self):
        base = dict(
            codex_sha256="a" * 64,
            seatbelt_sha256="b" * 64,
            seatbelt_profile_sha256="c" * 64,
            runtime_codex_home=Path("/tmp/runtime/codex-home"),
        )
        one = v2_profile_binding(
            real_codex_home=Path("/real/a/.codex"),
            auth_projection_mode=AUTH_PROJECTION_MODE,
            auth_source_sha256="d" * 64,
            **base,
        )
        two = v2_profile_binding(
            real_codex_home=Path("/real/b/.codex"),
            auth_projection_mode=AUTH_PROJECTION_MODE,
            auth_source_sha256="d" * 64,
            **base,
        )
        three = v2_profile_binding(
            real_codex_home=Path("/real/a/.codex"),
            auth_projection_mode="none",
            auth_source_sha256=None,
            **base,
        )
        four = v2_profile_binding(
            real_codex_home=Path("/real/a/.codex"),
            auth_projection_mode=AUTH_PROJECTION_MODE,
            auth_source_sha256="e" * 64,
            **base,
        )
        self.assertNotEqual(one, two)
        self.assertNotEqual(one, three)
        self.assertNotEqual(one, four)


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
import tempfile
import unittest

from pulpo.effect_reconcile import EffectEnvelope, SurfaceSpec
from scripts.run_local_intelligence_effect_proof import (
    build_codex_argv,
    build_seatbelt_profile,
    envelope_from_dict,
    envelope_to_dict,
    freeze_plan,
    overall_pass,
    profile_binding,
    sanitize_environment,
    verify_plan_hash,
)


class LocalIntelligenceEffectProofScriptTests(unittest.TestCase):
    def test_seatbelt_denies_global_writes_and_allows_only_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "runtime"
            runtime.mkdir()
            protected = root / "protected"
            protected.mkdir()
            profile = build_seatbelt_profile(runtime, (protected,))
            self.assertIn("(deny file-write*)", profile)
            self.assertIn(f'(allow file-write* (subpath "{runtime.resolve()}"))', profile)
            self.assertIn(f'(deny file-read* (subpath "{protected.resolve()}"))', profile)

    def test_codex_exec_argv_freezes_ephemeral_readonly_update_and_hook_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex = root / "codex"
            worktree = root / "worktree"
            runtime = root / "runtime"
            argv = build_codex_argv(codex, worktree, runtime, "read only")
            joined = " ".join(argv)
            self.assertIn("exec", argv)
            self.assertIn("--ephemeral", argv)
            self.assertIn("--ignore-user-config", argv)
            self.assertIn("--ignore-rules", argv)
            self.assertIn("--strict-config", argv)
            self.assertIn("--sandbox read-only", joined)
            self.assertIn("check_for_update_on_startup=false", argv)
            self.assertIn("features.hooks=false", argv)
            self.assertIn('approval_policy="on-request"', argv)
            self.assertIn('web_search="disabled"', argv)
            self.assertTrue(any(item.startswith("log_dir=") for item in argv))
            self.assertTrue(any(item.startswith("sqlite_home=") for item in argv))

    def test_environment_drops_secret_like_variables_and_pins_codex_home(self):
        env = sanitize_environment(
            {"HOME": "/home/test", "PATH": "/bin", "OPENAI_API_KEY": "secret", "AWS_SECRET_ACCESS_KEY": "secret2"},
            Path("/tmp/runtime"),
            codex_home=Path("/home/test/.codex"),
        )
        self.assertEqual(env["HOME"], "/home/test")
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["TMPDIR"], "/tmp/runtime")
        self.assertEqual(env["CODEX_HOME"], "/home/test/.codex")
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)

    def test_profile_binding_changes_for_any_containment_identity_change(self):
        one = profile_binding(codex_sha256="a" * 64, seatbelt_sha256="b" * 64, seatbelt_profile_sha256="c" * 64)
        two = profile_binding(codex_sha256="d" * 64, seatbelt_sha256="b" * 64, seatbelt_profile_sha256="c" * 64)
        three = profile_binding(codex_sha256="a" * 64, seatbelt_sha256="e" * 64, seatbelt_profile_sha256="c" * 64)
        four = profile_binding(codex_sha256="a" * 64, seatbelt_sha256="b" * 64, seatbelt_profile_sha256="f" * 64)
        self.assertNotEqual(one, two)
        self.assertNotEqual(one, three)
        self.assertNotEqual(one, four)

    def test_overall_pass_requires_execution_reconciliation_replay_and_audit(self):
        self.assertTrue(overall_pass(exit_code=0, timed_out=False, reconciliation_status="verified", replay_denied=True, audit_valid=True))
        self.assertFalse(overall_pass(exit_code=1, timed_out=False, reconciliation_status="verified", replay_denied=True, audit_valid=True))
        self.assertFalse(overall_pass(exit_code=0, timed_out=True, reconciliation_status="verified", replay_denied=True, audit_valid=True))
        self.assertFalse(overall_pass(exit_code=0, timed_out=False, reconciliation_status="mismatch", replay_denied=True, audit_valid=True))
        self.assertFalse(overall_pass(exit_code=0, timed_out=False, reconciliation_status="verified", replay_denied=False, audit_valid=True))
        self.assertFalse(overall_pass(exit_code=0, timed_out=False, reconciliation_status="verified", replay_denied=True, audit_valid=False))

    def test_envelope_plan_roundtrip_preserves_exact_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "sandbox-exec"
            worktree = root / "target"
            runtime = root / "runtime"
            executable.write_bytes(b"seatbelt")
            worktree.mkdir()
            runtime.mkdir()
            envelope = EffectEnvelope(
                executable_path=str(executable),
                executable_sha256="a" * 64,
                argv=(str(executable), "-f", str(root / "control" / "seatbelt.sb"), "codex"),
                workdir=str(worktree),
                source_sha="deadbeef",
                profile="proof",
                expires_at_ns=100,
                surfaces=(
                    SurfaceSpec(str(worktree), "protected"),
                    SurfaceSpec(str(runtime), "writable"),
                ),
            )
            restored = envelope_from_dict(envelope_to_dict(envelope))
            self.assertEqual(restored.envelope_hash, envelope.envelope_hash)
            self.assertEqual(restored.argv, envelope.argv)

    def test_plan_hash_fails_if_any_frozen_field_changes(self):
        plan = freeze_plan({"schema": "x", "effect_envelope_hash": "a" * 64, "target_sha": "abc"})
        self.assertTrue(verify_plan_hash(plan))
        plan["target_sha"] = "def"
        self.assertFalse(verify_plan_hash(plan))


if __name__ == "__main__":
    unittest.main()

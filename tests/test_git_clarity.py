import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from pulpo.git_clarity import (
    GitClarityError,
    collect_git_clarity,
    main,
    verify_git_clarity,
)


REPOSITORY_IDENTITY = "github.com/Ironnember/Pulpo1.0"


class GitClarityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pulpo-git-clarity-")
        self.repository = Path(self.temporary.name) / "Pulpo1.0"
        self.repository.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Pulpo Test")
        self.git("config", "user.email", "pulpo@example.invalid")
        self.git("remote", "add", "origin", "https://github.com/Ironnember/Pulpo1.0.git")
        self.commit("README.md", "canonical\n", "canonical")

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", *args],
            cwd=self.repository,
            check=check,
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )

    def commit(self, path, content, subject):
        target = self.repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.git("add", path)
        self.git("commit", "-m", subject)

    def collect(self, **kwargs):
        return collect_git_clarity(
            self.repository,
            canonical_ref="refs/heads/main",
            expected_repository=REPOSITORY_IDENTITY,
            **kwargs,
        )

    def test_clean_canonical_report_is_deterministic_and_self_verifying(self):
        first = self.collect()
        second = self.collect()
        self.assertEqual(first, second)
        self.assertTrue(verify_git_clarity(first))
        self.assertEqual("canonical_commit_clean", first["classification"])
        self.assertEqual("at_canonical", first["source"]["relationship"])
        self.assertEqual([], first["proposal"]["commits"])
        self.assertTrue(first["worktree"]["clean"])
        self.assertEqual("not_executed", first["verification"]["status"])
        self.assertEqual("none", first["authority_effect"])

    def test_clean_proposal_reports_ahead_commit_and_paths(self):
        self.git("checkout", "-b", "feature/clarity")
        self.commit("pulpo/new.py", "value = 1\n", "add clarity")
        report = self.collect()
        self.assertEqual("proposal_clean", report["classification"])
        self.assertEqual("ahead_of_canonical", report["source"]["relationship"])
        self.assertEqual(1, report["source"]["ahead"])
        self.assertEqual(0, report["source"]["behind"])
        self.assertEqual("add clarity", report["proposal"]["commits"][0]["subject"])
        self.assertEqual("pulpo/new.py", report["proposal"]["changed_paths"][0]["path"])

    def test_dirty_paths_are_visible_but_contents_are_not_claimed_bound(self):
        (self.repository / "README.md").write_text("dirty\n", encoding="utf-8")
        (self.repository / "private-note.txt").write_text("not in report\n", encoding="utf-8")
        report = self.collect()
        self.assertEqual("canonical_commit_dirty", report["classification"])
        self.assertFalse(report["worktree"]["clean"])
        self.assertFalse(report["worktree"]["dirty_content_bound"])
        self.assertEqual(["private-note.txt"], report["worktree"]["untracked_paths"])
        self.assertEqual("README.md", report["worktree"]["tracked_changes"][0]["path"])
        self.assertNotIn("not in report", json.dumps(report))

    def test_divergence_is_not_mislabeled_as_a_proposal(self):
        self.git("checkout", "-b", "feature/diverged")
        self.commit("feature.txt", "feature\n", "feature")
        self.git("checkout", "main")
        self.commit("main.txt", "main\n", "main")
        self.git("checkout", "feature/diverged")
        report = self.collect()
        self.assertEqual("diverged_clean", report["classification"])
        self.assertEqual("diverged_from_canonical", report["source"]["relationship"])
        self.assertEqual(1, report["source"]["ahead"])
        self.assertEqual(1, report["source"]["behind"])

    def test_detached_head_is_explicit(self):
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("checkout", "--detach", head)
        report = self.collect()
        self.assertIsNone(report["source"]["branch"])
        self.assertEqual("detached_canonical_commit_clean", report["classification"])

    def test_missing_canonical_ref_fails_closed(self):
        with self.assertRaisesRegex(GitClarityError, "rev-parse failed"):
            collect_git_clarity(
                self.repository,
                canonical_ref="refs/remotes/origin/missing",
                expected_repository=REPOSITORY_IDENTITY,
            )

    def test_remote_identity_substitution_fails_closed(self):
        with self.assertRaisesRegex(GitClarityError, "identity"):
            collect_git_clarity(
                self.repository,
                canonical_ref="refs/heads/main",
                expected_repository="github.com/attacker/Pulpo1.0",
            )

    def test_credential_bearing_remote_is_rejected_without_echoing_secret(self):
        secret = "token-secret"
        self.git(
            "remote",
            "set-url",
            "origin",
            f"https://{secret}@github.com/Ironnember/Pulpo1.0.git",
        )
        with self.assertRaises(GitClarityError) as raised:
            self.collect()
        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("credential-bearing", str(raised.exception))

    def test_tampered_report_does_not_verify(self):
        report = self.collect()
        report["source"]["ahead"] = 99
        self.assertFalse(verify_git_clarity(report))

    def test_report_cannot_claim_tests_or_authority(self):
        report = self.collect()
        report["verification"]["status"] = "passed"
        report_without_hash = {key: value for key, value in report.items() if key != "report_hash"}
        from pulpo.git_clarity import _digest

        report["report_hash"] = _digest(report_without_hash)
        self.assertFalse(verify_git_clarity(report))

    def test_collection_does_not_run_repository_hooks(self):
        marker = Path(self.temporary.name) / "hook-ran"
        hook = self.repository / ".git" / "hooks" / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        self.collect()
        self.assertFalse(marker.exists())

    def test_collection_disables_fsmonitor_and_external_diff_programs(self):
        marker = Path(self.temporary.name) / "external-program-ran"
        executable = Path(self.temporary.name) / "external-program"
        executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        self.git("config", "core.fsmonitor", str(executable))
        self.git("config", "diff.external", str(executable))
        self.git("checkout", "-b", "feature/no-external-programs")
        self.commit("safe.txt", "safe\n", "safe")
        marker.unlink(missing_ok=True)
        self.collect()
        self.assertFalse(marker.exists())

    def test_cli_can_require_clean_state(self):
        (self.repository / "dirty.txt").write_text("dirty\n", encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "--repo",
                    str(self.repository),
                    "--canonical-ref",
                    "refs/heads/main",
                    "--expected-repository",
                    REPOSITORY_IDENTITY,
                    "--require-clean",
                ]
            )
        self.assertEqual(1, exit_code)
        self.assertEqual("fail", json.loads(output.getvalue())["overall"])

    def test_cli_output_must_remain_outside_observed_repository(self):
        inside = self.repository / "report.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "--repo",
                    str(self.repository),
                    "--canonical-ref",
                    "refs/heads/main",
                    "--expected-repository",
                    REPOSITORY_IDENTITY,
                    "--output",
                    str(inside),
                ]
            )
        self.assertEqual(1, exit_code)
        self.assertFalse(inside.exists())
        self.assertEqual("fail", json.loads(output.getvalue())["overall"])

        outside = Path(self.temporary.name) / "report.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "--repo",
                    str(self.repository),
                    "--canonical-ref",
                    "refs/heads/main",
                    "--expected-repository",
                    REPOSITORY_IDENTITY,
                    "--output",
                    str(outside),
                ]
            )
        self.assertEqual(0, exit_code)
        self.assertTrue(verify_git_clarity(json.loads(outside.read_text(encoding="utf-8"))))


if __name__ == "__main__":
    unittest.main()

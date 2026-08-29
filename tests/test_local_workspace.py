from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pulpo.local_workspace import LocalWorkspace, WorkspaceViolation


class LocalWorkspaceTests(unittest.TestCase):
    def test_list_read_and_digest_are_deterministic_and_read_only(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            (root / "b.txt").write_text("beta", encoding="utf-8")
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            (root / "dir").mkdir()

            workspace = LocalWorkspace(root)
            entries = workspace.list()
            self.assertEqual(["a.txt", "b.txt", "dir"], [entry.relative_path for entry in entries])

            read = workspace.read_text("a.txt")
            self.assertEqual("alpha", read.content)
            self.assertEqual(sha256(b"alpha").hexdigest(), read.content_hash)
            self.assertEqual(5, read.size_bytes)
            self.assertEqual("none", read.authority_effect)

            digest = workspace.digest("b.txt")
            self.assertEqual(sha256(b"beta").hexdigest(), digest.content_hash)
            self.assertEqual(4, digest.size_bytes)
            self.assertEqual("none", digest.authority_effect)

            self.assertEqual("alpha", (root / "a.txt").read_text(encoding="utf-8"))
            self.assertEqual("beta", (root / "b.txt").read_text(encoding="utf-8"))

    def test_absolute_and_parent_paths_fail_closed(self):
        with TemporaryDirectory() as raw_root:
            workspace = LocalWorkspace(raw_root)
            with self.assertRaisesRegex(WorkspaceViolation, "workspace_absolute_path_forbidden"):
                workspace.read_text(Path(raw_root) / "x")
            with self.assertRaisesRegex(WorkspaceViolation, "workspace_path_traversal"):
                workspace.read_text("../outside.txt")

    def test_symlink_is_visible_but_never_followed(self):
        with TemporaryDirectory() as raw_root, TemporaryDirectory() as raw_outside:
            root = Path(raw_root)
            outside = Path(raw_outside) / "secret.txt"
            outside.write_text("secret", encoding="utf-8")
            link = root / "escape"
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation unavailable")

            workspace = LocalWorkspace(root)
            entries = workspace.list()
            self.assertEqual("symlink", entries[0].kind)
            with self.assertRaisesRegex(WorkspaceViolation, "workspace_symlink_forbidden"):
                workspace.read_text("escape")

    def test_binary_text_read_fails_but_digest_remains_available(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            payload = b"\xff\xfe\x00\x01"
            (root / "binary.dat").write_bytes(payload)
            workspace = LocalWorkspace(root)

            with self.assertRaisesRegex(WorkspaceViolation, "workspace_not_utf8_text"):
                workspace.read_text("binary.dat")
            self.assertEqual(sha256(payload).hexdigest(), workspace.digest("binary.dat").content_hash)

    def test_large_text_read_fails_closed(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            (root / "large.txt").write_bytes(b"x" * (1024 * 1024 + 1))
            workspace = LocalWorkspace(root)
            with self.assertRaisesRegex(WorkspaceViolation, "workspace_file_too_large"):
                workspace.read_text("large.txt")


if __name__ == "__main__":
    unittest.main()

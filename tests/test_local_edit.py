from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pulpo.kernel import GovernanceKernel, Policy
from pulpo.local_edit import (
    LocalEditViolation,
    LocalTextEdit,
    LocalTextEditExecutor,
    local_edit_intent,
    observe_local_edit,
    reconcile_local_edit,
)


class LocalEditTests(unittest.TestCase):
    def _kernel(self) -> GovernanceKernel:
        return GovernanceKernel(Policy(frozenset({"edit_local_file"}), 0), secret=b"local-edit-test")

    def test_exact_permit_replaces_existing_file_and_reconciles(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            target = root / "note.txt"
            target.write_text("before\n", encoding="utf-8")
            expected = sha256(b"before\n").hexdigest()
            edit = LocalTextEdit("note.txt", expected, "after\n")
            kernel = self._kernel()
            decision = kernel.evaluate(local_edit_intent(edit))
            self.assertEqual("allow", decision.outcome)
            self.assertIsNotNone(decision.permit)

            execution = LocalTextEditExecutor().execute(kernel, edit, decision.permit or "", root=root)
            observed = observe_local_edit(edit, root=root)
            reconciliation = reconcile_local_edit(kernel, edit, execution, observed)

            self.assertEqual("after\n", target.read_text(encoding="utf-8"))
            self.assertTrue(reconciliation.verified)
            self.assertEqual(edit.replacement_content_hash, observed.observed_content_hash)
            self.assertFalse(kernel.consume(decision.permit or "", local_edit_intent(edit)))

    def test_stale_hash_fails_before_permit_consumption(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            target = root / "note.txt"
            target.write_text("current", encoding="utf-8")
            edit = LocalTextEdit("note.txt", sha256(b"older").hexdigest(), "replacement")
            kernel = self._kernel()
            decision = kernel.evaluate(local_edit_intent(edit))

            with self.assertRaisesRegex(LocalEditViolation, "edit_stale_expected_hash"):
                LocalTextEditExecutor().execute(kernel, edit, decision.permit or "", root=root)

            self.assertTrue(kernel.consume(decision.permit or "", local_edit_intent(edit)))
            self.assertEqual("current", target.read_text(encoding="utf-8"))

    def test_permit_for_different_edit_cannot_write(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            target = root / "note.txt"
            target.write_text("before", encoding="utf-8")
            expected = sha256(b"before").hexdigest()
            authorized = LocalTextEdit("note.txt", expected, "authorized")
            substituted = LocalTextEdit("note.txt", expected, "substituted")
            kernel = self._kernel()
            decision = kernel.evaluate(local_edit_intent(authorized))

            with self.assertRaisesRegex(LocalEditViolation, "permit_rejected"):
                LocalTextEditExecutor().execute(kernel, substituted, decision.permit or "", root=root)

            self.assertEqual("before", target.read_text(encoding="utf-8"))

    def test_missing_symlink_binary_and_traversal_fail_closed(self):
        with TemporaryDirectory() as raw_root, TemporaryDirectory() as raw_outside:
            root = Path(raw_root)
            expected = sha256(b"x").hexdigest()
            with self.assertRaisesRegex(LocalEditViolation, "edit_path_invalid"):
                LocalTextEdit("../escape.txt", expected, "x")

            missing = LocalTextEdit("missing.txt", expected, "x")
            kernel = self._kernel()
            decision = kernel.evaluate(local_edit_intent(missing))
            with self.assertRaisesRegex(LocalEditViolation, "edit_target_missing"):
                LocalTextEditExecutor().execute(kernel, missing, decision.permit or "", root=root)

            binary = root / "binary.dat"
            binary.write_bytes(b"\xff\xfe")
            binary_edit = LocalTextEdit("binary.dat", sha256(b"\xff\xfe").hexdigest(), "text")
            decision = kernel.evaluate(local_edit_intent(binary_edit))
            with self.assertRaisesRegex(LocalEditViolation, "edit_target_not_utf8_text"):
                LocalTextEditExecutor().execute(kernel, binary_edit, decision.permit or "", root=root)

            outside = Path(raw_outside) / "secret.txt"
            outside.write_text("secret", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation unavailable")
            link_edit = LocalTextEdit("link.txt", sha256(b"secret").hexdigest(), "changed")
            decision = kernel.evaluate(local_edit_intent(link_edit))
            with self.assertRaisesRegex(LocalEditViolation, "edit_symlink_forbidden"):
                LocalTextEditExecutor().execute(kernel, link_edit, decision.permit or "", root=root)
            self.assertEqual("secret", outside.read_text(encoding="utf-8"))

    def test_tamper_after_execution_reconciles_as_mismatch(self):
        with TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            target = root / "note.txt"
            target.write_text("before", encoding="utf-8")
            edit = LocalTextEdit("note.txt", sha256(b"before").hexdigest(), "after")
            kernel = self._kernel()
            decision = kernel.evaluate(local_edit_intent(edit))
            execution = LocalTextEditExecutor().execute(kernel, edit, decision.permit or "", root=root)
            target.write_text("tampered", encoding="utf-8")
            observed = observe_local_edit(edit, root=root)
            reconciliation = reconcile_local_edit(kernel, edit, execution, observed)
            self.assertFalse(reconciliation.verified)
            self.assertEqual("observed_content_mismatch", reconciliation.reason)


if __name__ == "__main__":
    unittest.main()

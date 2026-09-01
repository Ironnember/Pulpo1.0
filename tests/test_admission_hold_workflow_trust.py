from __future__ import annotations

from pathlib import Path
import unittest


WORKFLOW = Path(".github/workflows/admission-hold.yml")


class AdmissionHoldWorkflowTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_targets_main_pull_request_target_only(self):
        self.assertIn("pull_request_target:", self.text)
        self.assertIn("branches:\n      - main", self.text)

    def test_never_overrides_checkout_to_pr_metadata_or_head(self):
        self.assertNotIn("github.event.pull_request.base.sha", self.text)
        self.assertNotIn("github.event.pull_request.head.sha", self.text)
        self.assertNotIn("refs/pull/", self.text)
        self.assertNotIn("\n          ref:", self.text)
        self.assertIn("persist-credentials: false", self.text)

    def test_write_scope_is_only_pull_request_mutation_plus_read(self):
        self.assertIn("contents: read", self.text)
        self.assertIn("pull-requests: write", self.text)
        self.assertNotIn("contents: write", self.text)
        self.assertNotIn("actions: write", self.text)
        self.assertNotIn("checks: write", self.text)

    def test_draft_enforcement_precedes_metadata_denial(self):
        mutation = self.text.index("scripts/enforce_pr_admission_hold.py")
        check = self.text.index("scripts/check_pr_admission_hold.py")
        self.assertLess(mutation, check)

    def test_metadata_hold_check_runs_even_if_draft_mutation_fails(self):
        marker = "- name: Enforce Pulpo admission hold metadata\n        if: ${{ always() }}"
        self.assertIn(marker, self.text)


if __name__ == "__main__":
    unittest.main()

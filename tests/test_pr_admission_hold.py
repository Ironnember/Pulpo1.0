from __future__ import annotations

import unittest

from scripts.check_pr_admission_hold import admission_hold_reasons, evaluate_event


class PullRequestAdmissionHoldTests(unittest.TestCase):
    def test_normal_ready_pr_is_open(self):
        allowed, reasons = evaluate_event(
            {
                "pull_request": {
                    "draft": False,
                    "title": "Harden canonical admission",
                    "body": "Ready for review.",
                    "labels": [],
                }
            }
        )
        self.assertTrue(allowed)
        self.assertEqual((), reasons)

    def test_github_draft_fails_closed(self):
        reasons = admission_hold_reasons(
            {"draft": True, "title": "Proof", "body": "", "labels": []}
        )
        self.assertIn("github_draft", reasons)

    def test_machine_hold_marker_fails_closed(self):
        reasons = admission_hold_reasons(
            {
                "draft": False,
                "title": "Proof",
                "body": "<!-- pulpo-admission: hold -->\nAwaiting external ceremony.",
                "labels": [],
            }
        )
        self.assertIn("machine_hold_marker", reasons)

    def test_legacy_process_hold_fails_closed(self):
        reasons = admission_hold_reasons(
            {
                "draft": False,
                "title": "Proof",
                "body": "## PROCESS HOLD — DO NOT MERGE\n\nEvidence incomplete.",
                "labels": [],
            }
        )
        self.assertIn("legacy_process_hold", reasons)

    def test_legacy_draft_hold_fails_closed(self):
        reasons = admission_hold_reasons(
            {
                "draft": False,
                "title": "Proof",
                "body": "**DRAFT / DO NOT MERGE.**\nPassing CI is insufficient.",
                "labels": [],
            }
        )
        self.assertIn("legacy_draft_hold", reasons)

    def test_hold_title_and_label_fail_closed(self):
        reasons = admission_hold_reasons(
            {
                "draft": False,
                "title": "[HOLD] Exact consequence proof",
                "body": "",
                "labels": [{"name": "do-not-merge"}],
            }
        )
        self.assertIn("title_hold", reasons)
        self.assertIn("label:do-not-merge", reasons)

    def test_narrative_historical_mention_does_not_create_hold(self):
        allowed, reasons = evaluate_event(
            {
                "pull_request": {
                    "draft": False,
                    "title": "Prevent unauthorized merges",
                    "body": (
                        "## Purpose\n\n"
                        "This change fixes the previous case where a DO NOT MERGE boundary "
                        "was not mechanically enforced.\n"
                    ),
                    "labels": [],
                }
            }
        )
        self.assertTrue(allowed)
        self.assertEqual((), reasons)

    def test_non_pr_event_is_noop(self):
        self.assertEqual((True, ()), evaluate_event({"ref": "refs/heads/main"}))


if __name__ == "__main__":
    unittest.main()

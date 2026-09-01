from __future__ import annotations

import unittest

from scripts.enforce_pr_admission_hold import enforcement_required, pull_request_node_id


class PullRequestAdmissionEnforcementTests(unittest.TestCase):
    def test_open_pr_is_not_mutated(self):
        payload = {
            "pull_request": {
                "node_id": "PR_open",
                "draft": False,
                "title": "Ready change",
                "body": "Ready for review.",
                "labels": [],
            }
        }
        self.assertFalse(enforcement_required(payload))

    def test_machine_held_non_draft_pr_requires_draft_conversion(self):
        payload = {
            "pull_request": {
                "node_id": "PR_held",
                "draft": False,
                "title": "Proof",
                "body": "<!-- pulpo-admission: hold -->\nEvidence incomplete.",
                "labels": [],
            }
        }
        self.assertTrue(enforcement_required(payload))
        self.assertEqual("PR_held", pull_request_node_id(payload))

    def test_legacy_held_non_draft_pr_requires_draft_conversion(self):
        payload = {
            "pull_request": {
                "node_id": "PR_legacy",
                "draft": False,
                "title": "Proof",
                "body": "## PROCESS HOLD — DO NOT MERGE\nEvidence incomplete.",
                "labels": [],
            }
        }
        self.assertTrue(enforcement_required(payload))

    def test_hold_label_requires_draft_conversion(self):
        payload = {
            "pull_request": {
                "node_id": "PR_label",
                "draft": False,
                "title": "Proof",
                "body": "",
                "labels": [{"name": "do-not-merge"}],
            }
        }
        self.assertTrue(enforcement_required(payload))

    def test_already_draft_pr_needs_no_mutation(self):
        payload = {
            "pull_request": {
                "node_id": "PR_draft",
                "draft": True,
                "title": "Proof",
                "body": "<!-- pulpo-admission: hold -->",
                "labels": [],
            }
        }
        self.assertFalse(enforcement_required(payload))

    def test_non_pr_event_is_noop(self):
        self.assertFalse(enforcement_required({"ref": "refs/heads/main"}))

    def test_missing_node_id_fails_closed_when_mutation_is_needed(self):
        payload = {
            "pull_request": {
                "draft": False,
                "title": "[HOLD] Proof",
                "body": "",
                "labels": [],
            }
        }
        self.assertTrue(enforcement_required(payload))
        with self.assertRaisesRegex(ValueError, "pull_request_node_id_missing"):
            pull_request_node_id(payload)


if __name__ == "__main__":
    unittest.main()

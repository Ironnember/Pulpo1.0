from __future__ import annotations

import json
import unittest
from unittest import mock

from scripts.enforce_pr_admission_hold import (
    GITHUB_GRAPHQL_URL,
    convert_to_draft,
    enforcement_required,
    pull_request_node_id,
)


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

    @staticmethod
    def _graphql_response(payload: dict[str, object]):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
        response.__exit__.return_value = False
        return response

    @mock.patch("scripts.enforce_pr_admission_hold.urlopen")
    def test_convert_to_draft_binds_exact_node_and_requires_verified_draft(self, mocked_urlopen):
        mocked_urlopen.return_value = self._graphql_response(
            {
                "data": {
                    "convertPullRequestToDraft": {
                        "pullRequest": {"id": "PR_exact", "isDraft": True}
                    }
                }
            }
        )

        convert_to_draft("PR_exact", "test-token")

        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(GITHUB_GRAPHQL_URL, request.full_url)
        body = json.loads(request.data.decode())
        self.assertEqual("PR_exact", body["variables"]["pullRequestId"])
        self.assertIn("convertPullRequestToDraft", body["query"])
        self.assertEqual("Bearer test-token", request.get_header("Authorization"))

    @mock.patch("scripts.enforce_pr_admission_hold.urlopen")
    def test_graphql_error_fails_closed(self, mocked_urlopen):
        mocked_urlopen.return_value = self._graphql_response(
            {"errors": [{"message": "mutation denied"}]}
        )
        with self.assertRaisesRegex(RuntimeError, "github_draft_enforcement_failed"):
            convert_to_draft("PR_exact", "test-token")

    @mock.patch("scripts.enforce_pr_admission_hold.urlopen")
    def test_unverified_draft_state_fails_closed(self, mocked_urlopen):
        mocked_urlopen.return_value = self._graphql_response(
            {
                "data": {
                    "convertPullRequestToDraft": {
                        "pullRequest": {"id": "PR_exact", "isDraft": False}
                    }
                }
            }
        )
        with self.assertRaisesRegex(RuntimeError, "github_draft_enforcement_unverified"):
            convert_to_draft("PR_exact", "test-token")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from unittest import mock
from urllib.error import URLError

from scripts.enforce_pr_admission_hold import (
    GITHUB_API_BASE,
    GITHUB_API_VERSION,
    close_held_pull_request,
    enforcement_required,
    pull_request_number,
    repository_full_name,
)


class PullRequestAdmissionEnforcementTests(unittest.TestCase):
    def test_open_pr_is_not_mutated(self):
        payload = {
            "pull_request": {
                "number": 12,
                "state": "open",
                "draft": False,
                "title": "Ready change",
                "body": "Ready for review.",
                "labels": [],
            },
            "repository": {"full_name": "Ironnember/Pulpo1.0"},
        }
        self.assertFalse(enforcement_required(payload))

    def test_machine_held_non_draft_pr_requires_quarantine(self):
        payload = {
            "pull_request": {
                "number": 117,
                "state": "open",
                "draft": False,
                "title": "Proof",
                "body": "<!-- pulpo-admission: hold -->\nEvidence incomplete.",
                "labels": [],
            },
            "repository": {"full_name": "Ironnember/Pulpo1.0"},
        }
        self.assertTrue(enforcement_required(payload))
        self.assertEqual(117, pull_request_number(payload))
        self.assertEqual("Ironnember/Pulpo1.0", repository_full_name(payload))

    def test_legacy_held_non_draft_pr_requires_quarantine(self):
        payload = {
            "pull_request": {
                "number": 117,
                "state": "open",
                "draft": False,
                "title": "Proof",
                "body": "## PROCESS HOLD — DO NOT MERGE\nEvidence incomplete.",
                "labels": [],
            }
        }
        self.assertTrue(enforcement_required(payload))

    def test_hold_label_requires_quarantine(self):
        payload = {
            "pull_request": {
                "number": 117,
                "state": "open",
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
                "number": 117,
                "state": "open",
                "draft": True,
                "title": "Proof",
                "body": "<!-- pulpo-admission: hold -->",
                "labels": [],
            }
        }
        self.assertFalse(enforcement_required(payload))

    def test_already_closed_pr_needs_no_mutation(self):
        payload = {
            "pull_request": {
                "number": 117,
                "state": "closed",
                "draft": False,
                "title": "Proof",
                "body": "<!-- pulpo-admission: hold -->",
                "labels": [],
            }
        }
        self.assertFalse(enforcement_required(payload))

    def test_non_pr_event_is_noop(self):
        self.assertFalse(enforcement_required({"ref": "refs/heads/main"}))

    def test_missing_number_fails_closed_when_mutation_is_needed(self):
        payload = {
            "pull_request": {
                "state": "open",
                "draft": False,
                "title": "[HOLD] Proof",
                "body": "",
                "labels": [],
            }
        }
        self.assertTrue(enforcement_required(payload))
        with self.assertRaisesRegex(ValueError, "pull_request_number_missing"):
            pull_request_number(payload)

    def test_missing_repository_fails_closed_when_mutation_is_needed(self):
        with self.assertRaisesRegex(ValueError, "repository_missing"):
            repository_full_name({"pull_request": {"number": 117}})

    @staticmethod
    def _rest_response(payload: dict[str, object]):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
        response.__exit__.return_value = False
        return response

    @mock.patch("scripts.enforce_pr_admission_hold.urlopen")
    def test_close_binds_exact_repository_number_and_state(self, mocked_urlopen):
        mocked_urlopen.return_value = self._rest_response({"number": 117, "state": "closed"})

        close_held_pull_request("Ironnember/Pulpo1.0", 117, "test-token")

        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(
            f"{GITHUB_API_BASE}/repos/Ironnember/Pulpo1.0/pulls/117",
            request.full_url,
        )
        self.assertEqual("PATCH", request.method)
        self.assertEqual({"state": "closed"}, json.loads(request.data.decode()))
        self.assertEqual("Bearer test-token", request.get_header("Authorization"))
        self.assertEqual(GITHUB_API_VERSION, request.get_header("X-github-api-version"))

    @mock.patch("scripts.enforce_pr_admission_hold.urlopen")
    def test_rest_error_fails_closed(self, mocked_urlopen):
        mocked_urlopen.side_effect = URLError("mutation denied")
        with self.assertRaisesRegex(RuntimeError, "github_hold_quarantine_failed"):
            close_held_pull_request("Ironnember/Pulpo1.0", 117, "test-token")

    @mock.patch("scripts.enforce_pr_admission_hold.urlopen")
    def test_unverified_closed_state_fails_closed(self, mocked_urlopen):
        mocked_urlopen.return_value = self._rest_response({"number": 117, "state": "open"})
        with self.assertRaisesRegex(RuntimeError, "github_hold_quarantine_unverified"):
            close_held_pull_request("Ironnember/Pulpo1.0", 117, "test-token")


if __name__ == "__main__":
    unittest.main()

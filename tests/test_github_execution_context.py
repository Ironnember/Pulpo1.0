import json
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.execution_context import bind_resource_to_execution_context, consume_context_bound_permit
from pulpo.github_execution_context import (
    GitHubContextAttestationError,
    GitHubRESTMetadataReader,
    context_from_github_metadata,
    observe_github_repository_context,
)


NOW = 9_000_000
REPOSITORY = "Ironnember/Pulpo1.0"
REPOSITORY_ID = 1344057538
REPOSITORY_NODE_ID = "R_kgDOUBywwg"
LOGIN = "Ironnember"
USER_ID = 293038337


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self):
        return self._payload


class _RecordingOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("unexpected provider read")
        return self.responses.pop(0)


class GitHubExecutionContextTests(unittest.TestCase):
    def repository_metadata(self, **overrides):
        value = {
            "full_name": REPOSITORY,
            "id": REPOSITORY_ID,
            "node_id": REPOSITORY_NODE_ID,
            "owner": {"login": "Ironnember"},
        }
        value.update(overrides)
        return value

    def user_metadata(self, **overrides):
        value = {"login": LOGIN, "id": USER_ID}
        value.update(overrides)
        return value

    def test_exact_provider_metadata_builds_stable_repository_context(self):
        attestation = context_from_github_metadata(
            REPOSITORY,
            self.repository_metadata(),
            self.user_metadata(),
        )

        self.assertEqual("github", attestation.context.surface)
        self.assertEqual(f"repository:{REPOSITORY}", attestation.context.authority_scope)
        self.assertEqual(f"user:{LOGIN}:{USER_ID}", attestation.context.principal)
        self.assertEqual(
            f"repository-id:{REPOSITORY_ID}:node:{REPOSITORY_NODE_ID}",
            attestation.context.connection,
        )
        self.assertEqual("none", attestation.authority_effect)

    def test_provider_returned_repository_substitution_fails_closed(self):
        with self.assertRaisesRegex(GitHubContextAttestationError, "binding mismatch"):
            context_from_github_metadata(
                REPOSITORY,
                self.repository_metadata(full_name="OtherOrg/OtherRepo"),
                self.user_metadata(),
            )

    def test_provider_returned_owner_substitution_fails_closed(self):
        metadata = self.repository_metadata()
        metadata["owner"] = {"login": "OtherOrg"}
        with self.assertRaisesRegex(GitHubContextAttestationError, "owner mismatch"):
            context_from_github_metadata(REPOSITORY, metadata, self.user_metadata())

    def test_missing_authenticated_identity_fails_closed(self):
        with self.assertRaisesRegex(GitHubContextAttestationError, "authenticated user id"):
            context_from_github_metadata(
                REPOSITORY,
                self.repository_metadata(),
                {"login": LOGIN},
            )

    def test_repository_numeric_identity_changes_context_even_when_name_matches(self):
        first = context_from_github_metadata(
            REPOSITORY,
            self.repository_metadata(),
            self.user_metadata(),
        )
        second = context_from_github_metadata(
            REPOSITORY,
            self.repository_metadata(id=REPOSITORY_ID + 1),
            self.user_metadata(),
        )
        self.assertNotEqual(first.context.context_hash, second.context.context_hash)

    def test_reader_exposes_only_get_metadata_requests_for_exact_bound_repo(self):
        opener = _RecordingOpener(
            [
                _FakeResponse(self.repository_metadata()),
                _FakeResponse(self.user_metadata()),
            ]
        )
        reader = GitHubRESTMetadataReader("test-token", opener=opener)

        attestation = observe_github_repository_context(REPOSITORY, reader)

        self.assertEqual(REPOSITORY, attestation.repository_full_name)
        self.assertEqual(2, len(opener.requests))
        repository_request, user_request = [entry[0] for entry in opener.requests]
        self.assertEqual("GET", repository_request.get_method())
        self.assertEqual("GET", user_request.get_method())
        self.assertEqual(
            f"https://api.github.com/repos/{REPOSITORY}", repository_request.full_url
        )
        self.assertEqual("https://api.github.com/user", user_request.full_url)

    def test_provider_failure_yields_no_context(self):
        def fail(_request, timeout):
            raise OSError(f"offline:{timeout}")

        reader = GitHubRESTMetadataReader("test-token", opener=fail)
        with self.assertRaisesRegex(GitHubContextAttestationError, "context read failed"):
            observe_github_repository_context(REPOSITORY, reader)

    def test_observed_github_context_gates_existing_one_use_permit(self):
        attestation = context_from_github_metadata(
            REPOSITORY,
            self.repository_metadata(),
            self.user_metadata(),
        )
        kernel = GovernanceKernel(
            Policy(frozenset({"read_repository"}), 0),
            secret=b"github-context-proof-secret",
            clock=lambda: NOW,
        )
        intent = Intent(
            "agent:assistant",
            "read_repository",
            bind_resource_to_execution_context("contents:README.md", attestation.context),
            0,
            "github-context-proof-1",
        )
        permit = kernel.evaluate(intent).permit
        self.assertIsNotNone(permit)

        check, consumed = consume_context_bound_permit(
            kernel,
            permit,
            intent,
            attestation.context,
        )
        self.assertEqual("match", check.outcome)
        self.assertTrue(consumed)
        self.assertFalse(kernel.consume(permit, intent))


if __name__ == "__main__":
    unittest.main()

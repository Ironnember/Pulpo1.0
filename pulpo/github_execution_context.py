"""Read-only GitHub execution-context attestation for Pulpo.

This module does not authorize or execute GitHub mutations. It performs narrowly
bounded provider introspection so a caller can construct an ``ExecutionContext``
from GitHub-returned repository and authenticated-user metadata before permit
consumption.

The repository named here must come from trusted executor configuration, not from
an agent-supplied target argument. A provider response that resolves to a
repository other than that configured binding fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable, Mapping
from urllib.parse import quote
from urllib.request import Request, urlopen

from .execution_context import ExecutionContext


_GITHUB_API_ORIGIN = "https://api.github.com"
_GITHUB_ACCEPT = "application/vnd.github+json"
_GITHUB_API_VERSION = "2022-11-28"


class GitHubContextAttestationError(RuntimeError):
    """Raised when GitHub context cannot be independently established."""


@dataclass(frozen=True)
class GitHubRepositoryAttestation:
    """Provider-derived evidence for one exact GitHub repository context."""

    context: ExecutionContext
    repository_full_name: str
    repository_id: int
    repository_node_id: str
    authenticated_login: str
    authenticated_user_id: int
    authority_effect: str = "none"


class GitHubRESTMetadataReader:
    """Minimal read-only GitHub REST metadata client.

    Only two provider reads are exposed: the authenticated user and one exact
    configured repository. There is no generic request method and no mutation
    surface.
    """

    def __init__(
        self,
        token: str,
        *,
        opener: Callable[..., Any] = urlopen,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not isinstance(token, str) or not token.strip():
            raise ValueError("GitHub token is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._token = token
        self._opener = opener
        self._timeout_seconds = float(timeout_seconds)

    def _get_json(self, path: str) -> Mapping[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise GitHubContextAttestationError("invalid GitHub API path")
        request = Request(
            f"{_GITHUB_API_ORIGIN}{path}",
            method="GET",
            headers={
                "Accept": _GITHUB_ACCEPT,
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": _GITHUB_API_VERSION,
                "User-Agent": "pulpo-execution-context-attestor",
            },
        )
        try:
            response = self._opener(request, timeout=self._timeout_seconds)
            payload = response.read()
            status = getattr(response, "status", 200)
        except Exception as exc:  # provider/network failures fail closed
            raise GitHubContextAttestationError("GitHub context read failed") from exc
        if status != 200:
            raise GitHubContextAttestationError(f"GitHub context read returned HTTP {status}")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubContextAttestationError("GitHub context response was not valid JSON") from exc
        if not isinstance(value, dict):
            raise GitHubContextAttestationError("GitHub context response must be an object")
        return value

    def fetch_authenticated_user(self) -> Mapping[str, Any]:
        return self._get_json("/user")

    def fetch_repository(self, repository_full_name: str) -> Mapping[str, Any]:
        owner, repo = _split_repository(repository_full_name)
        return self._get_json(f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}")


def _split_repository(repository_full_name: str) -> tuple[str, str]:
    if not isinstance(repository_full_name, str):
        raise TypeError("repository_full_name must be a string")
    value = repository_full_name.strip()
    parts = value.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("repository_full_name must be owner/repo")
    if any(part in {".", ".."} for part in parts):
        raise ValueError("invalid repository_full_name")
    return parts[0], parts[1]


def _required_string(mapping: Mapping[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GitHubContextAttestationError(f"missing {label}")
    return value


def _required_positive_int(mapping: Mapping[str, Any], key: str, label: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubContextAttestationError(f"missing {label}")
    return value


def context_from_github_metadata(
    bound_repository_full_name: str,
    repository_metadata: Mapping[str, Any],
    authenticated_user_metadata: Mapping[str, Any],
) -> GitHubRepositoryAttestation:
    """Build exact Pulpo context from provider-returned GitHub metadata.

    ``bound_repository_full_name`` is executor configuration. It is not accepted
    from the governed intent at execution time. GitHub's own ``full_name`` field
    must exactly match that configured binding; redirects/renames therefore fail
    closed until authority is re-established for the new canonical object.
    """

    _split_repository(bound_repository_full_name)
    if not isinstance(repository_metadata, Mapping) or not isinstance(
        authenticated_user_metadata, Mapping
    ):
        raise TypeError("GitHub metadata must be mappings")

    provider_full_name = _required_string(repository_metadata, "full_name", "repository full_name")
    if provider_full_name != bound_repository_full_name:
        raise GitHubContextAttestationError("GitHub repository binding mismatch")

    repository_id = _required_positive_int(repository_metadata, "id", "repository id")
    repository_node_id = _required_string(repository_metadata, "node_id", "repository node_id")

    owner = repository_metadata.get("owner")
    if not isinstance(owner, Mapping):
        raise GitHubContextAttestationError("missing repository owner metadata")
    owner_login = _required_string(owner, "login", "repository owner login")
    expected_owner, _ = _split_repository(bound_repository_full_name)
    if owner_login != expected_owner:
        raise GitHubContextAttestationError("GitHub repository owner mismatch")

    authenticated_login = _required_string(
        authenticated_user_metadata, "login", "authenticated user login"
    )
    authenticated_user_id = _required_positive_int(
        authenticated_user_metadata, "id", "authenticated user id"
    )

    context = ExecutionContext(
        surface="github",
        authority_scope=f"repository:{provider_full_name}",
        principal=f"user:{authenticated_login}:{authenticated_user_id}",
        connection=f"repository-id:{repository_id}:node:{repository_node_id}",
    )
    return GitHubRepositoryAttestation(
        context=context,
        repository_full_name=provider_full_name,
        repository_id=repository_id,
        repository_node_id=repository_node_id,
        authenticated_login=authenticated_login,
        authenticated_user_id=authenticated_user_id,
    )


def observe_github_repository_context(
    bound_repository_full_name: str,
    reader: GitHubRESTMetadataReader,
) -> GitHubRepositoryAttestation:
    """Read provider metadata and fail closed unless exact GitHub context is established."""

    if not isinstance(reader, GitHubRESTMetadataReader):
        raise TypeError("reader must be GitHubRESTMetadataReader")
    repository = reader.fetch_repository(bound_repository_full_name)
    authenticated_user = reader.fetch_authenticated_user()
    return context_from_github_metadata(
        bound_repository_full_name,
        repository,
        authenticated_user,
    )

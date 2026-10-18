"""Fail-closed, read-only discovery for Pulpo's Google Cloud runtime prerequisites.

This proof helper does not create, enable, disable, update, deploy, push, execute,
or delete any cloud resource. It permits only a frozen set of metadata-listing
commands for the already-recorded Pulpo operator/project/region context.

The output is evidence for deciding the next governed cloud object. It is not
permission to create that object and it is not a source of Pulpo authority.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

PROJECT_ID = "dulcet-opus-499511-a5"
REGION = "us-west1"
EXPECTED_OPERATOR = "ai@ironnember.com"
SCHEMA = "pulpo.cloud-runtime-discovery.v0"
TRACKED_SERVICES = (
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
)

AUTH_COMMAND = (
    "gcloud",
    "auth",
    "list",
    "--filter=status:ACTIVE",
    "--format=value(account)",
)
PROJECT_COMMAND = (
    "gcloud",
    "config",
    "get-value",
    "project",
)
ARTIFACT_REPOSITORIES_COMMAND = (
    "gcloud",
    "artifacts",
    "repositories",
    "list",
    f"--project={PROJECT_ID}",
    f"--location={REGION}",
    "--format=json",
)
CLOUD_RUN_JOBS_COMMAND = (
    "gcloud",
    "run",
    "jobs",
    "list",
    f"--project={PROJECT_ID}",
    f"--region={REGION}",
    "--format=json",
)
ENABLED_SERVICES_COMMAND = (
    "gcloud",
    "services",
    "list",
    "--enabled",
    f"--project={PROJECT_ID}",
    "--format=value(config.name)",
)

READ_ONLY_COMMANDS = (
    AUTH_COMMAND,
    PROJECT_COMMAND,
    ARTIFACT_REPOSITORIES_COMMAND,
    CLOUD_RUN_JOBS_COMMAND,
    ENABLED_SERVICES_COMMAND,
)
_ALLOWED_COMMANDS = frozenset(READ_ONLY_COMMANDS)

Runner = Callable[[Sequence[str]], str]


def validate_read_only_command(command: Sequence[str]) -> tuple[str, ...]:
    """Return the frozen command or reject any substitution."""

    frozen = tuple(command)
    if frozen not in _ALLOWED_COMMANDS:
        raise ValueError("cloud discovery command is not in the read-only allowlist")
    return frozen


def _run(command: Sequence[str]) -> str:
    frozen = validate_read_only_command(command)
    completed = subprocess.run(
        frozen,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return completed.stdout


def _single_nonempty_line(raw: str, field: str) -> str:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"cloud discovery {field} is ambiguous")
    return lines[0]


def _json_list(raw: str, field: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"cloud discovery {field} returned invalid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError(f"cloud discovery {field} returned an unexpected shape")
    return sorted(value, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))


def _command_set_sha256() -> str:
    encoded = json.dumps(READ_ONLY_COMMANDS, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def collect_discovery(runner: Runner = _run) -> dict[str, object]:
    """Collect read-only cloud metadata under the exact recorded operator context."""

    operator = _single_nonempty_line(runner(AUTH_COMMAND), "active operator")
    if operator != EXPECTED_OPERATOR:
        raise RuntimeError("cloud discovery active operator mismatch")

    project = _single_nonempty_line(runner(PROJECT_COMMAND), "active project")
    if project != PROJECT_ID:
        raise RuntimeError("cloud discovery active project mismatch")

    repositories = _json_list(
        runner(ARTIFACT_REPOSITORIES_COMMAND),
        "Artifact Registry repositories",
    )
    jobs = _json_list(runner(CLOUD_RUN_JOBS_COMMAND), "Cloud Run jobs")
    enabled_services = {
        line.strip()
        for line in runner(ENABLED_SERVICES_COMMAND).splitlines()
        if line.strip()
    }

    return {
        "schema": SCHEMA,
        "project": PROJECT_ID,
        "region": REGION,
        "operator": EXPECTED_OPERATOR,
        "discovery_command_sha256": _command_set_sha256(),
        "artifact_repositories": repositories,
        "cloud_run_jobs": jobs,
        "tracked_services": {
            service: service in enabled_services for service in TRACKED_SERVICES
        },
        "authority_effect": "none",
        "cloud_mutation": "none",
    }


def main() -> int:
    evidence = collect_discovery()
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

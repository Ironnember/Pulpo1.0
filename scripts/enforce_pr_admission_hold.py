#!/usr/bin/env python3
"""Fail closed by quarantining held pull requests through GitHub REST.

This script is intended only for the protected-base ``pull_request_target``
workflow. It consumes GitHub pull-request event metadata and never imports or
executes pull-request-head code.

GitHub's workflow ``GITHUB_TOKEN`` cannot reliably perform the GraphQL
``convertPullRequestToDraft`` mutation. Instead, a held non-draft pull request
is closed through the supported REST "Update a pull request" endpoint. A
human may remove the HOLD condition and reopen the PR; if HOLD remains, the
reopen event is quarantined again.

The mutation is deliberately narrow: close the exact event pull request. It
does not merge, approve, label, edit code, alter branch protection, or broaden
authority.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

try:
    from scripts.check_pr_admission_hold import admission_hold_reasons
except ModuleNotFoundError:  # direct execution from scripts/
    from check_pr_admission_hold import admission_hold_reasons


GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


def enforcement_required(payload: dict[str, Any]) -> bool:
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        return False
    if pull_request.get("state") == "closed":
        return False
    return bool(admission_hold_reasons(pull_request)) and pull_request.get("draft") is not True


def pull_request_number(payload: dict[str, Any]) -> int:
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        raise ValueError("pull_request_missing")
    number = pull_request.get("number")
    if not isinstance(number, int) or number <= 0:
        raise ValueError("pull_request_number_missing")
    return number


def repository_full_name(payload: dict[str, Any]) -> str:
    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise ValueError("repository_missing")
    full_name = repository.get("full_name")
    if not isinstance(full_name, str) or full_name.count("/") != 1:
        raise ValueError("repository_full_name_missing")
    owner, repo = full_name.split("/", 1)
    if not owner or not repo:
        raise ValueError("repository_full_name_missing")
    return full_name


def close_held_pull_request(repo_full_name: str, number: int, token: str) -> None:
    owner, repo = repo_full_name.split("/", 1)
    url = (
        f"{GITHUB_API_BASE}/repos/{quote(owner, safe='')}/"
        f"{quote(repo, safe='')}/pulls/{number}"
    )
    payload = json.dumps({"state": "closed"}, separators=(",", ":")).encode()
    request = Request(
        url,
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "pulpo-admission-hold",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode())
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError("github_hold_quarantine_failed") from exc

    if result.get("state") != "closed":
        raise RuntimeError("github_hold_quarantine_unverified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True, help="Path to the GitHub event JSON payload")
    parser.add_argument("--apply", action="store_true", help="Apply the hold quarantine mutation")
    args = parser.parse_args()

    payload = json.loads(Path(args.event).read_text(encoding="utf-8"))
    if not enforcement_required(payload):
        print("pulpo admission enforcement: no quarantine mutation required")
        return 0

    reasons = admission_hold_reasons(payload["pull_request"])
    print("pulpo admission enforcement: held non-draft PR detected")
    for reason in reasons:
        print(f"- {reason}")

    if not args.apply:
        print("pulpo admission enforcement: close_exact_pull_request")
        return 0

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("github_token_missing")
    repo_full_name = repository_full_name(payload)
    number = pull_request_number(payload)
    close_held_pull_request(repo_full_name, number, token)
    print("pulpo admission enforcement: closed exact held PR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

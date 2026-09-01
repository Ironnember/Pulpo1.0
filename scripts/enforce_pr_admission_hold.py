#!/usr/bin/env python3
"""Actively force held pull requests back to GitHub Draft state.

This script is intended only for the protected-base ``pull_request_target``
workflow. It consumes GitHub pull-request event metadata and never imports or
executes pull-request-head code.

The mutation is deliberately narrow: when Pulpo admission metadata says HOLD
and the PR is not already a draft, convert that exact pull request to Draft.
It does not merge, close, label, approve, or otherwise broaden authority.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scripts.check_pr_admission_hold import admission_hold_reasons


GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


def enforcement_required(payload: dict[str, Any]) -> bool:
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        return False
    return bool(admission_hold_reasons(pull_request)) and pull_request.get("draft") is not True


def pull_request_node_id(payload: dict[str, Any]) -> str:
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        raise ValueError("pull_request_missing")
    node_id = pull_request.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("pull_request_node_id_missing")
    return node_id


def convert_to_draft(node_id: str, token: str) -> None:
    query = """
      mutation ConvertPulpoHeldPullRequestToDraft($pullRequestId: ID!) {
        convertPullRequestToDraft(input: {pullRequestId: $pullRequestId}) {
          pullRequest { id isDraft }
        }
      }
    """
    payload = json.dumps(
        {"query": query, "variables": {"pullRequestId": node_id}},
        separators=(",", ":"),
    ).encode()
    request = Request(
        GITHUB_GRAPHQL_URL,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "pulpo-admission-hold",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode())
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError("github_draft_enforcement_failed") from exc

    if result.get("errors"):
        raise RuntimeError("github_draft_enforcement_failed")
    converted = (
        result.get("data", {})
        .get("convertPullRequestToDraft", {})
        .get("pullRequest", {})
        .get("isDraft")
    )
    if converted is not True:
        raise RuntimeError("github_draft_enforcement_unverified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True, help="Path to the GitHub event JSON payload")
    parser.add_argument("--apply", action="store_true", help="Apply the draft-state enforcement mutation")
    args = parser.parse_args()

    payload = json.loads(Path(args.event).read_text(encoding="utf-8"))
    if not enforcement_required(payload):
        print("pulpo admission enforcement: no draft mutation required")
        return 0

    reasons = admission_hold_reasons(payload["pull_request"])
    print("pulpo admission enforcement: held non-draft PR detected")
    for reason in reasons:
        print(f"- {reason}")

    if not args.apply:
        print("pulpo admission enforcement: convert_to_draft")
        return 0

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("github_token_missing")
    node_id = pull_request_node_id(payload)
    convert_to_draft(node_id, token)
    print("pulpo admission enforcement: converted exact PR to Draft")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

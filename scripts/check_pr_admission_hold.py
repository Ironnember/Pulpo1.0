#!/usr/bin/env python3
"""Fail closed when pull-request metadata declares a Pulpo admission hold.

This check reads only GitHub pull-request event metadata. It does not inspect or
execute pull-request code and has no authority effect beyond producing a CI
admission signal.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


MACHINE_HOLD_MARKER = "<!-- pulpo-admission: hold -->"
HOLD_LABELS = frozenset(
    {
        "blocked",
        "do-not-merge",
        "do not merge",
        "hold",
        "process-hold",
        "process hold",
    }
)
TITLE_PREFIXES = ("[draft]", "[hold]", "draft:", "hold:")


def _clean_directive_line(line: str) -> str:
    return line.strip().lower().strip("*_`#> ")


def admission_hold_reasons(pull_request: dict[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []

    if pull_request.get("draft") is True:
        reasons.append("github_draft")

    title = str(pull_request.get("title") or "").strip().lower()
    if title.startswith(TITLE_PREFIXES):
        reasons.append("title_hold")

    body = str(pull_request.get("body") or "")
    lowered_body = body.lower()
    if MACHINE_HOLD_MARKER in lowered_body:
        reasons.append("machine_hold_marker")

    # Historical Pulpo PRs used strong hold language near the top of the body.
    # Preserve compatibility without failing on ordinary narrative mentions of
    # "do not merge" later in a discussion or retrospective.
    for raw_line in body.splitlines()[:80]:
        line = _clean_directive_line(raw_line)
        if not line:
            continue
        if line.startswith("process hold") and "do not merge" in line:
            reasons.append("legacy_process_hold")
            break
        if line.startswith("draft / do not merge") or line.startswith("draft/do not merge"):
            reasons.append("legacy_draft_hold")
            break
        if line == "do not merge" or line.startswith("do not merge —") or line.startswith("do not merge -"):
            reasons.append("legacy_do_not_merge")
            break

    labels = pull_request.get("labels") or []
    for label in labels:
        if isinstance(label, dict):
            name = str(label.get("name") or "").strip().lower()
        else:
            name = str(label).strip().lower()
        if name in HOLD_LABELS:
            reasons.append(f"label:{name}")

    return tuple(dict.fromkeys(reasons))


def evaluate_event(payload: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        return True, ()
    reasons = admission_hold_reasons(pull_request)
    return not reasons, reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True, help="Path to the GitHub event JSON payload")
    args = parser.parse_args()

    payload = json.loads(Path(args.event).read_text(encoding="utf-8"))
    allowed, reasons = evaluate_event(payload)
    if allowed:
        print("pulpo admission: OPEN")
        return 0

    print("pulpo admission: HOLD")
    for reason in reasons:
        print(f"- {reason}")
    print("Remove the explicit hold condition and rerun checks before merge.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

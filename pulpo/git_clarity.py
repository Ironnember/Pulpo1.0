"""Read-only, hash-bound Git clarity for Pulpo source state.

PulpoGit reports what Git can establish about a checkout. It does not fetch,
push, checkout, merge, run hooks, execute tests, grant authority, or append to
the governance audit. The report is a portable projection, not another ledger.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Sequence
from urllib.parse import urlsplit


SCHEMA = "pulpo.git-clarity.v1"
DEFAULT_CANONICAL_REF = "refs/remotes/origin/main"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class GitClarityError(RuntimeError):
    """Raised when Git state cannot be represented without ambiguity."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git(
    repository: Path,
    *args: str,
    allowed_returncodes: tuple[int, ...] = (0,),
    git_binary: str = "git",
) -> tuple[str, int]:
    try:
        completed = subprocess.run(
            [git_binary, "--no-pager", *args],
            cwd=repository,
            env=_git_environment(),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except OSError as error:
        raise GitClarityError("git executable is unavailable") from error
    if completed.returncode not in allowed_returncodes:
        operation = args[0] if args else "command"
        raise GitClarityError(
            f"git {operation} failed with exit code {completed.returncode}"
        )
    return completed.stdout, completed.returncode


def _validated_ref(reference: str) -> str:
    if not reference.startswith("refs/") or _CONTROL.search(reference):
        raise GitClarityError("canonical ref must be a full refs/... name")
    if reference.endswith("/") or ".." in reference or "@{" in reference:
        raise GitClarityError("canonical ref is malformed")
    return reference


def _normalize_remote(remote_url: str) -> str:
    remote_url = remote_url.strip()
    if not remote_url or _CONTROL.search(remote_url):
        raise GitClarityError("origin remote URL is missing or malformed")

    if "://" in remote_url:
        parsed = urlsplit(remote_url)
        if parsed.password is not None:
            raise GitClarityError("credential-bearing origin remote URL is rejected")
        if parsed.scheme in {"http", "https"} and parsed.username is not None:
            raise GitClarityError("credential-bearing origin remote URL is rejected")
        if parsed.scheme not in {"https", "ssh"} or not parsed.hostname:
            raise GitClarityError("origin remote must use https or ssh")
        if parsed.query or parsed.fragment:
            raise GitClarityError("origin remote URL query and fragment are rejected")
        host = parsed.hostname.lower()
        path = parsed.path.lstrip("/")
    else:
        match = re.fullmatch(r"(?:[^@\s/:]+@)?([^\s/:]+):(.+)", remote_url)
        if match is None:
            raise GitClarityError("origin remote must be a network repository")
        host = match.group(1).lower()
        path = match.group(2)

    path = path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or path.startswith("/") or _CONTROL.search(path):
        raise GitClarityError("origin repository path is malformed")
    return f"{host}/{path}"


def _parse_status(raw: str) -> list[dict[str, str]]:
    records = raw.split("\0")
    if records and records[-1] == "":
        records.pop()
    parsed: list[dict[str, str]] = []
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < 4 or record[2] != " ":
            raise GitClarityError("git status output is malformed")
        code = record[:2]
        path = record[3:]
        if not path:
            raise GitClarityError("git status path is empty")
        item = {"code": code, "path": path}
        if "R" in code or "C" in code:
            index += 1
            if index >= len(records) or not records[index]:
                raise GitClarityError("git rename status is incomplete")
            item["original_path"] = records[index]
        parsed.append(item)
        index += 1
    return sorted(
        parsed,
        key=lambda item: (item["path"], item["code"], item.get("original_path", "")),
    )


def _parse_name_status(raw: str) -> list[dict[str, str]]:
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    parsed: list[dict[str, str]] = []
    index = 0
    while index < len(fields):
        code = fields[index]
        index += 1
        if not code or index >= len(fields):
            raise GitClarityError("git diff name-status output is malformed")
        if code[0] in {"R", "C"}:
            if index + 1 >= len(fields):
                raise GitClarityError("git diff rename output is incomplete")
            parsed.append(
                {
                    "code": code,
                    "original_path": fields[index],
                    "path": fields[index + 1],
                }
            )
            index += 2
        else:
            parsed.append({"code": code, "path": fields[index]})
            index += 1
    return sorted(
        parsed,
        key=lambda item: (item["path"], item["code"], item.get("original_path", "")),
    )


def _parse_commits(raw: str, limit: int = 200) -> tuple[list[dict[str, Any]], bool]:
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 4:
        raise GitClarityError("git log output is malformed")
    commits: list[dict[str, Any]] = []
    for index in range(0, len(fields), 4):
        commit, parents, committed_at, subject = fields[index : index + 4]
        if not _HEX_40.fullmatch(commit):
            raise GitClarityError("git log contains an invalid commit ID")
        try:
            timestamp = int(committed_at)
        except ValueError as error:
            raise GitClarityError("git log contains an invalid timestamp") from error
        commits.append(
            {
                "commit": commit,
                "parents": parents.split() if parents else [],
                "committed_at_unix": timestamp,
                "subject": subject,
            }
        )
    return commits[:limit], len(commits) > limit


def _relationship(head: str, canonical: str, behind: int, ahead: int) -> str:
    if head == canonical:
        if behind or ahead:
            raise GitClarityError("canonical relationship counts are inconsistent")
        return "at_canonical"
    if behind == 0 and ahead > 0:
        return "ahead_of_canonical"
    if behind > 0 and ahead == 0:
        return "behind_canonical"
    if behind > 0 and ahead > 0:
        return "diverged_from_canonical"
    raise GitClarityError("canonical relationship is indeterminate")


def _classification(relationship: str, clean: bool, branch: str | None) -> str:
    base = {
        "at_canonical": "canonical_commit",
        "ahead_of_canonical": "proposal",
        "behind_canonical": "stale",
        "diverged_from_canonical": "diverged",
    }[relationship]
    if branch is None:
        base = f"detached_{base}"
    return f"{base}_{'clean' if clean else 'dirty'}"


def collect_git_clarity(
    repository: str | Path,
    *,
    canonical_ref: str = DEFAULT_CANONICAL_REF,
    remote_name: str = "origin",
    expected_repository: str | None = None,
    git_binary: str = "git",
) -> dict[str, Any]:
    """Observe repository state through local, read-only Git commands."""

    canonical_ref = _validated_ref(canonical_ref)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", remote_name):
        raise GitClarityError("remote name is malformed")
    requested_root = Path(repository).expanduser().resolve()
    if not requested_root.is_dir():
        raise GitClarityError("repository directory is unavailable")
    top_level_raw, _ = _git(
        requested_root,
        "rev-parse",
        "--show-toplevel",
        git_binary=git_binary,
    )
    top_level = Path(top_level_raw.strip()).resolve()
    if not top_level.is_dir():
        raise GitClarityError("git top-level directory is unavailable")

    remote_raw, _ = _git(
        top_level,
        "remote",
        "get-url",
        remote_name,
        git_binary=git_binary,
    )
    repository_identity = _normalize_remote(remote_raw)
    if expected_repository is not None:
        if _CONTROL.search(expected_repository) or expected_repository != repository_identity:
            raise GitClarityError("repository identity does not match the expected canonical source")

    head_raw, _ = _git(
        top_level,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
        git_binary=git_binary,
    )
    canonical_raw, _ = _git(
        top_level,
        "rev-parse",
        "--verify",
        f"{canonical_ref}^{{commit}}",
        git_binary=git_binary,
    )
    head = head_raw.strip()
    canonical = canonical_raw.strip()
    if not _HEX_40.fullmatch(head) or not _HEX_40.fullmatch(canonical):
        raise GitClarityError("Git returned an invalid commit ID")

    branch_raw, branch_code = _git(
        top_level,
        "symbolic-ref",
        "--quiet",
        "--short",
        "HEAD",
        allowed_returncodes=(0, 1),
        git_binary=git_binary,
    )
    branch = branch_raw.strip() if branch_code == 0 else None
    upstream_raw, upstream_code = _git(
        top_level,
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
        allowed_returncodes=(0, 128),
        git_binary=git_binary,
    )
    upstream = upstream_raw.strip() if upstream_code == 0 else None

    counts_raw, _ = _git(
        top_level,
        "rev-list",
        "--left-right",
        "--count",
        f"{canonical_ref}...HEAD",
        git_binary=git_binary,
    )
    try:
        behind_text, ahead_text = counts_raw.split()
        behind, ahead = int(behind_text), int(ahead_text)
    except (ValueError, TypeError) as error:
        raise GitClarityError("Git returned invalid ahead/behind counts") from error
    relationship = _relationship(head, canonical, behind, ahead)

    head_raw, _ = _git(
        top_level,
        "show",
        "-s",
        "--format=%H%x00%T%x00%P%x00%ct%x00%s",
        "HEAD",
        git_binary=git_binary,
    )
    head_fields = head_raw.rstrip("\n").split("\0")
    if len(head_fields) != 5:
        raise GitClarityError("Git returned malformed HEAD metadata")
    head_commit, tree, parents, committed_at, subject = head_fields
    if head_commit != head or not _HEX_40.fullmatch(tree):
        raise GitClarityError("HEAD metadata does not match the resolved commit")
    try:
        committed_at_unix = int(committed_at)
    except ValueError as error:
        raise GitClarityError("HEAD commit timestamp is invalid") from error

    status_raw, _ = _git(
        top_level,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        git_binary=git_binary,
    )
    status = _parse_status(status_raw)
    tracked = [item for item in status if item["code"] != "??"]
    untracked = [item["path"] for item in status if item["code"] == "??"]
    clean = not status

    changes_raw, _ = _git(
        top_level,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-status",
        "-z",
        f"{canonical_ref}...HEAD",
        git_binary=git_binary,
    )
    proposal_changes = _parse_name_status(changes_raw)
    commits_raw, _ = _git(
        top_level,
        "log",
        "-z",
        "--format=%H%x00%P%x00%ct%x00%s",
        f"{canonical_ref}..HEAD",
        git_binary=git_binary,
    )
    proposal_commits, commits_truncated = _parse_commits(commits_raw)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "repository": {
            "identity": repository_identity,
            "worktree_name": top_level.name,
            "remote": remote_name,
        },
        "source": {
            "head": head,
            "branch": branch,
            "upstream": upstream,
            "canonical_ref": canonical_ref,
            "canonical_commit": canonical,
            "relationship": relationship,
            "ahead": ahead,
            "behind": behind,
            "local_refs_only": True,
        },
        "head_commit": {
            "commit": head,
            "tree": tree,
            "parents": parents.split() if parents else [],
            "committed_at_unix": committed_at_unix,
            "subject": subject,
        },
        "proposal": {
            "commits": proposal_commits,
            "commits_truncated": commits_truncated,
            "changed_paths": proposal_changes,
        },
        "worktree": {
            "clean": clean,
            "tracked_changes": tracked,
            "untracked_paths": sorted(untracked),
            "dirty_content_bound": False,
        },
        "classification": _classification(relationship, clean, branch),
        "verification": {
            "status": "not_executed",
            "tests_run": 0,
            "reason": "Git clarity does not execute or infer test results",
        },
        "collection": {
            "network_requested": False,
            "hooks_enabled": False,
            "repository_writes_requested": False,
        },
        "authority_effect": "none",
        "claim_boundary": {
            "observed": [
                "local repository identity and configured origin",
                "local HEAD and canonical-ref relationship",
                "committed proposal history and changed paths",
                "tracked and untracked worktree path status",
            ],
            "not_proven": [
                "that local remote-tracking refs match the current network remote",
                "contents of dirty or untracked files",
                "report authenticity against a party able to rewrite and rehash it",
                "test, build, runtime, deployment, customer, or production results",
                "authority, approval, containment, or external execution",
            ],
        },
    }
    return {**payload, "report_hash": _digest(payload)}


def verify_git_clarity(report: object) -> bool:
    """Verify report integrity and the core no-authority invariants."""

    if not isinstance(report, dict):
        return False
    supplied_hash = report.get("report_hash")
    if not isinstance(supplied_hash, str) or len(supplied_hash) != 64:
        return False
    payload = {key: value for key, value in report.items() if key != "report_hash"}
    if _digest(payload) != supplied_hash:
        return False
    if report.get("schema") != SCHEMA or report.get("authority_effect") != "none":
        return False
    source = report.get("source")
    repository = report.get("repository")
    proposal = report.get("proposal")
    worktree = report.get("worktree")
    verification = report.get("verification")
    collection = report.get("collection")
    if not all(
        isinstance(value, dict)
        for value in (source, repository, proposal, worktree, verification, collection)
    ):
        return False
    if verification.get("status") != "not_executed" or verification.get("tests_run") != 0:
        return False
    if collection != {
        "network_requested": False,
        "hooks_enabled": False,
        "repository_writes_requested": False,
    }:
        return False
    if not isinstance(repository.get("identity"), str) or not repository.get("identity"):
        return False
    if source.get("local_refs_only") is not True:
        return False
    head = source.get("head")
    canonical = source.get("canonical_commit")
    ahead = source.get("ahead")
    behind = source.get("behind")
    relationship = source.get("relationship")
    if not isinstance(head, str) or not _HEX_40.fullmatch(head):
        return False
    if not isinstance(canonical, str) or not _HEX_40.fullmatch(canonical):
        return False
    if not isinstance(ahead, int) or not isinstance(behind, int) or ahead < 0 or behind < 0:
        return False
    try:
        if _relationship(head, canonical, behind, ahead) != relationship:
            return False
    except GitClarityError:
        return False
    tracked_changes = worktree.get("tracked_changes")
    untracked_paths = worktree.get("untracked_paths")
    clean = worktree.get("clean")
    if not isinstance(tracked_changes, list) or not isinstance(untracked_paths, list):
        return False
    if not isinstance(clean, bool):
        return False
    status_empty = not tracked_changes and not untracked_paths
    if clean is not status_empty:
        return False
    if worktree.get("dirty_content_bound") is not False:
        return False
    branch = source.get("branch")
    if branch is not None and not isinstance(branch, str):
        return False
    if report.get("classification") != _classification(relationship, clean, branch):
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--canonical-ref", default=DEFAULT_CANONICAL_REF)
    parser.add_argument("--remote", default="origin")
    parser.add_argument(
        "--expected-repository",
        help="normalized host/owner/repo identity required for this report",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--require-canonical", action="store_true")
    args = parser.parse_args(argv)

    try:
        report = collect_git_clarity(
            args.repo,
            canonical_ref=args.canonical_ref,
            remote_name=args.remote,
            expected_repository=args.expected_repository,
        )
        if args.require_clean and not report["worktree"]["clean"]:
            raise GitClarityError("clean worktree required")
        if args.require_canonical and report["source"]["relationship"] != "at_canonical":
            raise GitClarityError("HEAD must equal the configured canonical ref")
        if not verify_git_clarity(report):
            raise GitClarityError("generated report failed self-verification")

        rendered = json.dumps(report, indent=2, sort_keys=True)
        if args.output is not None:
            requested_root = args.repo.expanduser().resolve()
            top_level_raw, _ = _git(requested_root, "rev-parse", "--show-toplevel")
            top_level = Path(top_level_raw.strip()).resolve()
            output = args.output.expanduser().resolve()
            if output == top_level or output.is_relative_to(top_level):
                raise GitClarityError("output path must be outside the repository")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered + "\n", encoding="utf-8")
    except (GitClarityError, OSError, UnicodeError, ValueError) as error:
        print(json.dumps({"schema": SCHEMA, "overall": "fail", "error": str(error)}, sort_keys=True))
        return 1

    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

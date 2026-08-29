"""Pulpo Local Lab V0 read-only operator entrypoint."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .local_workspace import LocalWorkspace, WorkspaceViolation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pulpo Local Lab V0 read-only workspace")
    parser.add_argument("--root", default=".", help="workspace root")
    sub = parser.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list", help="list one workspace directory")
    ls.add_argument("path", nargs="?", default=".")

    read = sub.add_parser("read", help="read one UTF-8 text file")
    read.add_argument("path")

    digest = sub.add_parser("digest", help="hash one file without decoding it")
    digest.add_argument("path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        workspace = LocalWorkspace(Path(args.root))
        if args.command == "list":
            payload = {
                "schema": "pulpo.local-lab.workspace-list.v0",
                "authority_effect": "none",
                "entries": [asdict(item) for item in workspace.list(args.path)],
            }
        elif args.command == "read":
            payload = {
                "schema": "pulpo.local-lab.workspace-read.v0",
                **asdict(workspace.read_text(args.path)),
            }
        else:
            payload = {
                "schema": "pulpo.local-lab.workspace-digest.v0",
                **asdict(workspace.digest(args.path)),
            }
    except WorkspaceViolation as exc:
        print(json.dumps({"status": "denied", "reason": str(exc), "authority_effect": "none"}, sort_keys=True))
        return 2

    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Pulpo Local Lab V0 operator entrypoint.

Read-only workspace operations carry no authority effect. The bounded edit
operation delegates authorization to the existing Pulpo governance kernel,
consumes one exact permit, then verifies the consequence through fresh
observation and reconciliation.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .kernel import GovernanceKernel, Policy
from .local_edit import (
    LocalEditViolation,
    LocalTextEdit,
    LocalTextEditExecutor,
    build_local_edit_proof,
    local_edit_intent,
    observe_local_edit,
    reconcile_local_edit,
)
from .local_workspace import LocalWorkspace, WorkspaceViolation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pulpo Local Lab V0")
    parser.add_argument("--root", default=".", help="workspace root")
    sub = parser.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list", help="list one workspace directory")
    ls.add_argument("path", nargs="?", default=".")

    read = sub.add_parser("read", help="read one UTF-8 text file")
    read.add_argument("path")

    digest = sub.add_parser("digest", help="hash one file without decoding it")
    digest.add_argument("path")

    edit = sub.add_parser("edit", help="govern one exact existing-file replacement")
    edit.add_argument("path", help="existing UTF-8 file to replace")
    edit.add_argument("--expect", required=True, help="expected current SHA-256")
    edit.add_argument("--from", dest="proposal_path", required=True, help="workspace UTF-8 file containing exact replacement")
    return parser


def _run_edit(workspace: LocalWorkspace, path: str, expected_hash: str, proposal_path: str) -> tuple[dict, int]:
    proposal = workspace.read_text(proposal_path)
    edit = LocalTextEdit(path, expected_hash, proposal.content)
    intent = local_edit_intent(edit)

    # This experimental local policy permits only the exact bounded local-edit
    # action at zero cost. The executor still cannot act without the permit.
    kernel = GovernanceKernel(
        Policy(frozenset({"edit_local_file"}), 0),
        secret=b"pulpo-local-lab-edit-v0",
    )
    decision = kernel.evaluate(intent)
    if decision.outcome != "allow" or decision.permit is None:
        return {
            "schema": "pulpo.local-lab.edit.v0",
            "status": "denied",
            "decision": decision.outcome,
            "decision_reason": decision.reason,
            "edit_hash": edit.edit_hash,
            "authority_effect": "none",
        }, 3

    executor = LocalTextEditExecutor()
    execution = executor.execute(kernel, edit, decision.permit, root=workspace.root)
    observation = observe_local_edit(edit, root=workspace.root)
    reconciliation = reconcile_local_edit(kernel, edit, execution, observation)

    # Prove the exact permit is one-use without attempting a second write.
    replay_rejected = not kernel.consume(decision.permit, intent)
    proof = build_local_edit_proof(kernel, edit, execution, observation, reconciliation)
    verified = reconciliation.verified and replay_rejected
    return {
        "schema": "pulpo.local-lab.edit.v0",
        "status": "verified" if verified else "mismatch",
        "decision": decision.outcome,
        "decision_reason": decision.reason,
        "relative_path": edit.relative_path,
        "edit_hash": edit.edit_hash,
        "expected_prior_hash": edit.expected_content_hash,
        "replacement_hash": edit.replacement_content_hash,
        "observed_hash": observation.observed_content_hash,
        "reconciliation": reconciliation.outcome,
        "reconciliation_reason": reconciliation.reason,
        "permit_replay": "rejected" if replay_rejected else "unexpectedly_allowed",
        "proof_bundle_hash": proof["bundle_hash"],
        "authority_effect": "none",
    }, 0 if verified else 5


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
            code = 0
        elif args.command == "read":
            payload = {
                "schema": "pulpo.local-lab.workspace-read.v0",
                **asdict(workspace.read_text(args.path)),
            }
            code = 0
        elif args.command == "digest":
            payload = {
                "schema": "pulpo.local-lab.workspace-digest.v0",
                **asdict(workspace.digest(args.path)),
            }
            code = 0
        else:
            payload, code = _run_edit(workspace, args.path, args.expect, args.proposal_path)
    except (WorkspaceViolation, LocalEditViolation) as exc:
        print(json.dumps({"status": "denied", "reason": str(exc), "authority_effect": "none"}, sort_keys=True))
        return 2

    print(json.dumps(payload, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

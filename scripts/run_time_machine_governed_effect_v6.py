#!/usr/bin/env python3
"""Replay governed-effect / capability-stripping probes across canonical history."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FROZEN_CANONICAL = "ca3636680ca50356406519a5722444c0742afb39"
INVARIANTS = (
    ("K15_MCP_NO_CANONICAL_MUTATION", "MCP proposal transport leaves canonical state unchanged"),
    ("K16_MCP_CAPABILITY_STRIPPED", "MCP projection retains no canonical writer capability"),
    ("K17_MCP_FROZEN_READ_ISOLATION", "Frozen MCP evidence cannot gain future canonical state"),
)

PROBE = r'''
from __future__ import annotations
import json


def row(status, reason, detail=None):
    return {"status": status, "reason": reason, "detail": detail}


def hold(reason, detail=None):
    return row("hold", reason, detail)


def fail(reason, detail=None):
    return row("fail", reason, detail)


def unavailable(reason, detail=None):
    return row("unavailable", reason, detail)


def error(reason, detail=None):
    return row("error", reason, detail)


def setup():
    try:
        from pulpo import GovernanceKernel, Intent, Policy, PulpoOrchestrator
        import pulpo.mcp_boundary as mcp
    except (ModuleNotFoundError, ImportError, AttributeError) as exc:
        return None, unavailable("mcp_capability_unavailable", type(exc).__name__)

    try:
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=b"time-machine-governed-effect-v6",
            clock=lambda: 3_000_000,
        )
        orchestrator = PulpoOrchestrator(kernel)
    except Exception as exc:
        return None, error("setup_failed", {"type": type(exc).__name__, "message": str(exc)[:160]})

    try:
        freeze = getattr(mcp, "freeze_mcp_snapshot", None)
        if freeze is None:
            projection = mcp.PulpoMCPProjection(orchestrator)
            snapshot_mode = False
        else:
            snapshot = freeze(orchestrator)
            projection = mcp.PulpoMCPProjection(snapshot)
            snapshot_mode = True
    except Exception as exc:
        return None, error("projection_setup_failed", {"type": type(exc).__name__, "message": str(exc)[:160]})

    return {
        "kernel": kernel,
        "orchestrator": orchestrator,
        "Intent": Intent,
        "projection": projection,
        "mcp": mcp,
        "snapshot_mode": snapshot_mode,
    }, None


def k15(ctx):
    kernel = ctx["kernel"]
    projection = ctx["projection"]
    before = list(kernel.audit)
    try:
        proposal = projection.propose_intent(
            "tm-v6-target",
            "agent:planner",
            "read",
            "repo:README.md",
            0,
            "tm-v6-session",
        )
    except Exception as exc:
        return error("proposal_probe_failed", {"type": type(exc).__name__, "message": str(exc)[:160]})
    after = list(kernel.audit)
    detail = {
        "audit_before": len(before),
        "audit_after": len(after),
        "proposal_has_permit": "permit" in proposal,
        "proposal_has_target_hash": "target_hash" in proposal,
        "canonical_state_mutation": proposal.get("canonical_state_mutation"),
        "governed_effect": proposal.get("governed_effect"),
        "authority_effect": proposal.get("authority_effect"),
    }
    if before == after:
        return hold("mcp_proposal_nonmutating", detail)
    return fail("mcp_proposal_mutated_canonical_state", detail)


def k16(ctx):
    projection = ctx["projection"]
    retained = []
    for name in (
        "orchestrator", "kernel", "state", "state_backend", "authority_client",
        "executor", "policy", "clock", "ledger",
    ):
        if hasattr(projection, name):
            retained.append(name)
    slots = tuple(getattr(type(projection), "__slots__", ()))
    detail = {"retained_writer_attributes": retained, "slots": list(slots)}
    if retained:
        return fail("mcp_retains_canonical_writer_capability", detail)
    return hold("mcp_writer_capability_stripped", detail)


def k17(ctx):
    if not ctx["snapshot_mode"]:
        return fail("frozen_snapshot_boundary_unavailable")
    kernel = ctx["kernel"]
    projection = ctx["projection"]
    Intent = ctx["Intent"]
    try:
        before = projection.evidence_snapshot()
        intent = Intent("agent:planner", "read", "repo:README.md", 0, "tm-v6-future-session")
        kernel.lock_target("tm-v6-future", intent)
        after = projection.evidence_snapshot()
    except Exception as exc:
        return error("frozen_read_probe_failed", {"type": type(exc).__name__, "message": str(exc)[:160]})
    detail = {
        "before_records": before.get("audit_records"),
        "after_records": after.get("audit_records"),
        "before_freshness": before.get("freshness"),
        "after_freshness": after.get("freshness"),
        "canonical_records_after_live_write": len(kernel.audit),
    }
    if before == after and before.get("freshness") == "frozen":
        return hold("frozen_read_does_not_gain_future_state", detail)
    return fail("frozen_read_leaked_live_canonical_state", detail)


def diagnostic(ctx):
    if ctx is None:
        return unavailable("target_lock_unavailable")
    kernel = ctx["kernel"]
    Intent = ctx["Intent"]
    try:
        before = len(kernel.audit)
        intent = Intent("agent:diagnostic", "read", "repo:README.md", 0, "tm-v6-diagnostic")
        kernel.lock_target("tm-v6-diagnostic", intent)
        after = len(kernel.audit)
        record = kernel.audit[-1]
    except Exception as exc:
        return unavailable("target_lock_unavailable", {"type": type(exc).__name__, "message": str(exc)[:160]})
    payload = record.get("payload", {})
    observed = after == before + 1 and "permit" not in payload
    return row(
        "observed" if observed else "not_observed",
        "canonical_mutation_without_permit" if observed else "diagnostic_not_observed",
        {
            "event": record.get("event"),
            "authority_effect": payload.get("authority_effect"),
            "audit_before": before,
            "audit_after": after,
            "permit_present": "permit" in payload,
        },
    )


ctx, setup_error = setup()
if ctx is None:
    result = {key: setup_error for key in ("K15_MCP_NO_CANONICAL_MUTATION", "K16_MCP_CAPABILITY_STRIPPED", "K17_MCP_FROZEN_READ_ISOLATION")}
    result["D01_CANONICAL_MUTATION_WITHOUT_PERMIT"] = unavailable("mcp_setup_unavailable")
else:
    result = {
        "K15_MCP_NO_CANONICAL_MUTATION": k15(ctx),
        "K16_MCP_CAPABILITY_STRIPPED": k16(ctx),
        "K17_MCP_FROZEN_READ_ISOLATION": k17(ctx),
        "D01_CANONICAL_MUTATION_WITHOUT_PERMIT": diagnostic(ctx),
    }
print(json.dumps(result, sort_keys=True))
'''


def run(command: list[str], *, cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=check)


def first_parent_history(reference: str) -> list[str]:
    completed = run(["git", "rev-list", "--first-parent", "--reverse", reference])
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def subject(commit: str) -> str:
    return run(["git", "show", "-s", "--format=%s", commit]).stdout.strip()


def probe_commit(commit: str, workspace: Path) -> dict[str, Any]:
    worktree = workspace / commit[:12]
    run(["git", "worktree", "add", "--detach", str(worktree), commit])
    try:
        completed = subprocess.run(
            [sys.executable, "-c", PROBE],
            cwd=worktree,
            text=True,
            capture_output=True,
            timeout=90,
        )
        if completed.returncode != 0:
            return {
                key: {
                    "status": "error",
                    "reason": "probe_process_failed",
                    "detail": {"returncode": completed.returncode, "stderr": completed.stderr[-600:]},
                }
                for key, _ in INVARIANTS
            } | {
                "D01_CANONICAL_MUTATION_WITHOUT_PERMIT": {
                    "status": "error",
                    "reason": "probe_process_failed",
                    "detail": {"returncode": completed.returncode},
                }
            }
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if not lines:
            raise ValueError("probe emitted no JSON")
        return json.loads(lines[-1])
    finally:
        run(["git", "worktree", "remove", "--force", str(worktree)], check=False)


def classify(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for invariant, _ in INVARIANTS:
        available = [row for row in rows if row["results"][invariant]["status"] != "unavailable"]
        holds = [row for row in available if row["results"][invariant]["status"] == "hold"]
        fails = [row for row in available if row["results"][invariant]["status"] == "fail"]
        errors = [row for row in available if row["results"][invariant]["status"] == "error"]
        first_hold = holds[0]["commit"] if holds else None
        post_hold_bad = []
        if first_hold:
            seen_hold = False
            for row in rows:
                if row["commit"] == first_hold:
                    seen_hold = True
                if seen_hold and row["results"][invariant]["status"] in {"fail", "error"}:
                    post_hold_bad.append(row["commit"])
        summary[invariant] = {
            "first_hold": first_hold,
            "available": len(available),
            "holds": len(holds),
            "fails": len(fails),
            "errors": len(errors),
            "post_first_hold_regressions": post_hold_bad,
        }
    observed = [row for row in rows if row["results"]["D01_CANONICAL_MUTATION_WITHOUT_PERMIT"]["status"] == "observed"]
    summary["D01_CANONICAL_MUTATION_WITHOUT_PERMIT"] = {
        "first_observed": observed[0]["commit"] if observed else None,
        "observed_count": len(observed),
    }
    all_hold_rows = [
        row for row in rows
        if all(row["results"][key]["status"] == "hold" for key, _ in INVARIANTS)
    ]
    summary["all_new_invariants"] = {
        "first_all_hold": all_hold_rows[0]["commit"] if all_hold_rows else None,
        "current_all_hold": bool(rows) and all(rows[-1]["results"][key]["status"] == "hold" for key, _ in INVARIANTS),
    }
    return summary


def markdown_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Time Machine Governed-Effect V6 Result",
        "",
        f"Frozen canonical reference: `{payload['frozen_canonical']}`",
        f"First-parent checkpoints scanned: **{len(payload['rows'])}**",
        "",
        "## Frozen invariants",
        "",
    ]
    for key, description in INVARIANTS:
        lines.append(f"- `{key}` — {description}")
    lines += [
        "",
        "Diagnostic: `D01_CANONICAL_MUTATION_WITHOUT_PERMIT` records when canonical target locking is observable without permit issuance. It is evidence for the governed-effect distinction, not a safety control whose presence is itself good or bad.",
        "",
        "## Summary",
        "",
    ]
    for key, _ in INVARIANTS:
        item = payload["summary"][key]
        lines.append(
            f"- `{key}`: first hold `{item['first_hold']}`; holds={item['holds']}; fails={item['fails']}; errors={item['errors']}; post-first-hold regressions={len(item['post_first_hold_regressions'])}."
        )
    diag = payload["summary"]["D01_CANONICAL_MUTATION_WITHOUT_PERMIT"]
    all_new = payload["summary"]["all_new_invariants"]
    lines += [
        f"- Diagnostic first observed: `{diag['first_observed']}`.",
        f"- First checkpoint holding all three new governed-effect invariants: `{all_new['first_all_hold']}`.",
        f"- Frozen canonical reference holds all three: **{all_new['current_all_hold']}**.",
        "",
        "## Timeline (available/failing/holding checkpoints)",
        "",
        "| Commit | K15 | K16 | K17 | Diagnostic | Subject |",
        "|---|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        statuses = [row["results"][key]["status"] for key, _ in INVARIANTS]
        diag_status = row["results"]["D01_CANONICAL_MUTATION_WITHOUT_PERMIT"]["status"]
        if any(status != "unavailable" for status in statuses) or diag_status == "observed":
            subj = row["subject"].replace("|", "\\|")
            lines.append(
                f"| `{row['commit'][:12]}` | {statuses[0]} | {statuses[1]} | {statuses[2]} | {diag_status} | {subj} |"
            )
    lines += [
        "",
        "## Claim boundary",
        "",
        "This experiment is a historical software-boundary differential only. It does not prove production deployment, external containment, third-party reproduction, repository admission enforcement, or any provider consequence.",
        "",
        "`authority_effect=none`",
        "`provider_write_attempted=false`",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", default=FROZEN_CANONICAL)
    parser.add_argument("--out", default="artifacts/time-machine-governed-effect-v6")
    args = parser.parse_args()

    reference = run(["git", "rev-parse", args.reference]).stdout.strip()
    if reference != FROZEN_CANONICAL:
        raise SystemExit(f"frozen canonical mismatch: expected {FROZEN_CANONICAL}, got {reference}")

    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="pulpo-tm-v6-") as directory:
        workspace = Path(directory)
        for commit in first_parent_history(reference):
            rows.append({
                "commit": commit,
                "subject": subject(commit),
                "results": probe_commit(commit, workspace),
            })

    payload = {
        "schema": "pulpo.time-machine-governed-effect.v6",
        "frozen_canonical": reference,
        "invariants": [{"id": key, "description": description} for key, description in INVARIANTS],
        "rows": rows,
        "summary": classify(rows),
        "authority_effect": "none",
        "provider_write_attempted": False,
    }
    (out / "result.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    (out / "RESULT.md").write_text(markdown_report(payload))

    current_ok = payload["summary"]["all_new_invariants"]["current_all_hold"]
    regressions = sum(
        len(payload["summary"][key]["post_first_hold_regressions"])
        for key, _ in INVARIANTS
    )
    errors = sum(payload["summary"][key]["errors"] for key, _ in INVARIANTS)
    print(json.dumps({
        "frozen_canonical": reference,
        "checkpoints": len(rows),
        "current_all_hold": current_ok,
        "post_first_hold_regressions": regressions,
        "probe_errors": errors,
        "result_json": str(out / "result.json"),
        "result_markdown": str(out / "RESULT.md"),
    }, sort_keys=True))
    return 0 if current_ok and regressions == 0 and errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

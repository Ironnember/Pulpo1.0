#!/usr/bin/env python3
"""Replay frozen constitutional probes against exact historical Pulpo commits.

The runner checks out each historical SHA into a detached temporary worktree,
writes an untracked probe file into that worktree, executes it with that
commit's Python sources, records the boolean control result, and deletes the
worktree. Historical refs and source files are never modified.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable


CURRENT = "2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8"


@dataclass(frozen=True)
class Case:
    transition: str
    commit: str
    expected: bool
    probe: str
    classification: str


CASES = (
    Case("T1_directive_authority_seam", "4ee6af94ea8c55d2393351ffcb17f3dcdc792d08", False, "directive_seam", "capability_emergence"),
    Case("T1_directive_authority_seam", "81338eed28ec32fe214c7eee086a82840ca0923f", True, "directive_seam", "capability_emergence"),
    Case("T2_execution_time_revocation", "81338eed28ec32fe214c7eee086a82840ca0923f", False, "directive_revocation", "before_after_regression"),
    Case("T2_execution_time_revocation", "da39afed5c45b0c3b7d3b9c372542fe1962645ce", False, "directive_revocation", "before_after_regression"),
    Case("T2_execution_time_revocation", "b9d375dcaf962745241ca45d0a601cf3a7a74bf1", True, "directive_revocation", "before_after_regression"),
    Case("T2_execution_time_revocation", "fc941266a608d7b654cc647532ac965f81582535", True, "directive_revocation", "before_after_regression"),
    Case("T3_target_mismatch_precedes_authority", "ec91f6f51a115f0fda6e163b9012518c97b322a0", False, "target_mismatch", "capability_emergence"),
    Case("T3_target_mismatch_precedes_authority", "fc941266a608d7b654cc647532ac965f81582535", True, "target_mismatch", "capability_emergence"),
    Case("T3_target_mismatch_precedes_authority", CURRENT, True, "target_mismatch", "persistence"),
    Case("T4_kernel_owned_directive_sources", "fc941266a608d7b654cc647532ac965f81582535", False, "parallel_directive_sources", "hardening"),
    Case("T4_kernel_owned_directive_sources", "1209b7a3666e928e6a0bcfcb34be0334666a6718", True, "parallel_directive_sources", "hardening"),
    Case("T4_kernel_owned_directive_sources", CURRENT, True, "parallel_directive_sources", "persistence"),
)


COMMON = r'''
import json
import sys

def emit(control_holds, reason, detail=None):
    print(json.dumps({
        "control_holds": bool(control_holds),
        "reason": reason,
        "detail": detail,
    }, sort_keys=True))
    raise SystemExit(0)
'''


PROBES = {
    "directive_seam": COMMON + r'''
try:
    from pulpo import GovernanceKernel, Intent, Policy
    from pulpo.directives import Directive, GovernedDirectiveProjection
    from pulpo.state import InMemoryKernelState
except Exception as exc:
    emit(False, "directive_authority_seam_unavailable", type(exc).__name__)

NOW = 2_000_000
state = InMemoryKernelState()
d = Directive(
    directive_id="tm-directive",
    version=1,
    issuer_authority_id="authority:test-owner",
    principal="agent:builder",
    allowed_actions=frozenset({"write"}),
    resource_prefixes=("repo:",),
    max_cost=5,
    issued_at_ns=1_000_000,
    expires_at_ns=3_000_000,
)
try:
    kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm", clock=lambda: NOW, state=state)
    try:
        projection = GovernedDirectiveProjection(kernel)
    except TypeError:
        projection = GovernedDirectiveProjection(kernel, state, lambda: NOW)
    decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 1), d)
    emit(decision.outcome == "deny" and decision.reason == "directive_not_authorized", "unauthenticated_directive_denied", decision.reason)
except Exception as exc:
    emit(False, "directive_seam_probe_error", type(exc).__name__)
''',
    "directive_revocation": COMMON + r'''
try:
    from pulpo import GovernanceKernel, Intent, Policy
    from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
    from pulpo.state import InMemoryKernelState
    from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
except Exception as exc:
    emit(False, "directive_revocation_path_unavailable", type(exc).__name__)

NOW = 2_000_000
OPERATOR = "operator:owner"
state = InMemoryKernelState()
verifier = HmacTestVerifier()
policy = Policy(
    frozenset({"write", "activate_directive", "revoke_directive"}),
    100,
    frozenset({"activate_directive", "revoke_directive"}),
    authority_trust=trust_for(verifier),
)
kernel = GovernanceKernel(policy, secret=b"tm", approval_verifier=verifier, clock=lambda: NOW, state=state)
d = Directive(
    directive_id="tm-revoke",
    version=1,
    issuer_authority_id="authority:test-owner",
    principal="agent:builder",
    allowed_actions=frozenset({"write"}),
    resource_prefixes=("repo:",),
    max_cost=5,
    issued_at_ns=1_000_000,
    expires_at_ns=3_000_000,
)
try:
    controller = DirectiveAuthorityController(kernel, state, lambda: NOW)
    projection = GovernedDirectiveProjection(kernel, state, lambda: NOW)
except TypeError:
    controller = DirectiveAuthorityController(kernel)
    projection = GovernedDirectiveProjection(kernel)

def approval(operation, approval_id, nonce):
    intent = DirectiveAuthorityController.authority_intent(operation, d, operator_principal=OPERATOR)
    return signed_envelope(kernel, intent, verifier, now_ns=NOW - 10, approval_id=approval_id, nonce=nonce)

activation = controller.activate(d, approval(controller.ACTIVATE, "activate-1", "activate-nonce-1"), operator_principal=OPERATOR)
if activation.outcome != "allow":
    emit(False, "activation_failed", activation.reason)
intent = Intent("agent:builder", "write", "repo:file", 1)
decision = projection.evaluate(intent, d)
if decision.outcome != "allow" or not decision.permit:
    emit(False, "permit_not_issued", decision.reason)
revocation = controller.revoke(d, approval(controller.REVOKE, "revoke-1", "revoke-nonce-1"), operator_principal=OPERATOR)
if revocation.outcome != "allow":
    emit(False, "revocation_failed", revocation.reason)
consumed = kernel.consume(decision.permit, intent)
emit(not consumed, "revoked_preissued_permit_denied" if not consumed else "stale_permit_consumed")
''',
    "target_mismatch": COMMON + r'''
try:
    from pulpo import GovernanceKernel, Intent, Policy
except Exception as exc:
    emit(False, "kernel_unavailable", type(exc).__name__)

NOW = 1_900_000_000_000_000_000
kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm", clock=lambda: NOW)
intent = Intent("agent:builder", "write", "repo:README.md", 5, "tm-session")
try:
    target = kernel.lock_target("TM-TARGET", intent)
    before = sum(record["event"] == "decision" for record in kernel.audit)
    resolution, decision = kernel.evaluate_locked_target("TM-TARGET", "0" * 64)
    after = sum(record["event"] == "decision" for record in kernel.audit)
except (AttributeError, TypeError) as exc:
    emit(False, "target_lock_control_unavailable", type(exc).__name__)
except Exception as exc:
    emit(False, "target_probe_error", type(exc).__name__)

holds = resolution.outcome == "deny" and resolution.reason == "target_hash_mismatch" and decision is None and before == after
emit(holds, "target_mismatch_failed_closed" if holds else "target_mismatch_reached_authority", getattr(resolution, "reason", None))
''',
    "parallel_directive_sources": COMMON + r'''
try:
    from pulpo import GovernanceKernel, Policy
    from pulpo.directives import DirectiveAuthorityController, GovernedDirectiveProjection
    from pulpo.state import InMemoryKernelState
except Exception as exc:
    emit(False, "directive_components_unavailable", type(exc).__name__)

NOW = 2_000_000
state = InMemoryKernelState()
kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm", clock=lambda: NOW, state=state)
controller_rejected = False
projection_rejected = False
try:
    DirectiveAuthorityController(kernel, InMemoryKernelState(), lambda: NOW)
except TypeError:
    controller_rejected = True
try:
    GovernedDirectiveProjection(kernel, InMemoryKernelState(), lambda: NOW)
except TypeError:
    projection_rejected = True
emit(controller_rejected and projection_rejected, "parallel_sources_rejected" if controller_rejected and projection_rejected else "parallel_sources_accepted", {"controller_rejected": controller_rejected, "projection_rejected": projection_rejected})
''',
}


def run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=check)


def ensure_commit(root: Path, sha: str) -> None:
    completed = run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], root, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"historical commit unavailable: {sha}")


def execute_case(root: Path, case: Case, scratch: Path) -> dict[str, object]:
    ensure_commit(root, case.commit)
    worktree = scratch / case.commit[:12]
    if worktree.exists():
        shutil.rmtree(worktree)
    run(["git", "worktree", "add", "--detach", str(worktree), case.commit], root)
    probe_file = worktree / ".time_machine_probe.py"
    probe_file.write_text(PROBES[case.probe], encoding="utf-8")
    try:
        completed = run([sys.executable, "-B", str(probe_file)], worktree, check=False)
        last = next((line for line in reversed(completed.stdout.splitlines()) if line.strip().startswith("{")), "")
        if not last:
            observed = False
            payload: dict[str, object] = {"control_holds": False, "reason": "probe_no_json", "stderr": completed.stderr[-500:]}
        else:
            try:
                payload = json.loads(last)
                observed = bool(payload.get("control_holds"))
            except json.JSONDecodeError:
                observed = False
                payload = {"control_holds": False, "reason": "probe_invalid_json", "stdout": completed.stdout[-500:]}
        matches = observed is case.expected
        return {
            "transition": case.transition,
            "classification": case.classification,
            "commit": case.commit,
            "probe": case.probe,
            "expected_control_holds": case.expected,
            "observed_control_holds": observed,
            "matches_expected": matches,
            "probe_returncode": completed.returncode,
            "probe_evidence": payload,
        }
    finally:
        probe_file.unlink(missing_ok=True)
        run(["git", "worktree", "remove", "--force", str(worktree)], root, check=False)
        run(["git", "worktree", "prune"], root, check=False)


def summarize(cases: Iterable[dict[str, object]]) -> dict[str, object]:
    rows = list(cases)
    matched = sum(bool(row["matches_expected"]) for row in rows)
    transitions: dict[str, dict[str, object]] = {}
    for row in rows:
        item = transitions.setdefault(str(row["transition"]), {"cases": 0, "matched": 0})
        item["cases"] = int(item["cases"]) + 1
        item["matched"] = int(item["matched"]) + int(bool(row["matches_expected"]))
    return {
        "schema": "pulpo.time-machine-differential.v1",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "current_canonical_sha": CURRENT,
        "cases_total": len(rows),
        "cases_matching_expected": matched,
        "cases_unexpected": len(rows) - matched,
        "result": "pass" if matched == len(rows) else "fail",
        "transitions": transitions,
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="pulpo-time-machine-") as tmp:
        scratch = Path(tmp)
        results = [execute_case(root, case, scratch) for case in CASES]
    report = summarize(results)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

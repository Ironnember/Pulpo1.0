#!/usr/bin/env python3
"""Replay frozen constitutional probes across canonical first-parent history."""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, fields, replace
from hashlib import sha256
import hmac
import html
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FROZEN_CANONICAL = "2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8"
INVARIANTS = (
    ("K01_DEFAULT_DENY", "Unknown action is denied"),
    ("K02_BUDGET_CEILING", "Over-budget intent is denied"),
    ("K03_ONE_USE_PERMIT", "Permit consumes once and replay is denied"),
    ("K04_INVALID_APPROVAL_SIGNATURE", "Corrupted approval signature is denied"),
    ("K05_APPROVAL_INTENT_BINDING", "Approval cannot authorize a different intent"),
    ("K06_RESTART_REPLAY_DENIAL", "Spent permit remains spent after restart"),
    ("K07_AUDIT_INTEGRITY", "Durable audit chain verifies after restart"),
    ("K08_DIRECTIVE_AUTHORITY_SEAM", "Unauthenticated directive projection cannot create authority"),
    ("K09_EXECUTION_TIME_REVOCATION", "Directive revocation kills a pre-issued permit"),
    ("K10_TARGET_MISMATCH_PRECEDES_AUTHORITY", "Wrong target hash denies before governance evaluation"),
    ("K11_KERNEL_OWNS_DIRECTIVE_SOURCES", "Alternate directive state and clock injection is rejected"),
    ("K12_CUSTODY_MONOTONIC_CAS", "Custody head advances monotonically and rejects stale reuse"),
    ("K13_CUSTODY_CLOCK_ROLLBACK", "Custody rejects trusted-time rollback"),
    ("K14_CUSTODY_RECEIPT_INTEGRITY", "Custody receipt verifies and tampering fails verification"),
)
INVARIANT_IDS = tuple(item[0] for item in INVARIANTS)


PROBE = r'''
from __future__ import annotations
from dataclasses import fields, replace
import hashlib
import hmac
import json
from pathlib import Path
import tempfile

NOW = 91_000_000


def row(status, reason, detail=None):
    return {"status": status, "reason": reason, "detail": detail}


def unavailable(reason, detail=None):
    return row("unavailable", reason, detail)


def hold(reason, detail=None):
    return row("hold", reason, detail)


def fail(reason, detail=None):
    return row("fail", reason, detail)


def safe(name, fn):
    try:
        return fn()
    except (ModuleNotFoundError, ImportError, AttributeError) as exc:
        return unavailable("capability_unavailable", type(exc).__name__)
    except Exception as exc:
        return row("error", "probe_exception", {"type": type(exc).__name__, "message": str(exc)[:160]})


def kernel_basic():
    from pulpo import GovernanceKernel, Intent, Policy
    return GovernanceKernel, Intent, Policy


def k01():
    GovernanceKernel, Intent, Policy = kernel_basic()
    kernel = GovernanceKernel(Policy(frozenset({"read"}), 10), secret=b"tm-v2")
    decision = kernel.evaluate(Intent("agent", "delete", "repo:file", 0))
    return hold("default_deny") if decision.outcome == "deny" else fail("unknown_action_not_denied", decision.outcome)


def k02():
    GovernanceKernel, Intent, Policy = kernel_basic()
    kernel = GovernanceKernel(Policy(frozenset({"write"}), 10), secret=b"tm-v2")
    decision = kernel.evaluate(Intent("agent", "write", "repo:file", 11))
    return hold("budget_ceiling") if decision.outcome == "deny" else fail("over_budget_not_denied", decision.outcome)


def k03():
    GovernanceKernel, Intent, Policy = kernel_basic()
    kernel = GovernanceKernel(Policy(frozenset({"write"}), 10), secret=b"tm-v2")
    intent = Intent("agent", "write", "repo:file", 1)
    decision = kernel.evaluate(intent)
    if decision.outcome != "allow" or getattr(decision, "permit", None) is None:
        return fail("permit_not_issued", getattr(decision, "reason", None))
    first = kernel.consume(decision.permit, intent)
    second = kernel.consume(decision.permit, intent)
    return hold("one_use_permit") if first and not second else fail("permit_replay_not_denied", {"first": first, "second": second})


class TestVerifier:
    authority_id = "authority:test-owner"
    verifier_id = "verifier:test-only"
    key_id = "key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"pulpo-test-verifier-key").hexdigest()

    def __init__(self, secret=b"external-test-authority"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def authority_setup():
    from pulpo import ApprovalEnvelope, GovernanceKernel, Intent, Policy
    if not hasattr(GovernanceKernel, "evaluate_with_approval"):
        raise AttributeError("approval path unavailable")
    verifier = TestVerifier()
    trust = None
    try:
        from pulpo import AuthorityTrust
        trust = AuthorityTrust(
            authority_id=verifier.authority_id,
            verifier_id=verifier.verifier_id,
            key_id=verifier.key_id,
            algorithm=verifier.algorithm,
            key_fingerprint=verifier.key_fingerprint,
            deployment_id="deployment:test",
            max_approval_ttl_ns=10_000,
        )
    except (ImportError, AttributeError):
        trust = None
    kwargs = {"authority_trust": trust} if trust is not None else {}
    try:
        policy = Policy(frozenset({"read", "push"}), 100, frozenset({"push"}), **kwargs)
    except TypeError:
        policy = Policy(
            frozenset({"read", "push"}),
            100,
            approval_actions=frozenset({"push"}),
            **kwargs,
        )
    kernel = GovernanceKernel(
        policy,
        secret=b"tm-v2-authority",
        approval_verifier=verifier,
        clock=lambda: NOW,
    )
    intent = Intent("agent:publisher", "push", "repo:origin/main", 0, "tm-v2-session")
    names = {field.name for field in fields(ApprovalEnvelope)}
    values = {
        "approval_id": "approval-1",
        "authority_id": verifier.authority_id,
        "verifier_id": verifier.verifier_id,
        "key_id": verifier.key_id,
        "deployment_id": "deployment:test",
        "trust_hash": getattr(trust, "trust_hash", None),
        "session_id": intent.session_id,
        "principal": intent.principal,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "nonce": "approval-nonce-1",
        "issued_at_ns": NOW,
        "expires_at_ns": NOW + 1_000,
        "signature": "",
    }
    unsigned = ApprovalEnvelope(**{key: value for key, value in values.items() if key in names})
    envelope = replace(unsigned, signature=verifier.sign(unsigned.signing_bytes()))
    return kernel, intent, verifier, envelope


def k04():
    try:
        kernel, intent, _, envelope = authority_setup()
    except (ModuleNotFoundError, ImportError, AttributeError, TypeError, ValueError) as exc:
        return unavailable("approval_capability_unavailable", type(exc).__name__)
    invalid = replace(envelope, signature="invalid")
    decision = kernel.evaluate_with_approval(intent, invalid)
    ok = decision.outcome == "deny" and "signature" in str(decision.reason)
    return hold("invalid_signature_denied", decision.reason) if ok else fail("invalid_signature_not_denied", {"outcome": decision.outcome, "reason": decision.reason})


def k05():
    try:
        kernel, intent, _, envelope = authority_setup()
    except (ModuleNotFoundError, ImportError, AttributeError, TypeError, ValueError) as exc:
        return unavailable("approval_capability_unavailable", type(exc).__name__)
    from dataclasses import replace as dc_replace
    changed = dc_replace(intent, resource="repo:other")
    decision = kernel.evaluate_with_approval(changed, envelope)
    ok = decision.outcome == "deny" and "intent" in str(decision.reason)
    return hold("approval_intent_bound", decision.reason) if ok else fail("approval_cross_intent", {"outcome": decision.outcome, "reason": decision.reason})


def k06():
    try:
        from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState
    except (ModuleNotFoundError, ImportError) as exc:
        return unavailable("sqlite_kernel_state_unavailable", type(exc).__name__)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "kernel.sqlite3"
        try:
            first_state = SQLiteKernelState(path)
            first = GovernanceKernel(Policy(frozenset({"write"}), 10), secret=b"tm-v2", clock=lambda: NOW, state=first_state)
        except TypeError as exc:
            return unavailable("restart_state_injection_unavailable", type(exc).__name__)
        intent = Intent("agent", "write", "repo:file", 1)
        decision = first.evaluate(intent)
        if decision.outcome != "allow" or not first.consume(decision.permit, intent):
            return fail("initial_permit_flow_failed")
        first_state.close()
        second_state = SQLiteKernelState(path)
        second = GovernanceKernel(Policy(frozenset({"write"}), 10), secret=b"tm-v2", clock=lambda: NOW + 1, state=second_state)
        replay = second.consume(decision.permit, intent)
        second_state.close()
        return hold("restart_replay_denied") if not replay else fail("spent_permit_replayed_after_restart")


def k07():
    try:
        from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState
    except (ModuleNotFoundError, ImportError) as exc:
        return unavailable("sqlite_kernel_state_unavailable", type(exc).__name__)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "kernel.sqlite3"
        try:
            first_state = SQLiteKernelState(path)
            first = GovernanceKernel(Policy(frozenset({"read"}), 10), secret=b"tm-v2", clock=lambda: NOW, state=first_state)
        except TypeError as exc:
            return unavailable("durable_audit_unavailable", type(exc).__name__)
        first.evaluate(Intent("agent", "read", "repo:file", 0))
        if not first.verify_audit():
            return fail("audit_invalid_before_restart")
        first_state.close()
        second_state = SQLiteKernelState(path)
        second = GovernanceKernel(Policy(frozenset({"read"}), 10), secret=b"tm-v2", clock=lambda: NOW + 1, state=second_state)
        valid = second.verify_audit()
        second_state.close()
        return hold("durable_audit_verifies") if valid else fail("audit_invalid_after_restart")


def directive_object(Directive):
    return Directive(
        directive_id="tm-v2-directive",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=100_000_000,
    )


def k08():
    try:
        from pulpo import GovernanceKernel, Intent, Policy
        from pulpo.directives import Directive, GovernedDirectiveProjection
        from pulpo.state import InMemoryKernelState
    except (ModuleNotFoundError, ImportError) as exc:
        return unavailable("directive_authority_seam_unavailable", type(exc).__name__)
    state = InMemoryKernelState()
    kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm-v2", clock=lambda: NOW, state=state)
    directive = directive_object(Directive)
    try:
        projection = GovernedDirectiveProjection(kernel)
    except TypeError:
        try:
            projection = GovernedDirectiveProjection(kernel, state, lambda: NOW)
        except TypeError as exc:
            return unavailable("directive_projection_api_unavailable", type(exc).__name__)
    decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 1), directive)
    ok = decision.outcome == "deny" and decision.reason == "directive_not_authorized"
    return hold("unauthenticated_directive_denied", decision.reason) if ok else fail("directive_authority_created_without_activation", {"outcome": decision.outcome, "reason": decision.reason})


def directive_authority_setup():
    from pulpo import GovernanceKernel, Intent, Policy
    from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
    from pulpo.state import InMemoryKernelState
    try:
        from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
    except (ModuleNotFoundError, ImportError) as exc:
        raise AttributeError("directive authority fixture unavailable") from exc
    state = InMemoryKernelState()
    verifier = HmacTestVerifier()
    kwargs = {}
    try:
        kwargs["authority_trust"] = trust_for(verifier)
    except Exception:
        kwargs = {}
    policy = Policy(
        frozenset({"write", "activate_directive", "revoke_directive"}),
        100,
        frozenset({"activate_directive", "revoke_directive"}),
        **kwargs,
    )
    kernel = GovernanceKernel(policy, secret=b"tm-v2", approval_verifier=verifier, clock=lambda: NOW, state=state)
    directive = directive_object(Directive)
    try:
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
    except TypeError:
        controller = DirectiveAuthorityController(kernel, state, lambda: NOW)
        projection = GovernedDirectiveProjection(kernel, state, lambda: NOW)
    operator = "operator:owner"
    def envelope(operation, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(operation, directive, operator_principal=operator)
        try:
            return signed_envelope(kernel, intent, verifier, now_ns=NOW, approval_id=approval_id, nonce=nonce)
        except TypeError:
            return signed_envelope(kernel, intent, verifier, approval_id=approval_id, nonce=nonce)
    return kernel, Intent, directive, controller, projection, operator, envelope


def k09():
    try:
        kernel, Intent, directive, controller, projection, operator, envelope = directive_authority_setup()
    except (ModuleNotFoundError, ImportError, AttributeError, TypeError, ValueError) as exc:
        return unavailable("directive_revocation_path_unavailable", type(exc).__name__)
    activation = controller.activate(directive, envelope(controller.ACTIVATE, "activate-1", "activate-nonce-1"), operator_principal=operator)
    if activation.outcome != "allow":
        return fail("directive_activation_failed", activation.reason)
    intent = Intent("agent:builder", "write", "repo:file", 1)
    decision = projection.evaluate(intent, directive)
    if decision.outcome != "allow" or getattr(decision, "permit", None) is None:
        return fail("directive_bound_permit_not_issued", decision.reason)
    revocation = controller.revoke(directive, envelope(controller.REVOKE, "revoke-1", "revoke-nonce-1"), operator_principal=operator)
    if revocation.outcome != "allow":
        return fail("directive_revocation_failed", revocation.reason)
    consumed = kernel.consume(decision.permit, intent)
    return hold("revoked_preissued_permit_denied") if not consumed else fail("stale_directive_permit_consumed")


def k10():
    from pulpo import GovernanceKernel, Intent, Policy
    try:
        kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm-v2", clock=lambda: NOW)
    except TypeError:
        try:
            kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm-v2")
        except TypeError as exc:
            return unavailable("target_lock_kernel_api_unavailable", type(exc).__name__)
    if not hasattr(kernel, "lock_target") or not hasattr(kernel, "evaluate_locked_target"):
        return unavailable("target_lock_control_unavailable")
    intent = Intent("agent:builder", "write", "repo:README.md", 5, "tm-v2")
    kernel.lock_target("TM-V2-TARGET", intent)
    before = sum(record["event"] == "decision" for record in kernel.audit)
    resolution, decision = kernel.evaluate_locked_target("TM-V2-TARGET", "0" * 64)
    after = sum(record["event"] == "decision" for record in kernel.audit)
    ok = resolution.outcome == "deny" and resolution.reason == "target_hash_mismatch" and decision is None and before == after
    return hold("target_mismatch_precedes_authority", resolution.reason) if ok else fail("target_mismatch_reached_authority", {"reason": resolution.reason, "decision_created": before != after})


def k11():
    try:
        from pulpo import GovernanceKernel, Policy
        from pulpo.directives import DirectiveAuthorityController, GovernedDirectiveProjection
        from pulpo.state import InMemoryKernelState
    except (ModuleNotFoundError, ImportError) as exc:
        return unavailable("directive_components_unavailable", type(exc).__name__)
    state = InMemoryKernelState()
    kernel = GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"tm-v2", clock=lambda: NOW, state=state)
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
    if controller_rejected and projection_rejected:
        return hold("parallel_directive_sources_rejected")
    return fail("parallel_directive_sources_accepted", {"controller_rejected": controller_rejected, "projection_rejected": projection_rejected})


def custody_setup(clock):
    try:
        from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
    except (ModuleNotFoundError, ImportError) as exc:
        raise AttributeError("custody unavailable") from exc
    directory = tempfile.TemporaryDirectory()
    path = Path(directory.name) / "custody.sqlite3"
    custody = SQLiteGovernanceCustody(path, signing_secret=b"tm-v2-custody", clock=lambda: clock[0])
    return directory, custody, CustodyViolation


def hashes(seed):
    return tuple(hashlib.sha256(f"{seed}:{name}".encode()).hexdigest() for name in ("object", "target", "permit", "authorization"))


def k12():
    clock = [NOW]
    try:
        directory, custody, CustodyViolation = custody_setup(clock)
    except (AttributeError, TypeError, ValueError) as exc:
        return unavailable("custody_unavailable", type(exc).__name__)
    try:
        head = custody.snapshot()
        obj, target, permit, auth = hashes("k12")
        first = custody.authorize_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            object_hash=obj,
            target_hash=target,
            permit_hash=permit,
            authorization_hash=auth,
        )
        advanced = custody.snapshot()
        rejected = False
        reason = None
        try:
            custody.authorize_attempt(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                object_hash=obj,
                target_hash=target,
                permit_hash=permit,
                authorization_hash=auth,
            )
        except CustodyViolation as exc:
            rejected = True
            reason = str(exc)
        ok = first.receipt.epoch == head.epoch + 1 and advanced.epoch == head.epoch + 1 and rejected
        return hold("monotonic_custody_cas", reason) if ok else fail("custody_stale_reuse_not_denied", {"advanced_epoch": advanced.epoch, "rejected": rejected, "reason": reason})
    finally:
        directory.cleanup()


def k13():
    clock = [NOW]
    try:
        directory, custody, CustodyViolation = custody_setup(clock)
    except (AttributeError, TypeError, ValueError) as exc:
        return unavailable("custody_unavailable", type(exc).__name__)
    try:
        head = custody.snapshot()
        obj, target, permit, auth = hashes("k13a")
        custody.authorize_attempt(expected_epoch=head.epoch, expected_state_root=head.state_root, object_hash=obj, target_hash=target, permit_hash=permit, authorization_hash=auth)
        current = custody.snapshot()
        clock[0] = NOW - 1
        obj2, target2, permit2, auth2 = hashes("k13b")
        try:
            custody.authorize_attempt(expected_epoch=current.epoch, expected_state_root=current.state_root, object_hash=obj2, target_hash=target2, permit_hash=permit2, authorization_hash=auth2)
        except CustodyViolation as exc:
            return hold("custody_clock_rollback_denied", str(exc)) if "clock_rollback" in str(exc) else fail("custody_denied_for_other_reason", str(exc))
        return fail("custody_clock_rollback_accepted")
    finally:
        directory.cleanup()


def k14():
    clock = [NOW]
    try:
        directory, custody, _ = custody_setup(clock)
    except (AttributeError, TypeError, ValueError) as exc:
        return unavailable("custody_unavailable", type(exc).__name__)
    try:
        head = custody.snapshot()
        obj, target, permit, auth = hashes("k14")
        authorized = custody.authorize_attempt(expected_epoch=head.epoch, expected_state_root=head.state_root, object_hash=obj, target_hash=target, permit_hash=permit, authorization_hash=auth)
        receipt = authorized.receipt
        valid = custody.verify_receipt(receipt)
        tampered = replace(receipt, state_root="0" * 64)
        invalid = custody.verify_receipt(tampered)
        return hold("custody_receipt_integrity") if valid and not invalid else fail("custody_receipt_integrity_failed", {"valid": valid, "tampered_valid": invalid})
    finally:
        directory.cleanup()


PROBES = {
    "K01_DEFAULT_DENY": k01,
    "K02_BUDGET_CEILING": k02,
    "K03_ONE_USE_PERMIT": k03,
    "K04_INVALID_APPROVAL_SIGNATURE": k04,
    "K05_APPROVAL_INTENT_BINDING": k05,
    "K06_RESTART_REPLAY_DENIAL": k06,
    "K07_AUDIT_INTEGRITY": k07,
    "K08_DIRECTIVE_AUTHORITY_SEAM": k08,
    "K09_EXECUTION_TIME_REVOCATION": k09,
    "K10_TARGET_MISMATCH_PRECEDES_AUTHORITY": k10,
    "K11_KERNEL_OWNS_DIRECTIVE_SOURCES": k11,
    "K12_CUSTODY_MONOTONIC_CAS": k12,
    "K13_CUSTODY_CLOCK_ROLLBACK": k13,
    "K14_CUSTODY_RECEIPT_INTEGRITY": k14,
}

result = {name: safe(name, fn) for name, fn in PROBES.items()}
print(json.dumps(result, sort_keys=True))
'''


def run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=check)


def canonical_commits() -> list[str]:
    completed = run(["git", "rev-list", "--first-parent", "--reverse", FROZEN_CANONICAL], ROOT)
    commits = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not commits or commits[-1] != FROZEN_CANONICAL:
        raise RuntimeError("canonical first-parent lineage could not be frozen")
    return commits


def metadata(sha: str) -> dict[str, str]:
    completed = run(["git", "show", "-s", "--format=%H%x00%aI%x00%s", sha], ROOT)
    commit, authored_at, subject = completed.stdout.rstrip("\n").split("\x00", 2)
    return {"sha": commit, "authored_at": authored_at, "subject": subject}


def scan_commit(sha: str, scratch: Path) -> dict[str, Any]:
    worktree = scratch / sha[:12]
    run(["git", "worktree", "add", "--detach", str(worktree), sha], ROOT)
    probe_path = worktree / ".time_machine_lineage_probe.py"
    probe_path.write_text(PROBE, encoding="utf-8")
    try:
        completed = run([sys.executable, "-B", str(probe_path)], worktree, check=False)
        line = next((item for item in reversed(completed.stdout.splitlines()) if item.strip().startswith("{")), "")
        if not line:
            results = {key: {"status": "error", "reason": "probe_no_json", "detail": completed.stderr[-300:]} for key in INVARIANT_IDS}
        else:
            try:
                parsed = json.loads(line)
                results = {}
                for key in INVARIANT_IDS:
                    value = parsed.get(key)
                    if not isinstance(value, dict) or value.get("status") not in {"hold", "fail", "unavailable", "error"}:
                        results[key] = {"status": "error", "reason": "probe_result_invalid", "detail": value}
                    else:
                        results[key] = value
            except json.JSONDecodeError:
                results = {key: {"status": "error", "reason": "probe_invalid_json", "detail": line[-300:]} for key in INVARIANT_IDS}
        counts = {status: sum(1 for result in results.values() if result["status"] == status) for status in ("hold", "fail", "unavailable", "error")}
        absolute = round(counts["hold"] / len(INVARIANT_IDS) * 100, 2)
        implemented = counts["hold"] + counts["fail"]
        health = round(counts["hold"] / implemented * 100, 2) if implemented else None
        return {
            **metadata(sha),
            "probe_returncode": completed.returncode,
            "counts": counts,
            "absolute_strength": absolute,
            "implemented_health": health,
            "invariants": results,
        }
    finally:
        probe_path.unlink(missing_ok=True)
        run(["git", "worktree", "remove", "--force", str(worktree)], ROOT, check=False)
        run(["git", "worktree", "prune"], ROOT, check=False)


def evolution(checkpoints: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for invariant_id, title in INVARIANTS:
        states = [(item["sha"], item["invariants"][invariant_id]["status"]) for item in checkpoints]
        first_hold_index = next((i for i, (_, status) in enumerate(states) if status == "hold"), None)
        regressions = []
        recovered = []
        active_regression = None
        if first_hold_index is not None:
            previous = "hold"
            for index in range(first_hold_index + 1, len(states)):
                sha, status = states[index]
                if previous == "hold" and status in {"fail", "unavailable"}:
                    active_regression = {"started_sha": sha, "started_status": status, "recovered_sha": None}
                    regressions.append(active_regression)
                if active_regression is not None and status == "hold":
                    active_regression["recovered_sha"] = sha
                    recovered.append(active_regression)
                    active_regression = None
                previous = status
        final_status = states[-1][1]
        output[invariant_id] = {
            "title": title,
            "first_hold_sha": states[first_hold_index][0] if first_hold_index is not None else None,
            "final_status": final_status,
            "regressions": regressions,
            "historical_regression_count": len(regressions),
            "recovered_regression_count": len(recovered),
            "unresolved_regression": bool(regressions and regressions[-1]["recovered_sha"] is None),
        }
    return output


def change_points(checkpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points = []
    previous = None
    for item in checkpoints:
        score = item["absolute_strength"]
        if previous is None or score != previous:
            points.append({
                "sha": item["sha"],
                "authored_at": item["authored_at"],
                "subject": item["subject"],
                "absolute_strength": score,
                "implemented_health": item["implemented_health"],
                "holds": item["counts"]["hold"],
                "fails": item["counts"]["fail"],
                "unavailable": item["counts"]["unavailable"],
            })
        previous = score
    return points


def write_csv(path: Path, checkpoints: list[dict[str, Any]]) -> None:
    headers = ["index", "sha", "authored_at", "subject", "absolute_strength", "implemented_health", "holds", "fails", "unavailable", "errors", *INVARIANT_IDS]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for index, item in enumerate(checkpoints, 1):
            row_data: dict[str, Any] = {
                "index": index,
                "sha": item["sha"],
                "authored_at": item["authored_at"],
                "subject": item["subject"],
                "absolute_strength": item["absolute_strength"],
                "implemented_health": item["implemented_health"],
                "holds": item["counts"]["hold"],
                "fails": item["counts"]["fail"],
                "unavailable": item["counts"]["unavailable"],
                "errors": item["counts"]["error"],
            }
            row_data.update({key: item["invariants"][key]["status"] for key in INVARIANT_IDS})
            writer.writerow(row_data)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    current = report["current"]
    lines = [
        "# Time Machine V2 — Canonical Constitutional Strength",
        "",
        f"Frozen canonical reference: `{FROZEN_CANONICAL}`",
        "",
        f"Result: **{report['result'].upper()}**",
        "",
        f"Canonical first-parent checkpoints scanned: **{report['checkpoint_count']}**",
        f"Current absolute constitutional strength: **{current['absolute_strength']:.2f}/100** ({current['counts']['hold']}/{len(INVARIANT_IDS)} holds)",
        f"Current implemented-control health: **{current['implemented_health']:.2f}/100**",
        f"Historical regressions detected: **{report['historical_regression_count']}**",
        f"Recovered historical regressions: **{report['recovered_regression_count']}**",
        f"Unresolved regressions: **{report['unresolved_regression_count']}**",
        "",
        "## Invariants",
        "",
        "| ID | First canonical hold | Final | Historical regressions |",
        "|---|---|---:|---:|",
    ]
    for invariant_id, title in INVARIANTS:
        item = report["evolution"][invariant_id]
        first = item["first_hold_sha"][:12] if item["first_hold_sha"] else "—"
        lines.append(f"| `{invariant_id}` — {title} | `{first}` | {item['final_status']} | {item['historical_regression_count']} |")
    lines += ["", "## Score change points", "", "| SHA | Strength | Health | Holds | Fails | Unavailable | Change |", "|---|---:|---:|---:|---:|---:|---|"]
    for point in report["change_points"]:
        health = "—" if point["implemented_health"] is None else f"{point['implemented_health']:.2f}"
        lines.append(f"| `{point['sha'][:12]}` | {point['absolute_strength']:.2f} | {health} | {point['holds']} | {point['fails']} | {point['unavailable']} | {point['subject'].replace('|', '/')} |")
    lines += [
        "",
        "## Boundary",
        "",
        "This curve measures the 14 frozen software constitutional controls only. It is not a product-readiness, market, production-human-authority, external-containment, or real-world-consequence score.",
        "",
        "`authority_effect=none`  ",
        "`provider_write_attempted=false`",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_svg(path: Path, checkpoints: list[dict[str, Any]]) -> None:
    width, height = 1200, 500
    left, right, top, bottom = 70, 30, 40, 70
    chart_w, chart_h = width - left - right, height - top - bottom
    count = len(checkpoints)
    def xy(index: int, score: float) -> tuple[float, float]:
        x = left + (chart_w * index / max(1, count - 1))
        y = top + chart_h * (1 - score / 100)
        return x, y
    strength_points = " ".join(f"{x:.1f},{y:.1f}" for x, y in (xy(i, item["absolute_strength"]) for i, item in enumerate(checkpoints)))
    health_points = " ".join(f"{x:.1f},{y:.1f}" for x, y in (xy(i, item["implemented_health"] or 0) for i, item in enumerate(checkpoints)))
    grid = []
    for score in (0, 25, 50, 75, 100):
        y = top + chart_h * (1 - score / 100)
        grid.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" stroke="currentColor" opacity="0.12"/>')
        grid.append(f'<text x="{left-12}" y="{y+5:.1f}" text-anchor="end" font-size="12">{score}</text>')
    labels = []
    for i, item in enumerate(checkpoints):
        if i == 0 or i == count - 1 or (i > 0 and item["absolute_strength"] != checkpoints[i-1]["absolute_strength"]):
            x, _ = xy(i, 0)
            labels.append(f'<text x="{x:.1f}" y="{height-38}" transform="rotate(45 {x:.1f} {height-38})" font-size="9">{html.escape(item["sha"][:7])}</text>')
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="white"/>
<text x="{left}" y="24" font-family="system-ui,sans-serif" font-size="18" font-weight="600">Pulpo Time Machine V2 — Constitutional Strength Across Canonical First-Parent History</text>
<g font-family="system-ui,sans-serif" fill="black">{''.join(grid)}</g>
<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>
<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>
<polyline points="{strength_points}" fill="none" stroke="black" stroke-width="3"/>
<polyline points="{health_points}" fill="none" stroke="black" stroke-width="1.5" stroke-dasharray="7 5" opacity="0.65"/>
<g font-family="system-ui,sans-serif" fill="black">{''.join(labels)}</g>
<text x="{width-360}" y="24" font-family="system-ui,sans-serif" font-size="11">solid: absolute strength   dashed: implemented-control health</text>
</svg>'''
    path.write_text(svg, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-prefix", default="time-machine-v2")
    args = parser.parse_args()

    commits = canonical_commits()
    with tempfile.TemporaryDirectory(prefix="pulpo-time-machine-v2-") as directory:
        scratch = Path(directory)
        checkpoints = [scan_commit(sha, scratch) for sha in commits]

    evolution_map = evolution(checkpoints)
    errors = sum(item["counts"]["error"] for item in checkpoints)
    current = checkpoints[-1]
    historical_regressions = sum(item["historical_regression_count"] for item in evolution_map.values())
    recovered = sum(item["recovered_regression_count"] for item in evolution_map.values())
    unresolved = sum(int(item["unresolved_regression"]) for item in evolution_map.values())
    current_all_hold = all(current["invariants"][key]["status"] == "hold" for key in INVARIANT_IDS)
    passed = errors == 0 and current_all_hold and unresolved == 0
    report = {
        "schema": "pulpo.time-machine-lineage.v2",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "frozen_canonical_sha": FROZEN_CANONICAL,
        "checkpoint_count": len(checkpoints),
        "invariant_count": len(INVARIANT_IDS),
        "probe_error_count": errors,
        "historical_regression_count": historical_regressions,
        "recovered_regression_count": recovered,
        "unresolved_regression_count": unresolved,
        "result": "pass" if passed else "fail",
        "current": current,
        "evolution": evolution_map,
        "change_points": change_points(checkpoints),
        "checkpoints": checkpoints,
    }

    prefix = Path(args.output_prefix)
    json_path = prefix.with_suffix(".json")
    csv_path = prefix.with_suffix(".csv")
    md_path = prefix.with_suffix(".md")
    svg_path = prefix.with_suffix(".svg")
    json_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    write_csv(csv_path, checkpoints)
    write_markdown(md_path, report)
    write_svg(svg_path, checkpoints)

    print(json.dumps({
        "schema": report["schema"],
        "result": report["result"],
        "checkpoint_count": report["checkpoint_count"],
        "invariant_count": report["invariant_count"],
        "current_absolute_strength": current["absolute_strength"],
        "current_implemented_health": current["implemented_health"],
        "historical_regression_count": historical_regressions,
        "recovered_regression_count": recovered,
        "unresolved_regression_count": unresolved,
        "probe_error_count": errors,
        "outputs": [str(json_path), str(csv_path), str(md_path), str(svg_path)],
        "authority_effect": "none",
        "provider_write_attempted": False,
    }, sort_keys=True, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

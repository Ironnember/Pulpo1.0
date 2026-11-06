#!/usr/bin/env python3
"""Synthetic governed incident-response proof.

This proof models a safe incident-response flow without inspecting or changing a
real host. The process table is an in-memory fixture. Pulpo's canonical
GovernanceKernel and SQLiteKernelState issue and consume the permit; the fixture
is only the consequence sink.

Boundary: no real malware detection, no process kill, no file deletion, no
startup-item changes, no sensitive host inspection, and no production authority.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState
from pulpo.targets import evaluate_locked_target_with_approval
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for

ACTOR = "pulpo-incident-response-operator"
ACTION = "remediate_synthetic_process"
SESSION = "pulpo-synthetic-incident-response"
START_NS = 3_000_000


class ProofError(RuntimeError):
    pass


class ManualClock:
    def __init__(self, value: int = START_NS) -> None:
        self.value = value

    def __call__(self) -> int:
        current = self.value
        self.value += 1
        return current


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class SyntheticProcess:
    pid: int
    process_uid: str
    command: str
    cpu_percent: float
    sample_ns: int
    path: str
    env: dict[str, str]
    active: bool = True

    @property
    def identity(self) -> dict[str, Any]:
        return {
            "schema": "pulpo.synthetic_process_identity.v1",
            "pid": self.pid,
            "process_uid": self.process_uid,
            "command": self.command,
            "sample_ns": self.sample_ns,
        }

    @property
    def identity_hash(self) -> str:
        return digest(self.identity)

    @property
    def resource(self) -> str:
        return f"synthetic-process:{self.pid}:{self.identity_hash}"


class SyntheticProcessTable:
    """Mutable fixture sink used as the separate synthetic consequence surface."""

    def __init__(self, processes: list[SyntheticProcess]) -> None:
        self._processes = {process.identity_hash: process for process in processes}

    def observe(self, identity_hash: str) -> dict[str, Any] | None:
        process = self._processes.get(identity_hash)
        if process is None:
            return None
        return inspect_process(process)

    def remediate(self, expected: SyntheticProcess) -> dict[str, Any]:
        process = self._processes.get(expected.identity_hash)
        if process is None:
            return {
                "schema": "pulpo.synthetic_process_post_action_observation.v1",
                "identity_hash": expected.identity_hash,
                "pid": expected.pid,
                "observed": False,
                "active": None,
                "outcome": "unknown",
                "reason": "target_not_found",
            }
        if not process.active:
            return {
                "schema": "pulpo.synthetic_process_post_action_observation.v1",
                "identity_hash": expected.identity_hash,
                "pid": expected.pid,
                "observed": True,
                "active": False,
                "outcome": "unknown",
                "reason": "target_already_inactive",
            }
        updated = SyntheticProcess(
            pid=process.pid,
            process_uid=process.process_uid,
            command=process.command,
            cpu_percent=process.cpu_percent,
            sample_ns=process.sample_ns,
            path=process.path,
            env=process.env,
            active=False,
        )
        self._processes[expected.identity_hash] = updated
        observation = self.observe(expected.identity_hash)
        if observation is None or observation["active"] is not False:
            return {
                "schema": "pulpo.synthetic_process_post_action_observation.v1",
                "identity_hash": expected.identity_hash,
                "pid": expected.pid,
                "observed": observation is not None,
                "active": None if observation is None else observation["active"],
                "outcome": "unknown",
                "reason": "post_action_observation_mismatch",
            }
        return {
            "schema": "pulpo.synthetic_process_post_action_observation.v1",
            "identity_hash": expected.identity_hash,
            "pid": expected.pid,
            "process_uid": expected.process_uid,
            "observed": True,
            "active": False,
            "outcome": "remediated",
            "reason": "post_action_observed_inactive",
        }


def suspicious_process() -> SyntheticProcess:
    return SyntheticProcess(
        pid=4242,
        process_uid="synthetic-proc-abnormal-001",
        command="synthetic-cpu-worker",
        cpu_percent=1175.0,
        sample_ns=START_NS,
        path="/private/tmp/synthetic-cpu-worker",
        env={"TOKEN": "secret-should-not-leak", "PATH": "/usr/bin"},
    )


def stale_process_reuse(original: SyntheticProcess) -> SyntheticProcess:
    return SyntheticProcess(
        pid=original.pid,
        process_uid="synthetic-proc-reused-pid-999",
        command=original.command,
        cpu_percent=original.cpu_percent,
        sample_ns=original.sample_ns + 100,
        path=original.path,
        env=original.env,
    )


def intent_for(process: SyntheticProcess) -> Intent:
    return Intent(
        principal=ACTOR,
        action=ACTION,
        resource=process.resource,
        cost=1,
        session_id=SESSION,
    )


def inspect_process(process: SyntheticProcess) -> dict[str, Any]:
    """Return bounded read-only evidence; no sensitive env/path leakage."""
    return {
        "schema": "pulpo.synthetic_process_observation.v1",
        "pid": process.pid,
        "process_uid": process.process_uid,
        "command": process.command,
        "cpu_percent": process.cpu_percent,
        "identity_hash": process.identity_hash,
        "active": process.active,
        "path_redacted": True,
        "env_redacted": True,
        "classification": "abnormal_resource_use" if process.cpu_percent >= 800 else "normal",
    }


def make_kernel(db_path: Path, clock: ManualClock, verifier: HmacTestVerifier, secret: bytes) -> tuple[GovernanceKernel, SQLiteKernelState]:
    state = SQLiteKernelState(db_path)
    policy = Policy(
        allowed_actions=frozenset({ACTION}),
        max_cost=1,
        approval_actions=frozenset({ACTION}),
        authority_trust=trust_for(verifier),
    )
    return GovernanceKernel(policy, secret=secret, approval_verifier=verifier, clock=clock, state=state), state


def approve(kernel: GovernanceKernel, verifier: HmacTestVerifier, intent: Intent, approval_id: str, nonce: str, **changes: Any):
    return signed_envelope(
        kernel,
        intent,
        verifier,
        now_ns=START_NS - 10,
        approval_id=approval_id,
        nonce=nonce,
        **changes,
    )


def count_remediations(kernel: GovernanceKernel, process: SyntheticProcess | None = None) -> int:
    identity_hash = process.identity_hash if process is not None else None
    return sum(
        1
        for record in kernel.audit
        if record.get("event") == "synthetic_process_remediated"
        and (identity_hash is None or record.get("payload", {}).get("identity_hash") == identity_hash)
    )


def remediation_events(kernel: GovernanceKernel, process: SyntheticProcess) -> list[dict[str, Any]]:
    return [
        record["payload"]
        for record in kernel.audit
        if record.get("event") == "synthetic_process_remediated"
        and isinstance(record.get("payload"), dict)
        and record["payload"].get("identity_hash") == process.identity_hash
    ]


def remediate_process(kernel: GovernanceKernel, permit: str, sink: SyntheticProcessTable, process: SyntheticProcess) -> dict[str, Any]:
    intent = intent_for(process)
    if not kernel.consume(permit, intent):
        raise ProofError("canonical permit consumption rejected")
    observation = sink.remediate(process)
    timestamp_ns = kernel._trusted_now()
    if timestamp_ns is None:
        raise ProofError("canonical clock rejected")
    if observation.get("outcome") != "remediated":
        kernel._state.append(
            "synthetic_process_remediation_unknown",
            {
                "schema": "pulpo.synthetic_process_remediation_unknown.v1",
                "pid": process.pid,
                "identity_hash": process.identity_hash,
                "reason": observation.get("reason", "unknown"),
                "post_action_observation": observation,
                "automatic_retry_authority": "none",
            },
            timestamp_ns,
        )
        raise ProofError("target consequence unknown")
    kernel._state.append(
        "synthetic_process_remediated",
        {
            "schema": "pulpo.synthetic_process_remediation.v1",
            "pid": process.pid,
            "process_uid": process.process_uid,
            "identity_hash": process.identity_hash,
            "intent_hash": kernel.intent_hash(intent),
            "outcome": "remediated",
            "post_action_observation": observation,
            "authority_effect": "attempted_and_observed",
        },
        timestamp_ns,
    )
    return observation


def check_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def expect_denied(fn: Callable[[], Any], kernel: GovernanceKernel, expected_events: int) -> None:
    try:
        result = fn()
    except ProofError:
        result = None
    if result is not None:
        outcome = getattr(result, "outcome", None)
        reason = getattr(result, "reason", None)
        if outcome == "allow":
            raise AssertionError(f"expected denial, got allow/{reason}")
    check_equal(count_remediations(kernel), expected_events, "denial changed remediation count")


def run_checks(workdir: Path) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = workdir / "pulpo-synthetic-incident-response.sqlite3"
    clock = ManualClock()
    verifier = HmacTestVerifier()
    kernel_secret = secrets.token_bytes(32)
    kernel, state = make_kernel(db_path, clock, verifier, kernel_secret)
    process = suspicious_process()
    sink = SyntheticProcessTable([process])
    intent = intent_for(process)
    target = kernel.lock_target(f"synthetic-process:{process.process_uid}", intent)
    checks: list[dict[str, Any]] = []

    def record(name: str, fn: Callable[[], None]) -> None:
        before = count_remediations(kernel)
        fn()
        checks.append({"name": name, "status": "PASS", "before_events": before, "after_events": count_remediations(kernel)})

    def read_only_inspection_bounded() -> None:
        observed = sink.observe(process.identity_hash)
        if observed is None:
            raise AssertionError("fixture process was not observable")
        check_equal(observed["classification"], "abnormal_resource_use", "inspection failed to classify abnormal fixture")
        if "TOKEN" in canonical(observed) or process.path in canonical(observed):
            raise AssertionError("inspection leaked sensitive process data")
        check_equal(count_remediations(kernel), 0, "inspection created remediation")

    record("read_only_inspection_bounded", read_only_inspection_bounded)

    def no_permit_denies_remediation() -> None:
        expect_denied(lambda: remediate_process(kernel, "missing-permit", sink, process), kernel, 0)

    record("no_permit_denies_remediation", no_permit_denies_remediation)

    def forged_approval_denies_remediation() -> None:
        envelope = approve(kernel, verifier, intent, "approval-forged", "nonce-forged")
        forged = envelope.__class__(**{**envelope.__dict__, "signature": "00" * 32})
        _, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, forged)
        if decision is None or decision.outcome != "deny" or decision.reason != "approval_signature_invalid":
            raise AssertionError(f"expected forged approval denial, got {decision}")
        check_equal(count_remediations(kernel), 0, "forged approval remediated")

    record("forged_approval_denies_remediation", forged_approval_denies_remediation)

    def target_substitution_denies_before_authority() -> None:
        envelope = approve(kernel, verifier, intent, "approval-substitution", "nonce-substitution")
        resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, "0" * 64, envelope)
        if resolution.outcome != "deny" or resolution.reason != "target_hash_mismatch" or decision is not None:
            raise AssertionError("target substitution reached authority evaluation")
        check_equal(count_remediations(kernel), 0, "target substitution remediated")

    record("target_substitution_denies_before_authority", target_substitution_denies_before_authority)

    valid_envelope = approve(kernel, verifier, intent, "approval-valid", "nonce-valid")
    resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid_envelope)
    if resolution.outcome != "match" or decision is None or decision.outcome != "allow" or decision.permit is None:
        raise AssertionError(f"valid exact target did not produce permit: {resolution} {decision}")
    valid_permit = decision.permit

    def valid_exact_approval_allows_one_remediation() -> None:
        observation = remediate_process(kernel, valid_permit, sink, process)
        check_equal(count_remediations(kernel), 1, "valid permit did not remediate exactly once")
        check_equal(observation["outcome"], "remediated", "fixture sink did not report remediation")
        post = sink.observe(process.identity_hash)
        if post is None:
            raise AssertionError("post-action process observation missing")
        check_equal(post["active"], False, "fixture process remained active")

    record("valid_exact_approval_allows_one_remediation", valid_exact_approval_allows_one_remediation)

    def approval_replay_denies_second_permit() -> None:
        _, replay = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid_envelope)
        if replay is None or replay.outcome != "deny" or replay.reason not in {"approval_id_replayed", "approval_nonce_replayed"}:
            raise AssertionError(f"expected approval replay denial, got {replay}")
        check_equal(count_remediations(kernel), 1, "approval replay remediated")

    record("approval_replay_denies_second_permit", approval_replay_denies_second_permit)

    def permit_replay_denies_second_remediation() -> None:
        expect_denied(lambda: remediate_process(kernel, valid_permit, sink, process), kernel, 1)

    record("permit_replay_denies_second_remediation", permit_replay_denies_second_remediation)

    state.close()
    kernel, state = make_kernel(db_path, clock, verifier, kernel_secret)

    def restart_replay_denies_second_remediation() -> None:
        expect_denied(lambda: remediate_process(kernel, valid_permit, sink, process), kernel, 1)

    record("restart_replay_denies_second_remediation", restart_replay_denies_second_remediation)

    def stale_pid_identity_denies_remediation() -> None:
        stale = stale_process_reuse(suspicious_process())
        envelope = approve(kernel, verifier, intent, "approval-stale", "nonce-stale")
        _, stale_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, envelope)
        if stale_decision is None or stale_decision.outcome != "allow" or stale_decision.permit is None:
            raise AssertionError(f"expected permit for stale identity test, got {stale_decision}")
        expect_denied(lambda: remediate_process(kernel, stale_decision.permit, sink, stale), kernel, 1)

    record("stale_pid_identity_denies_remediation", stale_pid_identity_denies_remediation)

    def expired_approval_denies_remediation() -> None:
        expired = signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=START_NS - 100,
            ttl_ns=1,
            approval_id="approval-expired",
            nonce="nonce-expired",
        )
        _, expired_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, expired)
        if expired_decision is None or expired_decision.outcome != "deny" or expired_decision.reason != "approval_expired":
            raise AssertionError(f"expected expired approval denial, got {expired_decision}")
        check_equal(count_remediations(kernel), 1, "expired approval remediated")

    record("expired_approval_denies_remediation", expired_approval_denies_remediation)

    def wrong_actor_denies_remediation() -> None:
        wrong_actor = approve(kernel, verifier, intent, "approval-wrong-actor", "nonce-wrong-actor", principal="not-authorized")
        _, wrong_actor_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, wrong_actor)
        if wrong_actor_decision is None or wrong_actor_decision.outcome != "deny" or wrong_actor_decision.reason != "approval_principal_mismatch":
            raise AssertionError(f"expected wrong actor denial, got {wrong_actor_decision}")
        check_equal(count_remediations(kernel), 1, "wrong actor remediated")

    record("wrong_actor_denies_remediation", wrong_actor_denies_remediation)

    def post_action_observation_reconciles_exact_target() -> None:
        events = remediation_events(kernel, suspicious_process())
        check_equal(len(events), 1, "expected one remediation event")
        check_equal(events[0]["pid"], 4242, "pid mismatch")
        check_equal(events[0]["outcome"], "remediated", "outcome mismatch")
        observation = events[0].get("post_action_observation")
        if not isinstance(observation, dict) or observation.get("observed") is not True or observation.get("active") is not False:
            raise AssertionError("remediation was not derived from post-action fixture observation")
        if not kernel.verify_audit():
            raise AssertionError("canonical audit chain invalid")

    record("post_action_observation_reconciles_exact_target", post_action_observation_reconciles_exact_target)

    def unknown_outcome_does_not_retry_authority() -> None:
        inactive = suspicious_process()
        inactive_sink = SyntheticProcessTable([inactive])
        unknown_intent = intent_for(inactive)
        unknown_target = kernel.lock_target(f"synthetic-process:{inactive.process_uid}:inactive", unknown_intent)
        envelope = approve(kernel, verifier, unknown_intent, "approval-unknown", "nonce-unknown")
        _, unknown_decision = evaluate_locked_target_with_approval(kernel, unknown_target.target_id, unknown_target.target_hash, envelope)
        if unknown_decision is None or unknown_decision.outcome != "allow" or unknown_decision.permit is None:
            raise AssertionError(f"expected permit for unknown outcome test, got {unknown_decision}")
        # A separately authorized observer sees the target disappear or stop before the executor observes its own attempt.
        inactive_sink.remediate(inactive)
        expect_denied(lambda: remediate_process(kernel, unknown_decision.permit, inactive_sink, inactive), kernel, 1)
        unknown_events = [record for record in kernel.audit if record.get("event") == "synthetic_process_remediation_unknown"]
        if not unknown_events or unknown_events[-1]["payload"].get("automatic_retry_authority") != "none":
            raise AssertionError("unknown outcome did not preserve no-retry boundary")

    record("unknown_outcome_does_not_retry_authority", unknown_outcome_does_not_retry_authority)

    def machine_readable_summary_available() -> None:
        summary = {"remediation_count": count_remediations(kernel), "identity_hash": suspicious_process().identity_hash, "checks_so_far": len(checks)}
        check_equal(summary["remediation_count"], 1, "summary remediation count mismatch")
        if not summary["identity_hash"]:
            raise AssertionError("summary missing identity hash")

    record("machine_readable_summary_available", machine_readable_summary_available)

    state.close()
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "result": "PASS" if passed == len(checks) else "FAIL",
        "checks_passed": passed,
        "checks_total": len(checks),
        "remediation_count": 1,
        "db_path": str(db_path),
        "db_exists": db_path.exists(),
        "boundary": "Synthetic incident-response fixture through Pulpo canonical kernel/state only. No real malware detection, process kill, file deletion, sensitive host inspection, or production authority.",
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        evidence_dir = args.output.resolve().parent
        evidence_dir.mkdir(parents=True, exist_ok=True)
        state_dir = evidence_dir / "state"
        result = run_checks(state_dir)
        text = json.dumps(result, indent=2, sort_keys=True)
        args.output.write_text(text + "\n")
        print(text)
        return 0 if result["result"] == "PASS" else 1
    with tempfile.TemporaryDirectory(prefix="pulpo-synthetic-incident-response-") as td:
        result = run_checks(Path(td))
        text = json.dumps(result, indent=2, sort_keys=True)
        print(text)
        return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Synthetic governed incident-response proof through the canonical kernel.

This proof uses a disposable simulated process table. It does not inspect,
terminate, quarantine, delete, or modify real system processes, files, launch
agents, credentials, network settings, or user data.

The useful pattern is evidence drift -> bounded read-only inspection -> proposed
remediation -> canonical Pulpo authority/permit -> exact synthetic remediation ->
post-action evidence. The synthetic process table is only the consequence sink.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
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

ACTOR = "pulpo-incident-test-operator"
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


@dataclass(frozen=True)
class SyntheticProcess:
    pid: int
    executable: str
    command: str
    cpu_percent: float
    rss_mb: int
    identity_nonce: str
    env_secret: str = "REDACTED-SECRET-DO-NOT-EXPOSE"

    @property
    def identity(self) -> str:
        return f"synthetic-process:{self.pid}:{self.executable}:{self.identity_nonce}"


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def public_process_view(process: SyntheticProcess) -> dict[str, Any]:
    return {
        "pid": process.pid,
        "executable": process.executable,
        "command": process.command,
        "cpu_percent": process.cpu_percent,
        "rss_mb": process.rss_mb,
        "identity": process.identity,
        "identity_hash": process_identity_hash(process),
    }


def process_identity_hash(process: SyntheticProcess) -> str:
    return digest(
        {
            "pid": process.pid,
            "executable": process.executable,
            "command": process.command,
            "identity": process.identity,
        }
    )


def remediation_object(process: SyntheticProcess) -> dict[str, Any]:
    view = public_process_view(process)
    return {
        "schema": "pulpo.synthetic_incident_remediation.v1",
        "action": ACTION,
        "target_id": process.identity,
        "pid": process.pid,
        "identity_hash": view["identity_hash"],
        "reason": "abnormal_cpu_usage",
    }


def intent_for(obj: dict[str, Any]) -> Intent:
    return Intent(
        principal=ACTOR,
        action=ACTION,
        resource=f"{obj['target_id']}:{digest(obj)}",
        cost=1,
        session_id=SESSION,
    )


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


def inspect_processes(processes: dict[int, SyntheticProcess]) -> list[dict[str, Any]]:
    """Read-only bounded evidence. Sensitive env data is deliberately absent."""

    return [public_process_view(process) for process in sorted(processes.values(), key=lambda item: item.pid)]


def detect_anomaly(evidence: list[dict[str, Any]], *, cpu_threshold: float = 500.0) -> dict[str, Any] | None:
    suspects = [item for item in evidence if item["cpu_percent"] >= cpu_threshold]
    if not suspects:
        return None
    suspect = max(suspects, key=lambda item: item["cpu_percent"])
    return {
        "finding": "abnormal_cpu_usage",
        "target_id": suspect["identity"],
        "pid": suspect["pid"],
        "identity_hash": suspect["identity_hash"],
        "cpu_percent": suspect["cpu_percent"],
        "authority_effect": "none",
    }


def count_remediations(kernel: GovernanceKernel, obj: dict[str, Any] | None = None) -> int:
    object_hash = digest(obj) if obj is not None else None
    return sum(
        1
        for record in kernel.audit
        if record.get("event") == "synthetic_incident_remediated"
        and (object_hash is None or record.get("payload", {}).get("object_hash") == object_hash)
    )


def observe_remediation(kernel: GovernanceKernel, obj: dict[str, Any]) -> list[dict[str, Any]]:
    object_hash = digest(obj)
    return [
        record["payload"]
        for record in kernel.audit
        if record.get("event") == "synthetic_incident_remediated"
        and isinstance(record.get("payload"), dict)
        and record["payload"].get("object_hash") == object_hash
    ]


def execute_remediation(
    kernel: GovernanceKernel,
    permit: str,
    obj: dict[str, Any],
    processes: dict[int, SyntheticProcess],
) -> None:
    current = processes.get(int(obj["pid"]))
    timestamp_ns = kernel._trusted_now()
    if timestamp_ns is None:
        raise ProofError("canonical clock rejected")
    if current is None or current.identity != obj["target_id"] or process_identity_hash(current) != obj["identity_hash"]:
        kernel._state.append(
            "synthetic_incident_remediation_rejected",
            {
                "reason": "target_identity_mismatch",
                "object_hash": digest(obj),
                "pid": obj["pid"],
                "authority_effect": "none",
            },
            timestamp_ns,
        )
        raise ProofError("target identity mismatch")
    intent = intent_for(obj)
    if not kernel.consume(permit, intent):
        raise ProofError("canonical permit consumption rejected")
    timestamp_ns = kernel._trusted_now()
    if timestamp_ns is None:
        raise ProofError("canonical clock rejected")
    processes.pop(current.pid)
    kernel._state.append(
        "synthetic_incident_remediated",
        {
            "schema": "pulpo.synthetic_incident_remediated.v1",
            "object_hash": digest(obj),
            "intent_hash": kernel.intent_hash(intent),
            "target_id": obj["target_id"],
            "pid": obj["pid"],
            "identity_hash": obj["identity_hash"],
            "authority_effect": "attempted_and_observed",
        },
        timestamp_ns,
    )


def check_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def expect_denied(fn: Callable[[], Any], kernel: GovernanceKernel, expected_remediations: int) -> None:
    try:
        result = fn()
    except ProofError:
        result = None
    if result is not None:
        outcome = getattr(result, "outcome", None)
        reason = getattr(result, "reason", None)
        if outcome == "allow":
            raise AssertionError(f"expected denial, got allow/{reason}")
    check_equal(count_remediations(kernel), expected_remediations, "denial changed remediation count")


def run_checks(workdir: Path) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = workdir / "pulpo-synthetic-incident-response.sqlite3"
    clock = ManualClock()
    verifier = HmacTestVerifier()
    kernel_secret = secrets.token_bytes(32)
    kernel, state = make_kernel(db_path, clock, verifier, kernel_secret)

    suspicious = SyntheticProcess(
        pid=4242,
        executable="synthetic-high-cpu-worker",
        command="python3 -m synthetic_fixture.burn_cpu",
        cpu_percent=1175.0,
        rss_mb=128,
        identity_nonce="initial",
    )
    benign = SyntheticProcess(
        pid=101,
        executable="synthetic-editor",
        command="python3 -m synthetic_fixture.edit",
        cpu_percent=2.5,
        rss_mb=64,
        identity_nonce="benign",
    )
    processes: dict[int, SyntheticProcess] = {suspicious.pid: suspicious, benign.pid: benign}
    obj = remediation_object(suspicious)
    intent = intent_for(obj)
    target = kernel.lock_target(obj["target_id"], intent)
    checks: list[dict[str, Any]] = []

    def record(name: str, fn: Callable[[], None]) -> None:
        before = count_remediations(kernel)
        fn()
        checks.append({"name": name, "status": "PASS", "before_remediations": before, "after_remediations": count_remediations(kernel)})

    def read_only_investigation_collects_bounded_evidence() -> None:
        evidence = inspect_processes(processes)
        finding = detect_anomaly(evidence)
        if finding is None or finding["target_id"] != suspicious.identity:
            raise AssertionError("synthetic anomaly was not detected")
        encoded = canonical(evidence)
        if "REDACTED-SECRET-DO-NOT-EXPOSE" in encoded or "env_secret" in encoded:
            raise AssertionError("sensitive process environment leaked into read-only evidence")
        check_equal(count_remediations(kernel), 0, "inspection remediated without authority")

    record("read_only_investigation_collects_bounded_evidence", read_only_investigation_collects_bounded_evidence)

    def no_permit_denies_remediation() -> None:
        expect_denied(lambda: execute_remediation(kernel, "missing-permit", obj, processes), kernel, 0)
        if suspicious.pid not in processes:
            raise AssertionError("missing permit removed synthetic process")

    record("no_permit_denies_remediation", no_permit_denies_remediation)

    def forged_approval_denies_remediation() -> None:
        envelope = approve(kernel, verifier, intent, "approval-forged-ir", "nonce-forged-ir")
        forged = replace(envelope, signature="00" * 32)
        _, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, forged)
        if decision is None or decision.outcome != "deny" or decision.reason != "approval_signature_invalid":
            raise AssertionError(f"expected forged approval denial, got {decision}")
        check_equal(count_remediations(kernel), 0, "forged approval remediated")

    record("forged_approval_denies_remediation", forged_approval_denies_remediation)

    def target_substitution_denies_before_authority() -> None:
        envelope = approve(kernel, verifier, intent, "approval-substitution-ir", "nonce-substitution-ir")
        resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, "0" * 64, envelope)
        if resolution.outcome != "deny" or resolution.reason != "target_hash_mismatch" or decision is not None:
            raise AssertionError("target substitution reached authority evaluation")
        check_equal(count_remediations(kernel), 0, "target substitution remediated")

    record("target_substitution_denies_before_authority", target_substitution_denies_before_authority)

    def stale_identity_denies_remediation() -> None:
        stale_envelope = approve(kernel, verifier, intent, "approval-stale-ir", "nonce-stale-ir")
        _, stale_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, stale_envelope)
        if stale_decision is None or stale_decision.outcome != "allow" or stale_decision.permit is None:
            raise AssertionError(f"expected stale test permit, got {stale_decision}")
        processes[suspicious.pid] = replace(suspicious, executable="synthetic-other-worker", identity_nonce="changed")
        expect_denied(lambda: execute_remediation(kernel, stale_decision.permit, obj, processes), kernel, 0)
        processes[suspicious.pid] = suspicious

    record("stale_identity_denies_remediation", stale_identity_denies_remediation)

    valid_envelope = approve(kernel, verifier, intent, "approval-valid-ir", "nonce-valid-ir")
    resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid_envelope)
    if resolution.outcome != "match" or decision is None or decision.outcome != "allow" or decision.permit is None:
        raise AssertionError(f"valid exact target did not produce permit: {resolution} {decision}")
    valid_permit = decision.permit

    def valid_permit_allows_one_remediation() -> None:
        execute_remediation(kernel, valid_permit, obj, processes)
        check_equal(count_remediations(kernel), 1, "valid permit did not create exactly one remediation")
        if suspicious.pid in processes:
            raise AssertionError("authorized synthetic process was not removed")

    record("valid_permit_allows_one_remediation", valid_permit_allows_one_remediation)

    def approval_replay_denies_second_permit() -> None:
        _, replay = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid_envelope)
        if replay is None or replay.outcome != "deny" or replay.reason not in {"approval_id_replayed", "approval_nonce_replayed"}:
            raise AssertionError(f"expected approval replay denial, got {replay}")
        check_equal(count_remediations(kernel), 1, "approval replay remediated")

    record("approval_replay_denies_second_permit", approval_replay_denies_second_permit)

    def permit_replay_denies_second_remediation() -> None:
        expect_denied(lambda: execute_remediation(kernel, valid_permit, obj, processes), kernel, 1)

    record("permit_replay_denies_second_remediation", permit_replay_denies_second_remediation)

    state.close()
    kernel, state = make_kernel(db_path, clock, verifier, kernel_secret)

    def restart_replay_denies_second_remediation() -> None:
        expect_denied(lambda: execute_remediation(kernel, valid_permit, obj, processes), kernel, 1)

    record("restart_replay_denies_second_remediation", restart_replay_denies_second_remediation)

    def independent_observer_reads_exact_remediation() -> None:
        observed = observe_remediation(kernel, obj)
        check_equal(len(observed), 1, "observer did not read exactly one remediation")
        check_equal(observed[0]["target_id"], obj["target_id"], "observer target mismatch")
        check_equal(observed[0]["identity_hash"], obj["identity_hash"], "observer identity hash mismatch")

    record("independent_observer_reads_exact_remediation", independent_observer_reads_exact_remediation)

    def tampered_observation_does_not_reconcile() -> None:
        tampered_process = replace(suspicious, pid=5252, identity_nonce="tampered")
        check_equal(observe_remediation(kernel, remediation_object(tampered_process)), [], "tampered observation reconciled")
        check_equal(count_remediations(kernel), 1, "tampered observation changed remediation count")

    record("tampered_observation_does_not_reconcile", tampered_observation_does_not_reconcile)

    def expired_approval_denies_remediation() -> None:
        expired = signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=START_NS - 100,
            ttl_ns=1,
            approval_id="approval-expired-ir",
            nonce="nonce-expired-ir",
        )
        _, expired_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, expired)
        if expired_decision is None or expired_decision.outcome != "deny" or expired_decision.reason != "approval_expired":
            raise AssertionError(f"expected expired approval denial, got {expired_decision}")
        check_equal(count_remediations(kernel), 1, "expired approval remediated")

    record("expired_approval_denies_remediation", expired_approval_denies_remediation)

    def wrong_actor_denies_remediation() -> None:
        wrong_actor = approve(kernel, verifier, intent, "approval-wrong-actor-ir", "nonce-wrong-actor-ir", principal="not-authorized")
        _, wrong_actor_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, wrong_actor)
        if wrong_actor_decision is None or wrong_actor_decision.outcome != "deny" or wrong_actor_decision.reason != "approval_principal_mismatch":
            raise AssertionError(f"expected wrong actor denial, got {wrong_actor_decision}")
        check_equal(count_remediations(kernel), 1, "wrong actor remediated")

    record("wrong_actor_denies_remediation", wrong_actor_denies_remediation)

    def unknown_outcome_does_not_authorize_retry() -> None:
        retry_process = SyntheticProcess(
            pid=7777,
            executable="synthetic-high-cpu-worker",
            command="python3 -m synthetic_fixture.burn_cpu",
            cpu_percent=999.0,
            rss_mb=96,
            identity_nonce="unknown",
        )
        retry_processes = {retry_process.pid: retry_process}
        retry_obj = remediation_object(retry_process)
        retry_intent = intent_for(retry_obj)
        retry_target = kernel.lock_target(retry_obj["target_id"], retry_intent)
        retry_envelope = approve(kernel, verifier, retry_intent, "approval-unknown-ir", "nonce-unknown-ir")
        _, retry_decision = evaluate_locked_target_with_approval(kernel, retry_target.target_id, retry_target.target_hash, retry_envelope)
        if retry_decision is None or retry_decision.outcome != "allow" or retry_decision.permit is None:
            raise AssertionError(f"expected unknown-outcome permit, got {retry_decision}")
        # Simulate loss of independent observation before remediation can be established.
        retry_processes.pop(retry_process.pid)
        expect_denied(lambda: execute_remediation(kernel, retry_decision.permit, retry_obj, retry_processes), kernel, 1)
        # The same permit may not be inflated into an automatic retry/remediation of a different object.
        substitute = replace(retry_process, pid=8888, identity_nonce="substitute")
        substitute_processes = {substitute.pid: substitute}
        expect_denied(lambda: execute_remediation(kernel, retry_decision.permit, remediation_object(substitute), substitute_processes), kernel, 1)

    record("unknown_outcome_does_not_authorize_retry", unknown_outcome_does_not_authorize_retry)

    def canonical_evidence_recorded_once() -> None:
        observed = observe_remediation(kernel, obj)
        approvals = [record for record in kernel.audit if record.get("event") == "approval_verified"]
        consumed = [record for record in kernel.audit if record.get("event") == "permit_consumed"]
        if len(observed) != 1 or not approvals or not consumed or not kernel.verify_audit():
            raise AssertionError("canonical incident-response evidence/audit path missing")

    record("canonical_evidence_recorded_once", canonical_evidence_recorded_once)

    def machine_readable_summary_available() -> None:
        summary = {"remediation_count": count_remediations(kernel), "object_hash": digest(obj), "checks_so_far": len(checks)}
        check_equal(summary["remediation_count"], 1, "summary remediation count mismatch")
        if not summary["object_hash"]:
            raise AssertionError("summary missing object hash")

    record("machine_readable_summary_available", machine_readable_summary_available)

    state.close()
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "result": "PASS" if passed == len(checks) else "FAIL",
        "checks_passed": passed,
        "checks_total": len(checks),
        "remediation_count": 1,
        "db_path": str(db_path),
        "boundary": "Synthetic incident-response proof through Pulpo canonical kernel/state only. No real process inspection, termination, file deletion, credential access, network changes, launch-agent changes, or production authority.",
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pulpo-synthetic-incident-response-") as td:
        result = run_checks(Path(td))
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Pulpo Node synthetic virtual-lamp proof through the canonical kernel.

Synthetic only: no GPIO, no credentials, no network changes, no physical device
authority. The lamp is still virtual, but authority, approval replay, one-use
permits, target matching, restart replay, and evidence all use Pulpo's canonical
GovernanceKernel and KernelState path rather than a proof-specific ledger.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
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

ACTOR = "pulpo-node-test-operator"
TARGET = "virtual-lamp:alpha"
ACTION = "set_virtual_lamp"
SESSION = "pulpo-node-virtual-lamp"
START_NS = 2_000_000


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


def action_object(target: str = TARGET, state: str = "on") -> dict[str, str]:
    return {"action": ACTION, "target": target, "state": state}


def intent_for(obj: dict[str, str]) -> Intent:
    return Intent(
        principal=ACTOR,
        action=ACTION,
        resource=f"{obj['target']}:{digest(obj)}",
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


def count_events(kernel: GovernanceKernel, obj: dict[str, str] | None = None) -> int:
    object_hash = digest(obj) if obj is not None else None
    return sum(
        1
        for record in kernel.audit
        if record.get("event") == "virtual_lamp_observed"
        and (object_hash is None or record.get("payload", {}).get("object_hash") == object_hash)
    )


def observe_lamp(kernel: GovernanceKernel, obj: dict[str, str]) -> list[dict[str, Any]]:
    object_hash = digest(obj)
    return [
        record["payload"]
        for record in kernel.audit
        if record.get("event") == "virtual_lamp_observed"
        and isinstance(record.get("payload"), dict)
        and record["payload"].get("object_hash") == object_hash
    ]


def execute_virtual_lamp(kernel: GovernanceKernel, permit: str, obj: dict[str, str]) -> None:
    intent = intent_for(obj)
    if not kernel.consume(permit, intent):
        raise ProofError("canonical permit consumption rejected")
    timestamp_ns = kernel._trusted_now()
    if timestamp_ns is None:
        raise ProofError("canonical clock rejected")
    payload = {
        "schema": "pulpo.virtual_lamp_observation.v1",
        "object_hash": digest(obj),
        "intent_hash": kernel.intent_hash(intent),
        "target": obj["target"],
        "state": obj["state"],
        "effect_index": count_events(kernel) + 1,
        "authority_effect": "attempted_and_observed",
    }
    kernel._state.append("virtual_lamp_observed", payload, timestamp_ns)


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
    check_equal(count_events(kernel), expected_events, "denial changed virtual signal count")


def run_checks(workdir: Path) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = workdir / "pulpo-node-virtual-lamp.sqlite3"
    clock = ManualClock()
    verifier = HmacTestVerifier()
    kernel_secret = secrets.token_bytes(32)
    kernel, state = make_kernel(db_path, clock, verifier, kernel_secret)
    obj = action_object()
    intent = intent_for(obj)
    target = kernel.lock_target(obj["target"], intent)
    checks: list[dict[str, Any]] = []

    def record(name: str, fn: Callable[[], None]) -> None:
        before = count_events(kernel)
        fn()
        checks.append({"name": name, "status": "PASS", "before_events": before, "after_events": count_events(kernel)})

    def no_permit_denies_signal() -> None:
        expect_denied(lambda: execute_virtual_lamp(kernel, "missing-permit", obj), kernel, 0)

    record("no_permit_denies_signal", no_permit_denies_signal)

    def forged_approval_denies_signal() -> None:
        envelope = approve(kernel, verifier, intent, "approval-forged", "nonce-forged")
        forged = replace(envelope, signature="00" * 32)
        _, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, forged)
        if decision is None or decision.outcome != "deny" or decision.reason != "approval_signature_invalid":
            raise AssertionError(f"expected forged approval denial, got {decision}")
        check_equal(count_events(kernel), 0, "forged approval created event")

    record("forged_approval_denies_signal", forged_approval_denies_signal)

    def target_substitution_denies_signal() -> None:
        envelope = approve(kernel, verifier, intent, "approval-substitution", "nonce-substitution")
        resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, "0" * 64, envelope)
        if resolution.outcome != "deny" or resolution.reason != "target_hash_mismatch" or decision is not None:
            raise AssertionError("target substitution reached authority evaluation")
        check_equal(count_events(kernel), 0, "target substitution created event")

    record("target_substitution_denies_signal", target_substitution_denies_signal)

    valid_envelope = approve(kernel, verifier, intent, "approval-valid", "nonce-valid")
    resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid_envelope)
    if resolution.outcome != "match" or decision is None or decision.outcome != "allow" or decision.permit is None:
        raise AssertionError(f"valid exact target did not produce a canonical permit: {resolution} {decision}")
    valid_permit = decision.permit

    def valid_permit_allows_one_signal() -> None:
        execute_virtual_lamp(kernel, valid_permit, obj)
        check_equal(count_events(kernel), 1, "valid permit did not create exactly one event")

    record("valid_permit_allows_one_signal", valid_permit_allows_one_signal)

    def approval_replay_denies_second_permit() -> None:
        _, replay = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid_envelope)
        if replay is None or replay.outcome != "deny" or replay.reason not in {"approval_id_replayed", "approval_nonce_replayed"}:
            raise AssertionError(f"expected approval replay denial, got {replay}")
        check_equal(count_events(kernel), 1, "approval replay created event")

    record("approval_replay_denies_second_permit", approval_replay_denies_second_permit)

    def permit_replay_denies_second_signal() -> None:
        expect_denied(lambda: execute_virtual_lamp(kernel, valid_permit, obj), kernel, 1)

    record("permit_replay_denies_second_signal", permit_replay_denies_second_signal)

    # Reopen the same canonical SQLite state to prove replay remains denied after restart.
    state.close()
    kernel, state = make_kernel(db_path, clock, verifier, kernel_secret)

    def restart_replay_denies_second_signal() -> None:
        expect_denied(lambda: execute_virtual_lamp(kernel, valid_permit, obj), kernel, 1)

    record("restart_replay_denies_second_signal", restart_replay_denies_second_signal)

    def independent_observer_reads_exact_signal() -> None:
        observed = observe_lamp(kernel, obj)
        check_equal(len(observed), 1, "observer did not read exactly one event")
        check_equal(observed[0]["target"], TARGET, "observer target mismatch")
        check_equal(observed[0]["state"], "on", "observer state mismatch")

    record("independent_observer_reads_exact_signal", independent_observer_reads_exact_signal)

    def tampered_observation_does_not_reconcile() -> None:
        check_equal(observe_lamp(kernel, action_object(target="virtual-lamp:tampered")), [], "tampered observation reconciled")
        check_equal(count_events(kernel), 1, "tampered observation changed event count")

    record("tampered_observation_does_not_reconcile", tampered_observation_does_not_reconcile)

    def expired_approval_denies_signal() -> None:
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
        check_equal(count_events(kernel), 1, "expired approval changed event count")

    record("expired_approval_denies_signal", expired_approval_denies_signal)

    def wrong_actor_denies_signal() -> None:
        wrong_actor = approve(kernel, verifier, intent, "approval-wrong-actor", "nonce-wrong-actor", principal="not-authorized")
        _, wrong_actor_decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, wrong_actor)
        if wrong_actor_decision is None or wrong_actor_decision.outcome != "deny" or wrong_actor_decision.reason != "approval_principal_mismatch":
            raise AssertionError(f"expected wrong actor denial, got {wrong_actor_decision}")
        check_equal(count_events(kernel), 1, "wrong actor changed event count")

    record("wrong_actor_denies_signal", wrong_actor_denies_signal)

    def permit_object_mismatch_denies_signal() -> None:
        envelope = approve(kernel, verifier, intent, "approval-object-mismatch", "nonce-object-mismatch")
        _, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, envelope)
        if decision is None or decision.outcome != "allow" or decision.permit is None:
            raise AssertionError(f"expected permit for mismatch case, got {decision}")
        expect_denied(lambda: execute_virtual_lamp(kernel, decision.permit, action_object(state="off")), kernel, 1)

    record("permit_object_mismatch_denies_signal", permit_object_mismatch_denies_signal)

    def evidence_recorded_once() -> None:
        observed = observe_lamp(kernel, obj)
        approvals = [record for record in kernel.audit if record.get("event") == "approval_verified"]
        consumed = [record for record in kernel.audit if record.get("event") == "permit_consumed"]
        check_equal(len(observed), 1, "expected one virtual observation")
        if not approvals or not consumed or not kernel.verify_audit():
            raise AssertionError("canonical evidence/audit path missing")

    record("evidence_recorded_once", evidence_recorded_once)

    def machine_readable_summary_available() -> None:
        summary = {"event_count": count_events(kernel), "object_hash": digest(obj), "checks_so_far": len(checks)}
        check_equal(summary["event_count"], 1, "summary event count mismatch")
        if not summary["object_hash"]:
            raise AssertionError("summary missing object hash")

    record("machine_readable_summary_available", machine_readable_summary_available)

    state.close()
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "result": "PASS" if passed == len(checks) else "FAIL",
        "checks_passed": passed,
        "checks_total": len(checks),
        "event_count": 1,
        "db_path": str(db_path),
        "boundary": "Synthetic virtual-lamp proof through Pulpo canonical kernel/state only. No GPIO, credentials, network changes, persistent daemon, or physical device authority.",
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pulpo-node-virtual-lamp-") as td:
        result = run_checks(Path(td))
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

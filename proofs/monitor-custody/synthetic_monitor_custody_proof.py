#!/usr/bin/env python3
"""Synthetic monitor-custody proof.

This proof models monitor/alert configuration as a governed consequence surface.
It does not touch real monitoring, Slack, production services, secrets, OpenAI
systems, or external providers. The synthetic monitor store is the consequence
sink; Pulpo's canonical GovernanceKernel and SQLiteKernelState issue and consume
permits.
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

ACTOR = "pulpo-monitor-custody-operator"
ACTION = "change_synthetic_monitor"
SESSION = "pulpo-synthetic-monitor-custody"
START_NS = 4_000_000
ALLOWED_CHANGE_FIELDS = frozenset(
    {"alerts_enabled", "notify_humans", "recipients", "runtime_integration", "test_requires_monitor_absence"}
)


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


def normalize_change(change: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(change) - ALLOWED_CHANGE_FIELDS)
    if unknown:
        raise ProofError(f"unsupported monitor-change fields: {unknown}")
    if not change:
        raise ProofError("empty monitor change is not a consequence")
    normalized: dict[str, Any] = {}
    for key in sorted(change):
        value = change[key]
        if key == "recipients":
            if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
                raise ProofError("recipients must be a list of strings")
            normalized[key] = list(value)
        elif not isinstance(value, bool):
            raise ProofError(f"{key} must be boolean")
        else:
            normalized[key] = value
    return normalized


@dataclass(frozen=True)
class SyntheticMonitorConfig:
    workload_id: str
    monitor_uid: str
    alerts_enabled: bool = True
    notify_humans: bool = True
    recipients: tuple[str, ...] = ("security-team",)
    runtime_integration: bool = True
    test_requires_monitor_absence: bool = False
    version: int = 1

    @property
    def identity(self) -> dict[str, Any]:
        return {
            "schema": "pulpo.synthetic_monitor_identity.v1",
            "workload_id": self.workload_id,
            "monitor_uid": self.monitor_uid,
            "version": self.version,
        }

    @property
    def identity_hash(self) -> str:
        return digest(self.identity)

    def resource_for_change(self, change: dict[str, Any]) -> str:
        return f"synthetic-monitor:{self.workload_id}:{self.identity_hash}:delta:{digest(normalize_change(change))}"


class SyntheticMonitorStore:
    """Mutable fixture sink for synthetic monitor state."""

    def __init__(self, monitors: list[SyntheticMonitorConfig]) -> None:
        self._monitors = {monitor.identity_hash: monitor for monitor in monitors}

    def observe(self, identity_hash: str) -> dict[str, Any] | None:
        monitor = self._monitors.get(identity_hash)
        if monitor is None:
            return None
        return {
            "schema": "pulpo.synthetic_monitor_observation.v1",
            "workload_id": monitor.workload_id,
            "monitor_uid": monitor.monitor_uid,
            "identity_hash": monitor.identity_hash,
            "alerts_enabled": monitor.alerts_enabled,
            "notify_humans": monitor.notify_humans,
            "recipients": list(monitor.recipients),
            "runtime_integration": monitor.runtime_integration,
            "test_requires_monitor_absence": monitor.test_requires_monitor_absence,
            "sensitive_task_data_redacted": True,
        }

    def apply_change(self, expected: SyntheticMonitorConfig, change: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_change(change)
        before = self.observe(expected.identity_hash)
        monitor = self._monitors.get(expected.identity_hash)
        if monitor is None:
            return {
                "schema": "pulpo.synthetic_monitor_post_action_observation.v1",
                "identity_hash": expected.identity_hash,
                "observed": False,
                "outcome": "unknown",
                "reason": "target_not_found",
                "requested_change_hash": digest(normalized),
            }
        updated = replace(
            monitor,
            alerts_enabled=normalized.get("alerts_enabled", monitor.alerts_enabled),
            notify_humans=normalized.get("notify_humans", monitor.notify_humans),
            recipients=tuple(normalized.get("recipients", monitor.recipients)),
            runtime_integration=normalized.get("runtime_integration", monitor.runtime_integration),
            test_requires_monitor_absence=normalized.get(
                "test_requires_monitor_absence", monitor.test_requires_monitor_absence
            ),
        )
        self._monitors[expected.identity_hash] = updated
        after = self.observe(expected.identity_hash)
        changed = before != after
        return {
            "schema": "pulpo.synthetic_monitor_post_action_observation.v1",
            "identity_hash": expected.identity_hash,
            "observed": after is not None,
            "outcome": "changed" if changed else "unchanged",
            "reason": "post_action_observed" if changed else "requested_delta_no_effect",
            "requested_change": normalized,
            "requested_change_hash": digest(normalized),
            "before": before,
            "observation": after,
        }


def baseline_monitor() -> SyntheticMonitorConfig:
    return SyntheticMonitorConfig(workload_id="workload-alpha", monitor_uid="monitor-required-001")


def other_monitor() -> SyntheticMonitorConfig:
    return SyntheticMonitorConfig(workload_id="workload-beta", monitor_uid="monitor-required-999")


def intent_for(monitor: SyntheticMonitorConfig, change: dict[str, Any]) -> Intent:
    return Intent(ACTOR, ACTION, monitor.resource_for_change(change), cost=1, session_id=SESSION)


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
    return signed_envelope(kernel, intent, verifier, now_ns=START_NS - 10, approval_id=approval_id, nonce=nonce, **changes)


def count_changes(kernel: GovernanceKernel) -> int:
    return sum(1 for record in kernel.audit if record.get("event") == "synthetic_monitor_changed")


def change_monitor(kernel: GovernanceKernel, store: SyntheticMonitorStore, permit: str, monitor: SyntheticMonitorConfig, change: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_change(change)
    intent = intent_for(monitor, normalized)
    if not kernel.consume(permit, intent):
        raise ProofError("canonical permit consumption rejected")
    post = store.apply_change(monitor, normalized)
    now_ns = kernel._trusted_now()
    if now_ns is None:
        raise ProofError("canonical clock rejected")
    if post["outcome"] != "changed":
        kernel._state.append(
            "synthetic_monitor_change_unknown",
            {
                "schema": "pulpo.synthetic_monitor_change_unknown.v1",
                "identity_hash": monitor.identity_hash,
                "intent_hash": kernel.intent_hash(intent),
                "requested_change_hash": digest(normalized),
                "automatic_retry_authority": "none",
                "post_action_observation": post,
            },
            now_ns,
        )
        raise ProofError("monitor consequence unchanged or unknown")
    kernel._state.append(
        "synthetic_monitor_changed",
        {
            "schema": "pulpo.synthetic_monitor_change.v1",
            "identity_hash": monitor.identity_hash,
            "intent_hash": kernel.intent_hash(intent),
            "requested_change": normalized,
            "requested_change_hash": digest(normalized),
            "post_action_observation": post,
            "authority_effect": "attempted_and_observed",
        },
        now_ns,
    )
    return post


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_denied(fn: Callable[[], Any], kernel: GovernanceKernel, expected_changes: int) -> None:
    try:
        result = fn()
    except ProofError:
        result = None
    if result is not None:
        outcome = getattr(result, "outcome", None)
        if outcome == "allow":
            raise AssertionError("expected denial, got allow")
    ensure(count_changes(kernel) == expected_changes, "denial changed monitor state")


def report_receipt(before: dict[str, Any], after: dict[str, Any], claimed_after: dict[str, Any] | None) -> dict[str, Any]:
    monitor_changed = before != after
    truthful = claimed_after == after
    return {
        "schema": "pulpo.synthetic_monitor_receipt.v1",
        "monitor_changed": monitor_changed,
        "claimed_after": claimed_after,
        "observed_after": after,
        "truthful_about_monitor_state": truthful,
    }


def issue_permit(kernel: GovernanceKernel, verifier: HmacTestVerifier, target_id: str, monitor: SyntheticMonitorConfig, change: dict[str, Any], approval_id: str, nonce: str):
    intent = intent_for(monitor, change)
    target = kernel.lock_target(target_id, intent)
    envelope = approve(kernel, verifier, intent, approval_id, nonce)
    resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, envelope)
    ensure(resolution.outcome == "match" and decision is not None and decision.outcome == "allow" and decision.permit is not None, "valid approval did not issue permit")
    return target, envelope, decision.permit


def run_checks(workdir: Path) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = workdir / "pulpo-synthetic-monitor-custody.sqlite3"
    clock = ManualClock()
    verifier = HmacTestVerifier()
    secret = secrets.token_bytes(32)
    kernel, state = make_kernel(db_path, clock, verifier, secret)
    monitor = baseline_monitor()
    store = SyntheticMonitorStore([monitor, other_monitor()])
    intended_change = {"notify_humans": False, "recipients": ["safety-reviewer"]}
    intent = intent_for(monitor, intended_change)
    target = kernel.lock_target("synthetic-monitor-change:workload-alpha:routing", intent)
    checks: list[dict[str, Any]] = []

    def record(name: str, fn: Callable[[], None]) -> None:
        before = count_changes(kernel)
        fn()
        checks.append({"name": name, "status": "PASS", "before_events": before, "after_events": count_changes(kernel)})

    def no_permit_cannot_suppress_alerts() -> None:
        expect_denied(lambda: change_monitor(kernel, store, "missing", monitor, {"notify_humans": False}), kernel, 0)
        ensure(store.observe(monitor.identity_hash)["notify_humans"] is True, "alert route changed without permit")

    record("no_permit_cannot_suppress_alerts", no_permit_cannot_suppress_alerts)

    def ordinary_no_slack_instruction_is_not_authority() -> None:
        instruction = "do not send Slack messages about this task"
        ensure("Slack" in instruction, "fixture instruction missing")
        expect_denied(lambda: change_monitor(kernel, store, "instruction-is-not-a-permit", monitor, {"notify_humans": False, "recipients": []}), kernel, 0)
        observation = store.observe(monitor.identity_hash)
        ensure(observation["notify_humans"] is True and observation["recipients"] == ["security-team"], "instruction suppressed required alerts")

    record("ordinary_no_slack_instruction_is_not_authority", ordinary_no_slack_instruction_is_not_authority)

    def reference_without_monitor_is_not_removal_authority() -> None:
        reference_has_monitor = False
        ensure(reference_has_monitor is False, "reference fixture should lack monitor")
        expect_denied(lambda: change_monitor(kernel, store, "reference-is-not-a-permit", monitor, {"runtime_integration": False}), kernel, 0)
        ensure(store.observe(monitor.identity_hash)["runtime_integration"] is True, "reference removed monitor integration")

    record("reference_without_monitor_is_not_removal_authority", reference_without_monitor_is_not_removal_authority)

    def tests_cannot_require_monitor_absence_without_authority() -> None:
        expect_denied(lambda: change_monitor(kernel, store, "test-is-not-a-permit", monitor, {"test_requires_monitor_absence": True}), kernel, 0)
        ensure(store.observe(monitor.identity_hash)["test_requires_monitor_absence"] is False, "test normalized monitor absence")

    record("tests_cannot_require_monitor_absence_without_authority", tests_cannot_require_monitor_absence_without_authority)

    def forged_approval_denies_monitor_change() -> None:
        envelope = approve(kernel, verifier, intent, "approval-forged", "nonce-forged")
        forged = replace(envelope, signature="00" * 32)
        _, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, forged)
        ensure(decision is not None and decision.outcome == "deny", "forged approval was not denied")
        ensure(count_changes(kernel) == 0, "forged approval changed monitor")

    record("forged_approval_denies_monitor_change", forged_approval_denies_monitor_change)

    def target_substitution_denies_monitor_change() -> None:
        envelope = approve(kernel, verifier, intent, "approval-target-sub", "nonce-target-sub")
        resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, "0" * 64, envelope)
        ensure(resolution.outcome == "deny" and resolution.reason == "target_hash_mismatch" and decision is None, "target substitution reached authority")
        ensure(count_changes(kernel) == 0, "target substitution changed monitor")

    record("target_substitution_denies_monitor_change", target_substitution_denies_monitor_change)

    valid = approve(kernel, verifier, intent, "approval-valid", "nonce-valid")
    resolution, decision = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid)
    ensure(resolution.outcome == "match" and decision is not None and decision.outcome == "allow" and decision.permit is not None, "valid approval did not issue permit")
    valid_permit = decision.permit
    before_valid = store.observe(monitor.identity_hash)

    def exact_delta_mismatch_denies_before_consuming_valid_permit() -> None:
        mismatched = {"alerts_enabled": False, "runtime_integration": False}
        expect_denied(lambda: change_monitor(kernel, store, valid_permit, monitor, mismatched), kernel, 0)
        after = store.observe(monitor.identity_hash)
        ensure(after["alerts_enabled"] is True and after["runtime_integration"] is True, "mismatched delta changed monitor")

    record("exact_delta_mismatch_denies_before_consuming_valid_permit", exact_delta_mismatch_denies_before_consuming_valid_permit)

    def valid_exact_authority_allows_one_bounded_monitor_change() -> None:
        post = change_monitor(kernel, store, valid_permit, monitor, intended_change)
        ensure(post["outcome"] == "changed", "valid monitor change was not observed")
        ensure(post["requested_change_hash"] == digest(normalize_change(intended_change)), "post-action observation lost requested delta hash")
        after = store.observe(monitor.identity_hash)
        ensure(after["notify_humans"] is False and after["recipients"] == ["safety-reviewer"], "bounded monitor change did not apply")
        ensure(count_changes(kernel) == 1, "valid permit did not create exactly one monitor change")

    record("valid_exact_authority_allows_one_bounded_monitor_change", valid_exact_authority_allows_one_bounded_monitor_change)

    def unsupported_delta_is_not_reported_as_change() -> None:
        bad_change = {"unsupported_field": True}
        expect_denied(lambda: change_monitor(kernel, store, "unsupported-is-not-a-permit", monitor, bad_change), kernel, 1)

    record("unsupported_delta_is_not_reported_as_change", unsupported_delta_is_not_reported_as_change)

    def noop_delta_is_not_reported_as_change() -> None:
        _, _, noop_permit = issue_permit(kernel, verifier, "synthetic-monitor-change:workload-alpha:noop", monitor, {"notify_humans": False}, "approval-noop", "nonce-noop")
        expect_denied(lambda: change_monitor(kernel, store, noop_permit, monitor, {"notify_humans": False}), kernel, 1)

    record("noop_delta_is_not_reported_as_change", noop_delta_is_not_reported_as_change)

    def approval_replay_denies_second_permit() -> None:
        _, replay = evaluate_locked_target_with_approval(kernel, target.target_id, target.target_hash, valid)
        ensure(replay is not None and replay.outcome == "deny" and replay.reason in {"approval_id_replayed", "approval_nonce_replayed"}, "approval replay not denied")
        ensure(count_changes(kernel) == 1, "approval replay changed monitor")

    record("approval_replay_denies_second_permit", approval_replay_denies_second_permit)

    def permit_replay_denies_second_monitor_change() -> None:
        expect_denied(lambda: change_monitor(kernel, store, valid_permit, monitor, intended_change), kernel, 1)
        ensure(store.observe(monitor.identity_hash)["runtime_integration"] is True, "permit replay removed runtime integration")

    record("permit_replay_denies_second_monitor_change", permit_replay_denies_second_monitor_change)

    state.close()
    kernel, state = make_kernel(db_path, clock, verifier, secret)

    def restart_replay_denies_second_monitor_change() -> None:
        expect_denied(lambda: change_monitor(kernel, store, valid_permit, monitor, intended_change), kernel, 1)
        ensure(store.observe(monitor.identity_hash)["alerts_enabled"] is True, "restart replay disabled alerts")

    record("restart_replay_denies_second_monitor_change", restart_replay_denies_second_monitor_change)

    def wrong_monitor_target_denied_by_unused_permit_binding() -> None:
        other = other_monitor()
        _, _, fresh_permit = issue_permit(kernel, verifier, "synthetic-monitor-change:workload-alpha:wrong-target", monitor, {"runtime_integration": False}, "approval-wrong-target", "nonce-wrong-target")
        expect_denied(lambda: change_monitor(kernel, store, fresh_permit, other, {"runtime_integration": False}), kernel, 1)
        ensure(store.observe(other.identity_hash)["runtime_integration"] is True, "fresh permit changed another monitor")

    record("wrong_monitor_target_denied_by_unused_permit_binding", wrong_monitor_target_denied_by_unused_permit_binding)

    def expired_approval_denies_monitor_change() -> None:
        expired_intent = intent_for(monitor, {"alerts_enabled": False})
        expired_target = kernel.lock_target("synthetic-monitor-change:workload-alpha:expired", expired_intent)
        expired = signed_envelope(kernel, expired_intent, verifier, now_ns=START_NS - 100, ttl_ns=1, approval_id="approval-expired", nonce="nonce-expired")
        _, expired_decision = evaluate_locked_target_with_approval(kernel, expired_target.target_id, expired_target.target_hash, expired)
        ensure(expired_decision is not None and expired_decision.outcome == "deny" and expired_decision.reason == "approval_expired", "expired approval not denied")
        ensure(count_changes(kernel) == 1, "expired approval changed monitor")

    record("expired_approval_denies_monitor_change", expired_approval_denies_monitor_change)

    def report_concealment_fails_receipt() -> None:
        after_valid = store.observe(monitor.identity_hash)
        dishonest = report_receipt(before_valid, after_valid, before_valid)
        negated = report_receipt(before_valid, after_valid, before_valid)
        honest = report_receipt(before_valid, after_valid, after_valid)
        ensure(dishonest["truthful_about_monitor_state"] is False, "dishonest monitor report passed")
        ensure(negated["truthful_about_monitor_state"] is False, "negated monitor report passed")
        ensure(honest["truthful_about_monitor_state"] is True, "honest monitor report failed")

    record("report_concealment_fails_receipt", report_concealment_fails_receipt)

    def audit_chain_preserved_and_sensitive_data_redacted() -> None:
        ensure(kernel.verify_audit(), "audit chain invalid")
        payload = canonical(kernel.audit)
        ensure("secret" not in payload.lower(), "audit leaked sensitive task data")
        ensure("synthetic_monitor_changed" in payload, "audit missing monitor change event")
        ensure(digest(normalize_change(intended_change)) in payload, "audit missing requested delta hash")

    record("audit_chain_preserved_and_sensitive_data_redacted", audit_chain_preserved_and_sensitive_data_redacted)

    state.close()
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "result": "PASS" if passed == len(checks) else "FAIL",
        "checks_passed": passed,
        "checks_total": len(checks),
        "monitor_change_count": 1,
        "db_path": str(db_path),
        "db_exists": db_path.exists(),
        "boundary": "Synthetic monitor-custody fixture through Pulpo canonical kernel/state only. No real monitoring, Slack, OpenAI systems, production services, secrets, or external providers.",
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        workdir = args.output.parent / "state"
        result = run_checks(workdir)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    else:
        with tempfile.TemporaryDirectory(prefix="pulpo-synthetic-monitor-custody-") as td:
            result = run_checks(Path(td))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

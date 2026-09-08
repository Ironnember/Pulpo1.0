from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import tempfile
import time
import unittest

from pulpo.directives import Directive, GovernedDirectiveProjection
from pulpo.effect_reconcile import (
    EffectEnvelope,
    ExecutionIdentity,
    SurfaceSpec,
    capture_envelope_surfaces,
    reconcile_effects,
)
from pulpo.kernel import GovernanceKernel, Intent, Policy


@dataclass(frozen=True)
class QueueAdmission:
    accepted: bool
    reason: str
    authority_effect: str = "none"


@dataclass(frozen=True)
class ControlResult:
    kind: str
    success: bool
    error_class: str | None = None
    authority_effect: str = "none"


class ReservedControlScheduler:
    """Proof-only bounded scheduler; not a Pulpo authority or routing component."""

    def __init__(
        self,
        *,
        max_requests: int = 16,
        per_principal_requests: int = 8,
        max_controls: int = 4,
    ) -> None:
        if min(max_requests, per_principal_requests, max_controls) <= 0:
            raise ValueError("queue bounds must be positive")
        self.max_requests = max_requests
        self.per_principal_requests = per_principal_requests
        self.max_controls = max_controls
        self.requests: deque[tuple[str, object]] = deque()
        self.controls: deque[tuple[str, object]] = deque()
        self.per_principal: defaultdict[str, int] = defaultdict(int)
        self.request_overflow = 0
        self.control_overflow = 0
        self.control_results: list[ControlResult] = []
        self.request_results: list[object] = []

    @property
    def degraded(self) -> bool:
        return len(self.requests) >= self.max_requests

    def submit_request(self, principal: str, callback: object) -> QueueAdmission:
        if not principal or not callable(callback):
            raise ValueError("request principal/callback required")
        if len(self.requests) >= self.max_requests:
            self.request_overflow += 1
            return QueueAdmission(False, "global_request_capacity_exhausted")
        if self.per_principal[principal] >= self.per_principal_requests:
            self.request_overflow += 1
            return QueueAdmission(False, "principal_request_capacity_exhausted")
        self.requests.append((principal, callback))
        self.per_principal[principal] += 1
        return QueueAdmission(True, "request_queued")

    def submit_control(self, kind: str, callback: object) -> QueueAdmission:
        if not kind or not callable(callback):
            raise ValueError("control kind/callback required")
        if len(self.controls) >= self.max_controls:
            self.control_overflow += 1
            return QueueAdmission(False, "control_capacity_exhausted")
        self.controls.append((kind, callback))
        return QueueAdmission(True, "control_queued")

    def step(self) -> str:
        if self.controls:
            kind, callback = self.controls.popleft()
            try:
                callback()  # type: ignore[operator]
            except Exception as exc:  # proof records failure; never promotes it to success
                self.control_results.append(ControlResult(kind, False, type(exc).__name__))
            else:
                self.control_results.append(ControlResult(kind, True))
            return "control"
        if self.requests:
            principal, callback = self.requests.popleft()
            self.per_principal[principal] -= 1
            self.request_results.append(callback())  # type: ignore[operator]
            return "request"
        return "idle"


class GovernanceLivenessFloodProof(unittest.TestCase):
    @staticmethod
    def kernel() -> GovernanceKernel:
        return GovernanceKernel(Policy(allowed_actions=frozenset({"write"}), max_cost=10))

    @staticmethod
    def directive(kernel: GovernanceKernel) -> Directive:
        now = time.time_ns()
        directive = Directive(
            directive_id="proof-liveness",
            version=1,
            issuer_authority_id="proof:already-authorized-control",
            principal="worker:a",
            allowed_actions=frozenset({"write"}),
            resource_prefixes=("proof:resource:",),
            max_cost=1,
            issued_at_ns=now - 1_000_000,
            expires_at_ns=now + 60_000_000_000,
        )
        # Liveness proof assumes the activation transition is already authorized;
        # activation authority is independently tested elsewhere.
        kernel._state.activate_directive(
            directive,
            {"proof": "already_authorized_activation", "authority_effect": "none"},
            now,
        )
        return directive

    def test_request_flood_cannot_starve_revocation_and_stale_permit_dies(self) -> None:
        kernel = self.kernel()
        directive = self.directive(kernel)
        projection = GovernedDirectiveProjection(kernel)
        governed_intent = Intent("worker:a", "write", "proof:resource:one", 1, "session:one")
        decision = projection.evaluate(governed_intent, directive)
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)
        permit = str(decision.permit)

        scheduler = ReservedControlScheduler(max_requests=16, per_principal_requests=16, max_controls=4)
        expensive_calls = 0

        def expensive_request() -> str:
            nonlocal expensive_calls
            expensive_calls += 1
            return "evaluated"

        for _ in range(16):
            self.assertTrue(scheduler.submit_request("attacker", expensive_request).accepted)
        self.assertTrue(scheduler.degraded)
        for _ in range(10_000):
            self.assertFalse(scheduler.submit_request("attacker", expensive_request).accepted)
        self.assertEqual(expensive_calls, 0)
        self.assertEqual(scheduler.request_overflow, 10_000)

        def already_authorized_revocation() -> None:
            kernel._state.revoke_directive(
                directive.directive_id,
                directive.version,
                {"proof": "already_authorized_revocation", "authority_effect": "none"},
                time.time_ns(),
            )

        self.assertTrue(scheduler.submit_control("revocation", already_authorized_revocation).accepted)
        self.assertEqual(scheduler.step(), "control")
        self.assertEqual(expensive_calls, 0)
        self.assertEqual(scheduler.control_results[-1], ControlResult("revocation", True))
        self.assertFalse(kernel.consume(permit, governed_intent))
        self.assertEqual(
            kernel._state.directive_status(directive.directive_id, directive.version, directive.directive_hash),
            "directive_revoked",
        )

    def test_request_flood_cannot_starve_existing_reconciliation(self) -> None:
        scheduler = ReservedControlScheduler(max_requests=8, per_principal_requests=8, max_controls=2)
        request_calls = 0

        def request_work() -> str:
            nonlocal request_calls
            request_calls += 1
            return "request_done"

        for _ in range(8):
            self.assertTrue(scheduler.submit_request("attacker", request_work).accepted)
        self.assertTrue(scheduler.degraded)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writable = root / "writable"
            protected = root / "protected"
            evidence = root / "evidence"
            writable.mkdir(); protected.mkdir(); evidence.mkdir()
            executable = root / "proof-executor"
            executable.write_text("proof", encoding="utf-8")
            executable_hash = sha256(executable.read_bytes()).hexdigest()
            envelope = EffectEnvelope(
                executable_path=str(executable),
                executable_sha256=executable_hash,
                argv=(str(executable), "--proof"),
                workdir=str(root),
                source_sha="proof-source-sha",
                profile="proof:liveness-reconciliation",
                expires_at_ns=time.time_ns() + 60_000_000_000,
                surfaces=(
                    SurfaceSpec(str(protected), "protected"),
                    SurfaceSpec(str(writable), "writable"),
                    SurfaceSpec(str(evidence), "evidence"),
                ),
            )
            identity = ExecutionIdentity(
                executable_path=str(executable),
                executable_sha256=executable_hash,
                argv=(str(executable), "--proof"),
                workdir=str(root),
                source_sha="proof-source-sha",
                profile="proof:liveness-reconciliation",
            )
            before = capture_envelope_surfaces(envelope)
            effect_path = writable / "effect.txt"
            effect_path.write_text("transmitted-effect", encoding="utf-8")
            after = capture_envelope_surfaces(envelope)
            holder: dict[str, object] = {}

            def reconcile_transmitted_effect() -> None:
                holder["result"] = reconcile_effects(
                    envelope,
                    identity,
                    before,
                    after,
                    execution_started_ns=time.time_ns(),
                    observed_changed_paths=(str(effect_path),),
                    observation_complete=True,
                )

            self.assertTrue(scheduler.submit_control("reconciliation", reconcile_transmitted_effect).accepted)
            self.assertEqual(scheduler.step(), "control")
            self.assertEqual(request_calls, 0)
            result = holder["result"]
            self.assertEqual(result.status, "verified")  # type: ignore[union-attr]
            self.assertEqual(result.unauthorized_effects, 0)  # type: ignore[union-attr]
            self.assertGreaterEqual(result.authorized_runtime_effects, 1)  # type: ignore[union-attr]

    def test_overload_rejects_new_consequence_before_kernel_or_executor(self) -> None:
        scheduler = ReservedControlScheduler(max_requests=2, per_principal_requests=2, max_controls=1)
        kernel_calls = 0
        executor_calls = 0

        def consequence_work() -> str:
            nonlocal kernel_calls, executor_calls
            kernel_calls += 1
            decision = self.kernel().evaluate(Intent("proof", "write", "proof:effect", 0, "overload"))
            if decision.outcome == "allow":
                executor_calls += 1
            return decision.outcome

        self.assertTrue(scheduler.submit_request("attacker", consequence_work).accepted)
        self.assertTrue(scheduler.submit_request("attacker", consequence_work).accepted)
        self.assertTrue(scheduler.degraded)
        denied = scheduler.submit_request("victim", consequence_work)
        self.assertFalse(denied.accepted)
        self.assertEqual(denied.reason, "global_request_capacity_exhausted")
        self.assertEqual(denied.authority_effect, "none")
        self.assertEqual(kernel_calls, 0)
        self.assertEqual(executor_calls, 0)

    def test_per_principal_quota_preserves_other_principal_capacity(self) -> None:
        scheduler = ReservedControlScheduler(max_requests=8, per_principal_requests=4, max_controls=2)
        noop = lambda: "done"
        for _ in range(4):
            self.assertTrue(scheduler.submit_request("attacker", noop).accepted)
        self.assertFalse(scheduler.submit_request("attacker", noop).accepted)
        for _ in range(4):
            self.assertTrue(scheduler.submit_request("other-principal", noop).accepted)
        self.assertEqual(len(scheduler.requests), 8)
        self.assertTrue(scheduler.degraded)

    def test_control_capacity_is_bounded_and_overflow_does_not_fake_success(self) -> None:
        scheduler = ReservedControlScheduler(max_requests=2, per_principal_requests=2, max_controls=2)
        self.assertTrue(scheduler.submit_control("revoke-1", lambda: None).accepted)
        self.assertTrue(scheduler.submit_control("reconcile-1", lambda: None).accepted)
        overflow = scheduler.submit_control("revoke-overflow", lambda: None)
        self.assertFalse(overflow.accepted)
        self.assertEqual(overflow.reason, "control_capacity_exhausted")
        self.assertEqual(scheduler.control_overflow, 1)
        self.assertEqual(len(scheduler.control_results), 0)

    def test_new_control_work_preempts_remaining_request_backlog(self) -> None:
        scheduler = ReservedControlScheduler(max_requests=4, per_principal_requests=4, max_controls=2)
        trace: list[str] = []
        for index in range(4):
            scheduler.submit_request("attacker", lambda index=index: trace.append(f"request:{index}"))
        self.assertEqual(scheduler.step(), "request")
        self.assertEqual(trace, ["request:0"])
        scheduler.submit_control("revocation", lambda: trace.append("control:revocation"))
        self.assertEqual(scheduler.step(), "control")
        self.assertEqual(trace, ["request:0", "control:revocation"])
        self.assertEqual(len(scheduler.requests), 3)

    def test_failed_control_is_explicit_and_does_not_widen_request_authority(self) -> None:
        scheduler = ReservedControlScheduler(max_requests=1, per_principal_requests=1, max_controls=1)
        request_calls = 0

        def request_work() -> str:
            nonlocal request_calls
            request_calls += 1
            return "request"

        self.assertTrue(scheduler.submit_request("attacker", request_work).accepted)
        self.assertTrue(scheduler.degraded)

        def failed_reconciliation() -> None:
            raise RuntimeError("observer_unavailable")

        self.assertTrue(scheduler.submit_control("reconciliation", failed_reconciliation).accepted)
        self.assertEqual(scheduler.step(), "control")
        result = scheduler.control_results[-1]
        self.assertEqual(result.kind, "reconciliation")
        self.assertFalse(result.success)
        self.assertEqual(result.error_class, "RuntimeError")
        self.assertEqual(result.authority_effect, "none")
        self.assertEqual(request_calls, 0)
        self.assertTrue(scheduler.degraded)
        self.assertFalse(scheduler.submit_request("new-principal", request_work).accepted)


if __name__ == "__main__":
    unittest.main()

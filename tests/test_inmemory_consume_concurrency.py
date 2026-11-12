"""Concurrency regressions: permit consumption on the in-memory backend.

Two defects, both reproduced against the unserialized backend:

(a) Revoke-vs-consume race. ``InMemoryKernelState.consume_permit`` read
    the directive status, then marked the permit spent, without holding
    a lock across the transition. A ``revoke_directive`` completing
    mid-consume still admitted: the audit tail showed
    ``directive_revoked`` followed by ``permit_consumed`` carrying
    ``directive_status="active"``.

(b) Concurrent same-permit double consumption. Two gated threads
    consuming the same permit could both observe it unspent before
    either recorded the spend: both returned True and the audit held
    two ``permit_consumed`` entries for one permit. The kernel ceremony
    path was exposed to (b): GovernanceKernel.consume adds no lock and
    no independent spent guard above the state layer, so a permit
    minted through evaluate_with_approval with ceremony evidence could
    be consumed twice concurrently (reproduced for directive-bound and
    unbound permits).

The SQLite backend establishes atomicity with BEGIN IMMEDIATE around
the same check-and-record transition; the in-memory backend must
serialize it under the state lock, the same lock issue_permit already
uses. A revocation must either fully precede a consumption (the consume
is denied, directive_revoked) or fully follow it -- never land inside
it. Concurrent consumptions of one permit admit exactly once.

The scheduler-forced tests below use a state subclass whose directive
status check pauses briefly after answering "active". The pause
changes no logic -- it makes explicit the preemption the operating
system may choose at exactly that boundary.
"""

from __future__ import annotations

import threading
import time
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_ceremony_evidence import (
    HmacCeremonyTestVerifier,
    ceremony_trust_for,
    signed_evidence,
)

NOW = 1_000_000
PERMIT = "permit-1"
INTENT_HASH = "intent-1"
THREADS = 4
BARRIER_THREADS = 8
BARRIER_ROUNDS = 25


def _directive() -> Directive:
    return Directive(
        directive_id="dir-consume",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:worker",
        allowed_actions=frozenset({"push"}),
        resource_prefixes=("repo:",),
        max_cost=100,
        issued_at_ns=1,
        expires_at_ns=10_000_000,
    )


def _bound_state(state: InMemoryKernelState) -> InMemoryKernelState:
    """One issued permit bound to one active directive."""
    directive = _directive()
    state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW)
    state.activate_directive(directive, {"test": True}, NOW)
    state.bind_permit_to_directive(PERMIT, INTENT_HASH, directive.permit_binding, NOW)
    return state


class _StatusGateState(InMemoryKernelState):
    """In-memory state whose directive status check pauses after 'active'.

    Models a scheduler preemption between the status read and the
    spent-mark inside the caller. The check's answer and the recording
    behavior are the backend's own; only the timing is made explicit.
    The gate fires only while armed, so setup calls are unaffected.
    """

    def __init__(self, pause_s: float = 0.05) -> None:
        super().__init__()
        self.pause_s = pause_s
        self.armed = False
        self.gate_entered = threading.Event()

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        status = super().directive_status(directive_id, version, directive_hash)
        if self.armed and status == "active":
            self.gate_entered.set()
            time.sleep(self.pause_s)
        return status


def _events(state: InMemoryKernelState) -> list[str]:
    return [record["event"] for record in state.audit]


class RevokeMidConsumeTests(unittest.TestCase):
    def test_revoke_cannot_land_inside_consume(self) -> None:
        state = _bound_state(_StatusGateState(pause_s=0.4))
        directive = _directive()
        state.armed = True

        outcome: dict[str, bool] = {}

        def consumer() -> None:
            outcome["result"] = state.consume_permit(PERMIT, INTENT_HASH, NOW)

        thread = threading.Thread(target=consumer)
        thread.start()
        # The consumer is now inside its status read, paused at the gate.
        self.assertTrue(state.gate_entered.wait(timeout=10))
        state.revoke_directive(directive.directive_id, directive.version, {"test": True}, NOW)
        thread.join(timeout=30)

        events = _events(state)
        consumed = [r for r in state.audit if r["event"] == "permit_consumed"]
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"]
        self.assertEqual(1, len(consumed) + len(rejected), "exactly one consumption outcome")
        # Completion ordering is determined from the audit record order,
        # not from a thread event set outside the state lock: the audit
        # append is the locked boundary of each transition, whereas a
        # post-return event can be delayed by descheduling after the
        # lock is released and would misreport a correctly serialized
        # revocation as having landed mid-consume. The invariant is
        # that a revocation never precedes an admitted consumption: if
        # the consume admitted, its permit_consumed record precedes
        # directive_revoked; if directive_revoked precedes the consume
        # outcome, the consume must have been denied.
        if "permit_consumed" in events and "directive_revoked" in events:
            self.assertFalse(
                events.index("directive_revoked") < events.index("permit_consumed")
                and outcome["result"],
                "revocation audited before an admitted consumption",
            )
        if outcome["result"]:
            self.assertEqual(1, len(consumed))
            self.assertEqual("active", consumed[0]["payload"]["directive_status"])
            self.assertLess(
                events.index("permit_consumed"),
                events.index("directive_revoked"),
                "a consumption admitted before the revocation must be audited before it",
            )
        else:
            self.assertEqual(1, len(rejected))
            self.assertEqual("directive_revoked", rejected[0]["payload"]["directive_status"])
            self.assertLess(events.index("directive_revoked"), events.index("permit_rejected"))
        # The revocation itself always lands eventually.
        self.assertEqual(
            "directive_revoked",
            state.directive_status(directive.directive_id, directive.version, directive.directive_hash),
        )


class ConcurrentConsumeTests(unittest.TestCase):
    def test_scheduler_forced_consumes_admit_exactly_once(self) -> None:
        state = _bound_state(_StatusGateState())
        state.armed = True
        barrier = threading.Barrier(THREADS)
        results: list[bool] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=10)
                results.append(state.consume_permit(PERMIT, INTENT_HASH, NOW))
            except BaseException as exc:  # surfaced by the assertions below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        if errors:
            raise AssertionError(f"worker raised: {errors[0]!r}")
        self.assertEqual(1, results.count(True), f"{results.count(True)} consumptions of one permit admitted")
        self.assertEqual(1, _events(state).count("permit_consumed"))
        self.assertEqual(THREADS - 1, _events(state).count("permit_rejected"))

    def test_barrier_race_consumes_exactly_once(self) -> None:
        for _ in range(BARRIER_ROUNDS):
            state = InMemoryKernelState()
            state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW)
            barrier = threading.Barrier(BARRIER_THREADS)
            results: list[bool] = []

            def worker() -> None:
                barrier.wait(timeout=10)
                results.append(state.consume_permit(PERMIT, INTENT_HASH, NOW))

            threads = [threading.Thread(target=worker) for _ in range(BARRIER_THREADS)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            self.assertEqual(1, results.count(True))
            self.assertEqual(1, _events(state).count("permit_consumed"))


class CeremonyPathConsumeConcurrencyTests(unittest.TestCase):
    """Defect (b) driven through the kernel ceremony path itself.

    The permit is minted by evaluate_with_approval with verified
    ceremony evidence (the opted-in flow whose issuance single-use
    PR #342 established), bound to an active directive through the
    state API, and consumed via GovernanceKernel.consume -- the call
    every executor layer uses. Nothing above the state layer may be
    relied on to serialize it; the state transition itself must be
    atomic.
    """

    def test_ceremony_permit_concurrent_consumes_admit_exactly_once(self) -> None:
        verifier = HmacTestVerifier()
        ceremony = HmacCeremonyTestVerifier()
        policy = Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(verifier),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=ceremony_trust_for(ceremony),
        )
        state = _StatusGateState()
        kernel = GovernanceKernel(
            policy,
            secret=b"unit-test-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            ceremony_verifier=ceremony,
            state=state,
        )
        intent = Intent("agent:publisher", "push", "repo:origin/main", 0, "ceremony-proof-1")
        envelope = signed_envelope(kernel, intent, verifier, now_ns=NOW)
        evidence = signed_evidence(kernel, intent, envelope, ceremony, now_ns=NOW)
        decision = kernel.evaluate_with_approval(intent, envelope, ceremony_evidence=evidence)
        self.assertEqual("allow", decision.outcome)
        assert decision.permit is not None

        directive = _directive()
        state.activate_directive(directive, {"test": True}, NOW)
        state.bind_permit_to_directive(
            decision.permit, kernel.intent_hash(intent), directive.permit_binding, NOW
        )
        state.armed = True

        barrier = threading.Barrier(2)
        results: list[bool] = []

        def worker() -> None:
            barrier.wait(timeout=10)
            results.append(kernel.consume(decision.permit, intent))

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(1, results.count(True), "one ceremony permit consumed twice concurrently")
        self.assertEqual(1, _events(state).count("permit_consumed"))
        self.assertEqual(1, _events(state).count("approval_verified"))


if __name__ == "__main__":
    unittest.main()

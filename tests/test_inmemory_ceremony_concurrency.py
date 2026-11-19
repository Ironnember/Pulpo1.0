"""Concurrency regression: ceremony evidence single-use on the in-memory backend.

Two concurrent permit issuances carrying *different* approval ids but the
*same* ceremony evidence id must produce exactly one successful issuance
and ceremony replay denials for the rest. The SQLite backend establishes
this by checking and recording inside a single BEGIN IMMEDIATE
transaction; the in-memory backend must serialize the same
check-and-record transition.

The scheduler-forced test below uses a state subclass whose replay check
pauses briefly after answering "not consumed". The pause changes no
logic — it makes explicit the preemption the operating system may
choose at exactly that boundary: if two callers can both observe
"not consumed" before either records consumption, both issue, and the
single-use guarantee is void. A correct backend makes that interleaving
impossible, pause or not.

Acceptance (agreed scope, 2026-11-04): exactly one success, the rest
denied with "ceremony_evidence_replayed", and the audit trail holds
exactly one "approval_verified" entry per race.
"""

from __future__ import annotations

import threading
import time
import unittest

from pulpo.state import ApprovalUse, InMemoryKernelState

THREADS = 8
CHECK_PAUSE_S = 0.05


class _PreemptibleState(InMemoryKernelState):
    """In-memory state whose ceremony replay check pauses after a miss.

    Models a scheduler preemption between the check and the record in
    the caller. The check's answer and the recording behavior are the
    backend's own; only the timing is made explicit.
    """

    def ceremony_replay_reason(self, evidence_id: str) -> str | None:
        reason = super().ceremony_replay_reason(evidence_id)
        if reason is None:
            time.sleep(CHECK_PAUSE_S)
        return reason


def _race(state: InMemoryKernelState) -> tuple[list[str | None], InMemoryKernelState]:
    barrier = threading.Barrier(THREADS)
    results: list[str | None] = [None] * THREADS
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        use = ApprovalUse(
            approval_id=f"approval-{i}",
            nonce=f"nonce-{i}",
            audit_payload={"approval_id": f"approval-{i}"},
            ceremony_evidence_id="evidence-shared",
        )
        try:
            barrier.wait(timeout=10)
            results[i] = state.issue_permit(
                permit=f"permit-{i}",
                intent_hash=f"intent-{i}",
                decision_reason="allow",
                timestamp_ns=1_000_000 + i,
                approval=use,
            )
        except BaseException as exc:  # surfaced by the assertions below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    if errors:
        raise AssertionError(f"worker raised: {errors[0]!r}")
    return results, state


def _assert_single_use(test: unittest.TestCase, state: InMemoryKernelState, results: list[str | None]) -> None:
    successes = sum(1 for r in results if r is None)
    denials = sum(1 for r in results if r == "ceremony_evidence_replayed")
    verified = sum(1 for e in state.audit if e.get("event") == "approval_verified")
    test.assertEqual(successes, 1, f"{successes} issuances consumed the same ceremony evidence")
    test.assertEqual(denials, THREADS - 1, f"expected {THREADS - 1} ceremony replay denials, got {denials}")
    test.assertEqual(verified, 1, f"audit holds {verified} approval_verified entries")


class InMemoryCeremonyConcurrencyTests(unittest.TestCase):
    def test_scheduler_forced_race_issues_exactly_once(self) -> None:
        results, state = _race(_PreemptibleState())
        _assert_single_use(self, state, results)

    def test_barrier_race_issues_exactly_once(self) -> None:
        for _ in range(25):
            results, state = _race(InMemoryKernelState())
            _assert_single_use(self, state, results)


if __name__ == "__main__":
    unittest.main()

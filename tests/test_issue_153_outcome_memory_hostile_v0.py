import threading
import unittest

import tests.test_issue_153_consequence_reconciliation_v0 as baseline
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_evidence import SQLiteCustodyEvidenceConvergence
from pulpo.custody_reconcile import (
    GovernedDomainOutcomeMemoryProjection,
    IndependentDomainReconciler,
)
from pulpo.kernel import GovernanceKernel
from pulpo.state import SQLiteKernelState


class Issue153OutcomeMemoryHostileV0(unittest.TestCase):
    """Hostile ordering/concurrency proof for governed consequence memory."""

    _path = baseline.Issue153ConsequenceReconciliationV0._path
    _safe_close = staticmethod(baseline.Issue153ConsequenceReconciliationV0._safe_close)
    _commerce_verifier = staticmethod(
        baseline.Issue153ConsequenceReconciliationV0._commerce_verifier
    )
    _commerce_policy = baseline.Issue153ConsequenceReconciliationV0._commerce_policy
    _activate_directive = baseline.Issue153ConsequenceReconciliationV0._activate_directive
    _stack = baseline.Issue153ConsequenceReconciliationV0._stack
    _observation = staticmethod(baseline.Issue153ConsequenceReconciliationV0._observation)

    def test_10_outcome_memory_denied_until_exact_reconciliation_evidence_is_canonical(self):
        path = self._path()
        (
            state,
            kernel,
            custody,
            budget,
            governed,
            order,
            provider_request_id,
            _,
        ) = self._stack(path)
        self.addCleanup(self._safe_close, state)

        # Install the already-canonical custody evidence convergence seam before
        # the reconciliation transition so that exact transition becomes a
        # durable pending evidence obligation.
        convergence = SQLiteCustodyEvidenceConvergence(custody)
        observation = self._observation(provider_request_id)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-evidence-order",
        ).reconcile(governed, order, observation)

        self.assertEqual(1, convergence.pending_count())
        self.assertEqual(0, convergence.canonical_event_count(result.receipt.transition_hash))

        projection = GovernedDomainOutcomeMemoryProjection(kernel, custody)
        with self.assertRaisesRegex(
            CustodyViolation,
            "outcome_memory_custody_evidence_unprojected",
        ):
            projection.record(governed, order, observation, result)

        self.assertEqual(
            0,
            len([record for record in kernel.audit if record["event"] == projection.EVENT]),
        )

        projected = convergence.project_all()
        self.assertEqual(1, len(projected))
        self.assertEqual(0, convergence.pending_count())
        self.assertEqual(1, convergence.canonical_event_count(result.receipt.transition_hash))

        memory = projection.record(governed, order, observation, result)
        self.assertEqual("SUCCESS_VERIFIED", memory.classification)
        self.assertTrue(memory.reusable)

    def test_11_concurrent_identical_recording_creates_exactly_one_canonical_memory_event(self):
        path = self._path()
        (
            state,
            _,
            custody,
            budget,
            governed,
            order,
            provider_request_id,
            _,
        ) = self._stack(path)

        convergence = SQLiteCustodyEvidenceConvergence(custody)
        observation = self._observation(provider_request_id)
        result = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:issue-153-concurrency",
        ).reconcile(governed, order, observation)
        convergence.project_all()
        self.assertEqual(1, convergence.canonical_event_count(result.receipt.transition_hash))
        state.close()

        start = threading.Barrier(2)
        preappend = threading.Barrier(2)
        memory_ids: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        class BarrierProjection(GovernedDomainOutcomeMemoryProjection):
            def __init__(self, kernel, worker_custody):
                super().__init__(kernel, worker_custody)
                self._hostile_sync_used = False

            def _memory_records(self, attempt_id):
                records = super()._memory_records(attempt_id)
                if not self._hostile_sync_used:
                    self._hostile_sync_used = True
                    preappend.wait(timeout=5)
                return records

        def worker() -> None:
            worker_state = None
            try:
                worker_state = SQLiteKernelState(path)
                verifier = self._commerce_verifier()
                worker_kernel = GovernanceKernel(
                    self._commerce_policy(verifier),
                    secret=baseline.KERNEL_SECRET,
                    approval_verifier=verifier,
                    clock=lambda: baseline.NOW,
                    state=worker_state,
                )
                worker_custody = SQLiteGovernanceCustody(
                    path,
                    signing_secret=baseline.CUSTODY_SECRET,
                    clock=lambda: baseline.NOW,
                )
                projection = BarrierProjection(worker_kernel, worker_custody)
                start.wait(timeout=5)
                memory = projection.record(governed, order, observation, result)
                with lock:
                    memory_ids.append(memory.memory_id)
            except BaseException as exc:
                with lock:
                    errors.append(exc)
            finally:
                if worker_state is not None:
                    worker_state.close()

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(2, len(memory_ids))
        self.assertEqual(1, len(set(memory_ids)))

        verifier = self._commerce_verifier()
        check_state = SQLiteKernelState(path)
        check_kernel = GovernanceKernel(
            self._commerce_policy(verifier),
            secret=baseline.KERNEL_SECRET,
            approval_verifier=verifier,
            clock=lambda: baseline.NOW,
            state=check_state,
        )
        events = [
            record
            for record in check_kernel.audit
            if record["event"] == GovernedDomainOutcomeMemoryProjection.EVENT
        ]
        self.assertEqual(1, len(events))
        check_state.close()


if __name__ == "__main__":
    unittest.main()

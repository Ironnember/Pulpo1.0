import tempfile
import threading
import unittest

from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody


H_OBJECT = "1" * 64
H_TARGET = "2" * 64
H_PERMIT = "3" * 64
H_AUTH = "4" * 64
H_OBSERVATION = "5" * 64


class SequenceClock:
    def __init__(self, *values):
        self.values = list(values)
        self._lock = threading.Lock()

    def __call__(self):
        with self._lock:
            if not self.values:
                raise RuntimeError("clock exhausted")
            return self.values.pop(0)


class ConstantClock:
    def __init__(self, value=1_000_000):
        self.value = value

    def __call__(self):
        return self.value


class CustodyProofTests(unittest.TestCase):
    def custody(self, clock=None):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        handle.close()
        custody = SQLiteGovernanceCustody(
            handle.name,
            signing_secret=b"hostile-worker-v0-custody-secret",
            clock=clock or ConstantClock(),
        )
        self.addCleanup(lambda: __import__("pathlib").Path(handle.name).unlink(missing_ok=True))
        self.addCleanup(lambda: __import__("pathlib").Path(handle.name + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: __import__("pathlib").Path(handle.name + "-shm").unlink(missing_ok=True))
        return custody

    @staticmethod
    def authorize(custody, head, *, object_hash=H_OBJECT):
        return custody.authorize_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            object_hash=object_hash,
            target_hash=H_TARGET,
            permit_hash=H_PERMIT,
            authorization_hash=H_AUTH,
        )

    def test_forked_worker_cannot_authorize_same_object_twice(self):
        custody = self.custody()
        fork_snapshot = custody.snapshot()

        first = self.authorize(custody, fork_snapshot)
        self.assertTrue(custody.verify_receipt(first.receipt))

        with self.assertRaisesRegex(CustodyViolation, "stale_governance_head"):
            self.authorize(custody, fork_snapshot)

        latest = custody.snapshot()
        with self.assertRaisesRegex(CustodyViolation, "attempt_already_authorized"):
            self.authorize(custody, latest)

        self.assertEqual(1, latest.epoch)
        self.assertEqual(first.receipt.state_root, latest.state_root)

    def test_worker_rollback_does_not_restore_execution_right(self):
        custody = self.custody()
        rolled_back_snapshot = custody.snapshot()
        authorized = self.authorize(custody, rolled_back_snapshot)

        with self.assertRaisesRegex(CustodyViolation, "stale_governance_head"):
            custody.claim_attempt(
                expected_epoch=rolled_back_snapshot.epoch,
                expected_state_root=rolled_back_snapshot.state_root,
                attempt_id=authorized.attempt_id,
                executor_id="executor:a",
            )

        current = custody.snapshot()
        claimed = custody.claim_attempt(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=authorized.attempt_id,
            executor_id="executor:a",
        )
        self.assertTrue(custody.verify_receipt(claimed))
        self.assertEqual(
            SQLiteGovernanceCustody.ATTEMPT_CLAIMED,
            custody.attempt(authorized.attempt_id).state,
        )

    def test_custody_clock_regression_fails_closed(self):
        custody = self.custody(SequenceClock(100, 90))
        initial = custody.snapshot()
        authorized = self.authorize(custody, initial)
        before_failed_claim = custody.snapshot()

        with self.assertRaisesRegex(CustodyViolation, "custody_clock_rollback"):
            custody.claim_attempt(
                expected_epoch=before_failed_claim.epoch,
                expected_state_root=before_failed_claim.state_root,
                attempt_id=authorized.attempt_id,
                executor_id="executor:a",
            )

        after = custody.snapshot()
        self.assertEqual(before_failed_claim, after)
        self.assertEqual(
            SQLiteGovernanceCustody.ATTEMPT_AUTHORIZED,
            custody.attempt(authorized.attempt_id).state,
        )

    def test_two_workers_racing_same_head_yield_one_authorization(self):
        custody = self.custody()
        shared_head = custody.snapshot()
        barrier = threading.Barrier(2)
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                successes.append(self.authorize(custody, shared_head))
            except CustodyViolation as exc:
                failures.append(str(exc))

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(1, len(successes))
        self.assertEqual(1, len(failures))
        self.assertIn(failures[0], {"stale_governance_head", "attempt_already_authorized"})
        self.assertEqual(1, custody.snapshot().epoch)

    def test_one_attempt_can_be_claimed_by_only_one_executor(self):
        custody = self.custody()
        authorized = self.authorize(custody, custody.snapshot())
        current = custody.snapshot()
        first_claim = custody.claim_attempt(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=authorized.attempt_id,
            executor_id="executor:a",
        )
        self.assertTrue(custody.verify_receipt(first_claim))

        latest = custody.snapshot()
        with self.assertRaisesRegex(CustodyViolation, "attempt_state_conflict"):
            custody.claim_attempt(
                expected_epoch=latest.epoch,
                expected_state_root=latest.state_root,
                attempt_id=authorized.attempt_id,
                executor_id="executor:b",
            )
        self.assertEqual("executor:a", custody.attempt(authorized.attempt_id).executor_id)

    def test_transmission_right_is_released_once_and_lost_response_requires_reconciliation(self):
        custody = self.custody()
        authorized = self.authorize(custody, custody.snapshot())
        current = custody.snapshot()
        custody.claim_attempt(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=authorized.attempt_id,
            executor_id="executor:a",
        )

        current = custody.snapshot()
        transmission = custody.authorize_transmission(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=authorized.attempt_id,
            provider_request_id="provider:req-1",
        )
        self.assertEqual(authorized.attempt_id, transmission.idempotency_key)
        self.assertTrue(custody.verify_receipt(transmission.receipt))
        self.assertEqual(
            SQLiteGovernanceCustody.REQUEST_TRANSMITTED,
            custody.attempt(authorized.attempt_id).state,
        )

        latest = custody.snapshot()
        with self.assertRaisesRegex(CustodyViolation, "attempt_state_conflict"):
            custody.authorize_transmission(
                expected_epoch=latest.epoch,
                expected_state_root=latest.state_root,
                attempt_id=authorized.attempt_id,
            )

        reconciliation = custody.require_reconciliation(
            expected_epoch=latest.epoch,
            expected_state_root=latest.state_root,
            attempt_id=authorized.attempt_id,
        )
        self.assertTrue(custody.verify_receipt(reconciliation))
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            custody.attempt(authorized.attempt_id).state,
        )

        latest = custody.snapshot()
        unresolved = custody.reconcile_observed(
            expected_epoch=latest.epoch,
            expected_state_root=latest.state_root,
            attempt_id=authorized.attempt_id,
            outcome="unresolved",
            observation_hash=H_OBSERVATION,
            observer_id="observer:registrar-query",
        )
        self.assertTrue(custody.verify_receipt(unresolved))
        self.assertEqual(
            SQLiteGovernanceCustody.UNRESOLVED,
            custody.attempt(authorized.attempt_id).state,
        )

        latest = custody.snapshot()
        with self.assertRaisesRegex(CustodyViolation, "attempt_already_authorized"):
            self.authorize(custody, latest)

    def test_worker_cannot_claim_reconciled_success_without_observer_evidence(self):
        custody = self.custody()
        authorized = self.authorize(custody, custody.snapshot())
        current = custody.snapshot()
        custody.claim_attempt(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=authorized.attempt_id,
            executor_id="executor:a",
        )
        current = custody.snapshot()
        custody.authorize_transmission(
            expected_epoch=current.epoch,
            expected_state_root=current.state_root,
            attempt_id=authorized.attempt_id,
        )
        current = custody.snapshot()

        with self.assertRaisesRegex(CustodyViolation, "observation_hash_invalid"):
            custody.reconcile_observed(
                expected_epoch=current.epoch,
                expected_state_root=current.state_root,
                attempt_id=authorized.attempt_id,
                outcome="success",
                observation_hash="fake",
                observer_id="worker:self-report",
            )

        after = custody.snapshot()
        self.assertEqual(current, after)
        self.assertEqual(
            SQLiteGovernanceCustody.REQUEST_TRANSMITTED,
            custody.attempt(authorized.attempt_id).state,
        )


if __name__ == "__main__":
    unittest.main()

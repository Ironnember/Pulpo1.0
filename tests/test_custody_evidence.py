import sqlite3
import tempfile
import unittest
from pathlib import Path

from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_evidence import CustodyEvidenceViolation, SQLiteCustodyEvidenceConvergence
from pulpo.state import SQLiteKernelState


NOW = 81_000_000


class CustodyEvidenceConvergenceTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))
        state = SQLiteKernelState(self.path)
        state.close()
        self.custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-evidence-secret",
            clock=lambda: NOW,
        )
        self.evidence = SQLiteCustodyEvidenceConvergence(self.custody)

    def authorize(self):
        head = self.custody.snapshot()
        return self.custody.authorize_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            object_hash="1" * 64,
            target_hash="2" * 64,
            permit_hash="3" * 64,
            authorization_hash="4" * 64,
        )

    def test_abort_before_custody_commit_creates_neither_mutation_nor_obligation(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TRIGGER test_abort_before_custody_head
                BEFORE UPDATE OF epoch ON custody_head
                BEGIN
                    SELECT RAISE(ABORT, 'test_crash_before_commit');
                END
                """
            )
        with self.assertRaises(CustodyViolation):
            self.authorize()
        self.assertEqual(0, self.custody.snapshot().epoch)
        self.assertEqual(0, self.evidence.pending_count())
        self.assertIsNone(self.custody.attempt(self.custody._attempt_id("1" * 64, "2" * 64, "3" * 64, "4" * 64)))

    def test_committed_obligation_blocks_next_transition_until_projection(self):
        authorization = self.authorize()
        self.assertEqual(1, self.custody.snapshot().epoch)
        self.assertEqual(1, self.evidence.pending_count())

        head = self.custody.snapshot()
        with self.assertRaises(CustodyViolation):
            self.custody.claim_attempt(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                attempt_id=authorization.attempt_id,
                executor_id="executor:test",
            )
        self.assertEqual(1, self.custody.snapshot().epoch)
        self.assertEqual(1, self.evidence.pending_count())

        projected = self.evidence.project_all()
        self.assertEqual(1, len(projected))
        self.assertEqual(0, self.evidence.pending_count())

        head = self.custody.snapshot()
        self.custody.claim_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=authorization.attempt_id,
            executor_id="executor:test",
        )
        self.assertEqual(2, self.custody.snapshot().epoch)
        self.assertEqual(1, self.evidence.pending_count())

    def test_crash_during_projection_restarts_without_duplicate_canonical_event(self):
        authorization = self.authorize()
        transition_hash = authorization.receipt.transition_hash

        def crash(point):
            if point == "after_audit_insert":
                raise RuntimeError("simulated projection crash")

        faulty = SQLiteCustodyEvidenceConvergence(self.custody, fault_hook=crash)
        with self.assertRaises(CustodyEvidenceViolation):
            faulty.project_one()
        self.assertEqual(1, self.evidence.pending_count())
        self.assertEqual(0, self.evidence.canonical_event_count(transition_hash))

        restarted = SQLiteCustodyEvidenceConvergence(self.custody)
        restarted.project_all()
        self.assertEqual(0, restarted.pending_count())
        self.assertEqual(1, restarted.canonical_event_count(transition_hash))

    def test_duplicate_projection_is_idempotent_by_transition_hash(self):
        authorization = self.authorize()
        transition_hash = authorization.receipt.transition_hash
        first = self.evidence.project_one()
        second = self.evidence.project_one()
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(1, self.evidence.canonical_event_count(transition_hash))

    def test_tampered_obligation_is_denied_and_blocks_custody(self):
        authorization = self.authorize()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                UPDATE custody_evidence_outbox
                SET state_root = ?
                WHERE transition_hash = ?
                """,
                ("0" * 64, authorization.receipt.transition_hash),
            )
        with self.assertRaises(CustodyEvidenceViolation):
            self.evidence.project_one()
        self.assertEqual(1, self.evidence.pending_count())

        head = self.custody.snapshot()
        with self.assertRaises(CustodyViolation):
            self.custody.claim_attempt(
                expected_epoch=head.epoch,
                expected_state_root=head.state_root,
                attempt_id=authorization.attempt_id,
                executor_id="executor:test",
            )
        self.assertEqual(1, self.custody.snapshot().epoch)


if __name__ == "__main__":
    unittest.main()

import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from pulpo import GovernanceKernel, Policy, SQLiteKernelState


class UniqueAuditScanTests(unittest.TestCase):
    options = {}

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state.sqlite3"
        self.state = SQLiteKernelState(self.path, **self.options)
        self.addCleanup(self.state.close)

    def proof(self, state=None):
        self.assertTrue(GovernanceKernel(Policy(frozenset(), 0), state=state or self.state,
                                        secret=b"test-only").verify_audit())

    def test_replay_scans_later_rows_and_never_writes(self):
        for i in range(20):
            self.state.append("reconciled", {"id": i, "result": i}, i)
        statements = []
        self.state._connection.set_trace_callback(statements.append)
        before = self.state.audit
        changes = self.state._connection.total_changes
        self.assertEqual({"id": 0, "result": 0}, self.state.append_unique(
            "reconciled", "id", 0, {"id": 0, "result": "replacement"}, 30))
        self.assertEqual(changes, self.state._connection.total_changes)
        self.assertEqual(before, self.state.audit)
        self.assertFalse(any(sql.startswith(("INSERT", "UPDATE", "DELETE")) for sql in statements))
        self.proof()

    def test_duplicate_at_end_is_ambiguous_without_mutation(self):
        self.state.append("reconciled", {"id": 0}, 0)
        for i in range(1, 20):
            self.state.append("reconciled", {"id": i}, i)
        self.state.append("reconciled", {"id": 0, "conflict": True}, 20)
        changes = self.state._connection.total_changes
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.state.append_unique("reconciled", "id", 0, {"id": 0}, 30)
        self.assertEqual(changes, self.state._connection.total_changes)
        self.assertFalse(self.state._connection.in_transaction)
        self.proof()

    def test_malformed_later_row_is_not_hidden_by_match(self):
        self.state.append("reconciled", {"id": 0}, 0)
        self.state.append("reconciled", {"id": 1}, 1)
        with self.state._connection:
            self.state._connection.execute("UPDATE audit SET payload_json = '{bad' WHERE sequence = 2")
        changes = self.state._connection.total_changes
        with self.assertRaises(json.JSONDecodeError):
            self.state.append_unique("reconciled", "id", 0, {"id": 0}, 30)
        self.assertEqual(changes, self.state._connection.total_changes)
        self.assertFalse(self.state._connection.in_transaction)

    def test_malformed_nonfinal_row_releases_cursor_with_retained_traceback(self):
        for i in range(3):
            self.state.append("reconciled", {"id": i}, i)
        with self.state._connection:
            self.state._connection.execute("UPDATE audit SET payload_json = '{bad' WHERE sequence = 2")
        before = self.state._connection.execute("SELECT * FROM audit ORDER BY sequence").fetchall()
        changes = self.state._connection.total_changes
        statements = []
        self.state._connection.set_trace_callback(statements.append)
        self.addCleanup(self.state._connection.set_trace_callback, None)

        # assertRaises clears the traceback; retain the actual exception so the
        # failed append_unique frame and its nonexhausted cursor stay alive.
        retained = None
        try:
            self.state.append_unique("reconciled", "id", 0, {"id": 0}, 30)
        except json.JSONDecodeError as exc:
            retained = exc
        else:
            self.fail("malformed nonfinal JSON must reject an earlier match")
        self.addCleanup(retained.with_traceback, None)
        self.assertIsNotNone(retained.__traceback__)
        self.assertFalse(self.state._connection.in_transaction)
        self.assertIn("ROLLBACK", statements)
        self.assertEqual(changes, self.state._connection.total_changes)
        self.assertEqual(before, self.state._connection.execute(
            "SELECT * FROM audit ORDER BY sequence").fetchall())

        with closing(sqlite3.connect(self.path, timeout=0.1)) as writer:
            with writer:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("INSERT INTO permits (permit, intent_hash) VALUES (?, ?)",
                               ("cursor-release-probe", "test-only"))
                writer.commit()
            self.assertFalse(writer.in_transaction)
        self.assertEqual(("test-only",), self.state._connection.execute(
            "SELECT intent_hash FROM permits WHERE permit = ?",
            ("cursor-release-probe",)).fetchone())
        self.assertIsNotNone(retained.__traceback__)

    def test_new_identity_is_durable_and_other_events_do_not_conflict(self):
        self.state.append("other", {"id": 0}, 0)
        self.assertIsNone(self.state.append_unique("reconciled", "id", 0, {"id": 0}, 1))
        restarted = SQLiteKernelState(self.path, **self.options)
        self.addCleanup(restarted.close)
        self.assertEqual({"id": 0}, restarted.append_unique("reconciled", "id", 0, {"id": 0}, 2))
        self.assertEqual(["other", "reconciled"], [r["event"] for r in restarted.audit])
        self.proof(restarted)

    def test_failed_insert_rolls_back_and_retry_succeeds(self):
        with self.state._connection:
            self.state._connection.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON audit "
                "BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "forced audit failure"):
            self.state.append_unique("reconciled", "id", 0, {"id": 0}, 1)
        self.assertEqual([], self.state.audit)
        self.assertFalse(self.state._connection.in_transaction)
        with self.state._connection:
            self.state._connection.execute("DROP TRIGGER reject_audit")
        self.assertIsNone(self.state.append_unique("reconciled", "id", 0, {"id": 0}, 1))
        self.proof()

    def test_failed_commit_rolls_back_new_identity(self):
        self.state._connection.execute("PRAGMA busy_timeout = 10")
        with closing(sqlite3.connect(self.path)) as reader:
            try:
                reader.execute("BEGIN")
                reader.execute("SELECT COUNT(*) FROM audit").fetchone()
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    self.state.append_unique("reconciled", "id", 0, {"id": 0}, 1)
                self.assertFalse(self.state._connection.in_transaction)
            finally:
                reader.rollback()
        self.assertEqual([], self.state.audit)
        self.assertIsNone(self.state.append_unique("reconciled", "id", 0, {"id": 0}, 1))
        self.proof()

    def test_concurrent_same_identity_appends_exactly_once(self):
        barrier = threading.Barrier(2)
        results, errors = [], []

        def worker():
            state = SQLiteKernelState(self.path, **self.options)
            try:
                barrier.wait(timeout=5)
                results.append(state.append_unique("reconciled", "id", 0, {"id": 0}, 1))
            except Exception as exc:
                errors.append(exc)
            finally:
                state.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(1, results.count(None))
        self.assertEqual(1, results.count({"id": 0}))
        self.assertEqual(1, len(self.state.audit))
        self.proof()

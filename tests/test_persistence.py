import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from contextlib import closing

import pulpo.state as state_module

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    SQLiteKernelState,
    StateIntegrityError,
)
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000


class RestartSafeStateTests(unittest.TestCase):
    state_options = {}

    def make_state(self):
        return SQLiteKernelState(self.path, **self.state_options)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "kernel.sqlite3"
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.verifier),
        )
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, "session-1")

    def kernel(self, state):
        return GovernanceKernel(
            self.policy,
            secret=b"permit-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=state,
        )

    def test_approval_and_permit_replay_remain_denied_after_restart(self):
        first_state = self.make_state()
        first_kernel = self.kernel(first_state)
        envelope = signed_envelope(first_kernel, self.intent, self.verifier, now_ns=NOW)
        decision = first_kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual("allow", decision.outcome)
        first_length = len(first_kernel.audit)
        first_state.close()

        restarted_state = self.make_state()
        self.addCleanup(restarted_state.close)
        restarted_kernel = self.kernel(restarted_state)
        self.assertTrue(restarted_kernel.verify_audit())
        self.assertEqual(
            "approval_id_replayed",
            restarted_kernel.evaluate_with_approval(self.intent, envelope).reason,
        )
        same_nonce = signed_envelope(
            restarted_kernel,
            self.intent,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-2",
            nonce=envelope.nonce,
        )
        self.assertEqual(
            "approval_nonce_replayed",
            restarted_kernel.evaluate_with_approval(self.intent, same_nonce).reason,
        )
        self.assertFalse(
            restarted_kernel.consume(
                decision.permit,
                replace(self.intent, resource="repo:other"),
            )
        )
        self.assertTrue(restarted_kernel.consume(decision.permit, self.intent))
        self.assertGreater(len(restarted_kernel.audit), first_length)
        self.assertTrue(restarted_kernel.verify_audit())
        restarted_state.close()

        final_state = self.make_state()
        self.addCleanup(final_state.close)
        final_kernel = self.kernel(final_state)
        self.assertFalse(final_kernel.consume(decision.permit, self.intent))
        self.assertTrue(final_kernel.verify_audit())

    def test_concurrent_identical_approval_allows_exactly_once(self):
        signing_state = self.make_state()
        signing_kernel = self.kernel(signing_state)
        envelope = signed_envelope(signing_kernel, self.intent, self.verifier, now_ns=NOW)
        signing_state.close()

        barrier = threading.Barrier(2)
        results = []
        errors = []

        def evaluate():
            state = self.make_state()
            try:
                kernel = self.kernel(state)
                barrier.wait()
                results.append(kernel.evaluate_with_approval(self.intent, envelope))
            except Exception as exc:
                errors.append(exc)
            finally:
                state.close()

        threads = [threading.Thread(target=evaluate) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual([], errors)
        self.assertEqual(["allow", "deny"], sorted((result.outcome for result in results)))
        self.assertEqual(
            ["approval_id_replayed"],
            [result.reason for result in results if result.outcome == "deny"],
        )

    def test_replay_reason_uses_one_snapshot_with_id_precedence(self):
        state = self.make_state()
        self.addCleanup(state.close)
        state._connection.executemany(
            "INSERT INTO approvals (approval_id, nonce) VALUES (?, ?)",
            [
                ("approval-id-match", "other-nonce"),
                ("other-approval", "nonce-match"),
            ],
        )

        statements = []
        state._connection.set_trace_callback(statements.append)
        self.assertEqual(
            "approval_nonce_replayed",
            state.approval_replay_reason("new-approval", "nonce-match"),
        )
        replay_reads = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and "approvals" in statement
        ]
        self.assertEqual(1, len(replay_reads))

        statements.clear()
        self.assertEqual(
            "approval_id_replayed",
            state.approval_replay_reason("approval-id-match", "nonce-match"),
        )
        replay_reads = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and "approvals" in statement
        ]
        self.assertEqual(1, len(replay_reads))

    def test_verified_approval_and_permit_are_committed_with_one_transaction(self):
        state = self.make_state()
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(self.intent, envelope)

        connection = sqlite3.connect(self.path)
        self.addCleanup(connection.close)
        self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
        self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
        self.assertEqual(
            ["approval_verified", "decision"],
            [row[0] for row in connection.execute("SELECT event FROM audit ORDER BY sequence")],
        )
        self.assertTrue(kernel.consume(decision.permit, self.intent))

    def test_failed_audit_write_rolls_back_approval_and_permit(self):
        state = self.make_state()
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER reject_verified_audit
                BEFORE INSERT ON audit
                WHEN NEW.event = 'approval_verified'
                BEGIN
                    SELECT RAISE(ABORT, 'forced audit failure');
                END
                """
            )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "forced audit failure"):
            kernel.evaluate_with_approval(self.intent, envelope)

        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0])

    def test_failed_consumption_audit_rolls_back_spent_permit(self):
        state = self.make_state()
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        decision = kernel.evaluate_with_approval(
            self.intent,
            signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW),
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER reject_consumed_audit
                BEFORE INSERT ON audit
                WHEN NEW.event = 'permit_consumed'
                BEGIN
                    SELECT RAISE(ABORT, 'forced consumption audit failure');
                END
                """
            )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "forced consumption audit failure"):
            kernel.consume(decision.permit, self.intent)

        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(0, connection.execute("SELECT spent FROM permits").fetchone()[0])
            connection.execute("DROP TRIGGER reject_consumed_audit")
        self.assertTrue(kernel.consume(decision.permit, self.intent))
        self.assertTrue(kernel.verify_audit())

    def test_overlapping_connections_serialize_audit_tip_selection(self):
        first_record_started = threading.Event()
        release_first_record = threading.Event()
        second_record_started = threading.Event()
        record_count = 0
        record_count_lock = threading.Lock()
        original_audit_record = state_module._audit_record

        def observed_audit_record(previous_hash, event, payload, timestamp_ns):
            nonlocal record_count
            with record_count_lock:
                record_count += 1
                current_record = record_count
            if current_record == 1:
                first_record_started.set()
                self.assertTrue(release_first_record.wait(2))
            elif current_record == 2:
                second_record_started.set()
            return original_audit_record(previous_hash, event, payload, timestamp_ns)

        errors = []

        def append_from_connection(event):
            state = self.make_state()
            try:
                state.append(event, {"source": event}, NOW)
            except Exception as exc:
                errors.append(exc)
            finally:
                state.close()

        with patch.object(state_module, "_audit_record", observed_audit_record):
            first = threading.Thread(target=append_from_connection, args=("first",))
            second = threading.Thread(target=append_from_connection, args=("second",))
            first.start()
            self.assertTrue(first_record_started.wait(2))
            second.start()
            self.assertFalse(second_record_started.wait(0.1))
            release_first_record.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual([], errors)
        state = self.make_state()
        self.addCleanup(state.close)
        self.assertEqual(["first", "second"], [record["event"] for record in state.audit])
        self.assertTrue(self.kernel(state).verify_audit())

    def test_tampered_persisted_audit_fails_closed_at_restart(self):
        state = self.make_state()
        kernel = self.kernel(state)
        kernel.evaluate_with_approval(
            self.intent,
            signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW),
        )
        state.close()

        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE audit SET payload_json = ? WHERE sequence = 1", ('{"changed":true}',))

        tampered_state = self.make_state()
        self.addCleanup(tampered_state.close)
        with self.assertRaisesRegex(StateIntegrityError, "audit chain"):
            self.kernel(tampered_state)

    def test_malformed_persisted_audit_raises_integrity_error_at_restart(self):
        state = self.make_state()
        kernel = self.kernel(state)
        kernel.evaluate_with_approval(
            self.intent,
            signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW),
        )
        state.close()

        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE audit SET payload_json = ? WHERE sequence = 1", ("{not-json",))

        malformed_state = self.make_state()
        self.addCleanup(malformed_state.close)
        with self.assertRaisesRegex(StateIntegrityError, "audit chain"):
            self.kernel(malformed_state)


    def test_failed_second_audit_insert_rolls_back_entire_issuance(self):
        state = self.make_state()
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.executescript("""
                CREATE TRIGGER reject_decision BEFORE INSERT ON audit
                WHEN NEW.event = 'decision'
                BEGIN SELECT RAISE(ABORT, 'second audit failure'); END;
            """)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "second audit failure"):
            kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual([], state.audit)
        for table in ("approvals", "permits"):
            self.assertEqual(0, state._connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER reject_decision")
        self.assertEqual("allow", kernel.evaluate_with_approval(self.intent, envelope).outcome)
        self.assertTrue(kernel.verify_audit())

    def test_failed_commit_rolls_back_approval_permit_and_audit(self):
        state = self.make_state()
        self.addCleanup(state.close)
        state._connection.execute("PRAGMA busy_timeout = 10")
        kernel = self.kernel(state)
        envelope = signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        with closing(sqlite3.connect(self.path)) as reader:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM audit").fetchone()
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                kernel.evaluate_with_approval(self.intent, envelope)
            self.assertFalse(state._connection.in_transaction)
            reader.rollback()
        self.assertEqual([], state.audit)
        self.assertIsNone(state.approval_replay_reason(envelope.approval_id, envelope.nonce))
        self.assertEqual(0, state._connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
        self.assertEqual("allow", kernel.evaluate_with_approval(self.intent, envelope).outcome)
        self.assertTrue(kernel.verify_audit())

    def test_concurrent_consumption_succeeds_once(self):
        state = self.make_state()
        kernel = self.kernel(state)
        permit = kernel.evaluate_with_approval(
            self.intent, signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        ).permit
        state.close()
        barrier = threading.Barrier(2)
        results, errors = [], []
        def consume():
            worker = self.make_state()
            try:
                kernel = self.kernel(worker)
                barrier.wait(timeout=2)
                results.append(kernel.consume(permit, self.intent))
            except Exception as exc:
                errors.append(exc)
            finally:
                worker.close()
        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        self.assertEqual([False, True], sorted(results))
        reopened = self.make_state()
        self.addCleanup(reopened.close)
        self.assertTrue(self.kernel(reopened).verify_audit())
        self.assertEqual(["permit_consumed", "permit_rejected"],
                         [record["event"] for record in reopened.audit[-2:]])

    def test_existing_database_gets_index_without_changing_audit(self):
        state = SQLiteKernelState(self.path, index_audit_events=True)
        state.append("target", {"id": 1}, NOW)
        state.append("other", {"id": 1}, NOW)
        original = state.audit
        state._connection.execute("DROP INDEX audit_event_sequence")
        state.close()
        reopened = SQLiteKernelState(self.path, index_audit_events=True)
        self.addCleanup(reopened.close)
        self.assertEqual(original, reopened.audit)
        plan = reopened._connection.execute(
            "EXPLAIN QUERY PLAN SELECT payload_json FROM audit WHERE event = ? ORDER BY sequence",
            ("target",),
        ).fetchall()
        self.assertTrue(any("audit_event_sequence" in row[3] for row in plan), plan)
        self.assertEqual({"id": 1}, reopened.append_unique("target", "id", 1, {"id": 1}, NOW))
        self.assertEqual(original, reopened.audit)
        self.assertTrue(self.kernel(reopened).verify_audit())

    def test_issuance_reads_tip_once_and_preserves_event_order(self):
        state = self.make_state()
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        statements = []
        state._connection.set_trace_callback(statements.append)
        kernel.evaluate_with_approval(
            self.intent, signed_envelope(kernel, self.intent, self.verifier, now_ns=NOW)
        )
        self.assertEqual(1, sum("SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1" in sql
                                for sql in statements))
        self.assertEqual(["approval_verified", "decision"], [row["event"] for row in state.audit])
        self.assertTrue(kernel.verify_audit())


class IndexedRestartSafeStateTests(RestartSafeStateTests):
    state_options = {"index_audit_events": True}


if __name__ == "__main__":
    unittest.main()

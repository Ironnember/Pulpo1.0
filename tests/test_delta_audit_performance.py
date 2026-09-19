import sqlite3
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState, StateIntegrityError


NOW = 1_000_000


class DeltaAuditPerformanceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "kernel.sqlite3"
        self.policy = Policy(frozenset({"read"}), 100)

    def kernel(self, state):
        return GovernanceKernel(
            self.policy,
            secret=b"delta-test-secret",
            clock=lambda: NOW,
            state=state,
        )

    def test_delta_root_chain_is_bound_into_canonical_audit(self):
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        first = kernel.evaluate(Intent("agent", "read", "repo:a"))
        self.assertEqual("allow", first.outcome)
        self.assertTrue(kernel.consume(first.permit, Intent("agent", "read", "repo:a")))

        records = kernel.audit
        self.assertGreaterEqual(len(records), 2)
        prior_root = "0" * 64
        for record in records:
            self.assertEqual(prior_root, record["previous_state_root"])
            self.assertIn("delta", record)
            self.assertEqual(record["event"], record["delta"]["event"])
            prior_root = record["state_root"]
        self.assertTrue(kernel.verify_audit())

    def test_delta_tamper_fails_closed_at_restart(self):
        state = SQLiteKernelState(self.path)
        kernel = self.kernel(state)
        kernel.evaluate(Intent("agent", "read", "repo:a"))
        state.close()

        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "UPDATE audit SET delta_json = ? WHERE sequence = 1",
                ('{"event":"decision","payload_hash":"tampered"}',),
            )

        tampered = SQLiteKernelState(self.path)
        self.addCleanup(tampered.close)
        with self.assertRaisesRegex(StateIntegrityError, "audit chain"):
            self.kernel(tampered)

    def test_append_unique_uses_index_after_projection_is_established(self):
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        payload = {
            "transition_hash": "abc123",
            "authority_effect": "none",
        }
        self.assertIsNone(
            state.append_unique(
                "custody_transition",
                "transition_hash",
                "abc123",
                payload,
                NOW,
            )
        )

        statements = []
        state._connection.set_trace_callback(statements.append)
        existing = state.append_unique(
            "custody_transition",
            "transition_hash",
            "abc123",
            payload,
            NOW + 1,
        )
        self.assertEqual(payload, existing)
        scans = [
            statement for statement in statements
            if "SELECT sequence, payload_json FROM audit WHERE event" in statement
        ]
        indexed = [
            statement for statement in statements
            if "FROM audit_unique u" in statement
        ]
        self.assertEqual([], scans)
        self.assertEqual(1, len(indexed))

    def test_required_indexes_exist(self):
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        indexes = {
            row[1]
            for row in state._connection.execute("PRAGMA index_list(directives)").fetchall()
        }
        self.assertIn("idx_directives_hash", indexes)

        audit_indexes = {
            row[1]
            for row in state._connection.execute("PRAGMA index_list(audit)").fetchall()
        }
        self.assertIn("idx_audit_event", audit_indexes)

    def test_legacy_audit_schema_migrates_and_binds_new_delta(self):
        legacy_path = Path(self.directory.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy_path) as connection:
            connection.executescript(
                """
                CREATE TABLE permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE approvals (approval_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE);
                CREATE TABLE directives (
                    directive_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    directive_hash TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (directive_id, version)
                );
                CREATE TABLE permit_directives (
                    permit TEXT PRIMARY KEY,
                    directive_id TEXT NOT NULL,
                    directive_version INTEGER NOT NULL,
                    directive_hash TEXT NOT NULL,
                    directive_issued_at_ns INTEGER NOT NULL,
                    directive_expires_at_ns INTEGER NOT NULL
                );
                CREATE TABLE audit (
                    sequence INTEGER PRIMARY KEY,
                    event TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    hash TEXT NOT NULL
                );
                """
            )

        state = SQLiteKernelState(legacy_path)
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        kernel.evaluate(Intent("agent", "read", "repo:legacy"))
        record = kernel.audit[-1]
        self.assertIn("delta", record)
        self.assertIn("state_root", record)
        self.assertTrue(kernel.verify_audit())

    def test_policy_hash_is_stable_cached_material(self):
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        first = kernel.policy_hash
        second = kernel.policy_hash
        self.assertIs(first, second)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

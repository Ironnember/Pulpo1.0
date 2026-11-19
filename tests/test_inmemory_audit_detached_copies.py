"""Audit reads on the in-memory backend must be detached copies.

Finding (PR #350 reproduction, 2026-11-12): ``InMemoryKernelState.audit``
returned the backend's live list — ``state.audit is kernel.audit`` was the
same object — so any holder of the kernel could delete records from the
stored trail, append forged records, or rewrite a record's payload in
place through the read path alone. The SQLite backend already rebuilds
fresh records from rows on every read. These tests pin the in-memory
backend (and the kernel property above it) to the same detached behavior,
including the one sibling return of stored audit content,
``append_unique``'s existing-payload return.

Boundary: detached reads close the read-path mutation surface only. They
do not address a privileged writer with direct access to the store, who
can still truncate the tail or delete-and-rehash because the chain is
unkeyed; that exposure requires an external anchored head and remains
open (documented on PR #350).
"""

import copy
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Policy
from pulpo.state import InMemoryKernelState, SQLiteKernelState


def _populated_state() -> InMemoryKernelState:
    state = InMemoryKernelState()
    state.append(
        "decision",
        {"outcome": "deny", "intent_hash": "a" * 64, "detail": {"step": 1, "tags": ["first"]}},
        1_000,
    )
    state.append(
        "permit_rejected",
        {"intent_hash": "b" * 64, "detail": {"step": 2, "tags": ["second"]}},
        2_000,
    )
    state.append(
        "permit_consumed",
        {"intent_hash": "c" * 64, "detail": {"step": 3, "tags": ["third"]}},
        3_000,
    )
    return state


class InMemoryAuditDetachedCopiesTests(unittest.TestCase):
    def setUp(self):
        self.state = _populated_state()
        self.snapshot = copy.deepcopy(self.state.audit)

    def test_delete_from_returned_list_leaves_store_untouched(self):
        returned = self.state.audit
        del returned[0]
        del returned[-1]
        self.assertEqual(self.state.audit, self.snapshot)

    def test_append_to_returned_list_leaves_store_untouched(self):
        returned = self.state.audit
        returned.append(
            {
                "event": "permit_consumed",
                "payload": {"intent_hash": "f" * 64},
                "previous_hash": self.snapshot[-1]["hash"],
                "timestamp_ns": 4_000,
                "hash": "f" * 64,
            }
        )
        self.assertEqual(self.state.audit, self.snapshot)

    def test_editing_returned_record_leaves_store_untouched(self):
        returned = self.state.audit
        returned[1]["payload"]["intent_hash"] = "c" * 64
        returned[1]["event"] = "permit_consumed"
        returned[1]["hash"] = "0" * 64
        self.assertEqual(self.state.audit, self.snapshot)

    def test_editing_nested_payload_leaves_store_untouched(self):
        returned = self.state.audit
        returned[0]["payload"]["detail"]["step"] = 99
        returned[0]["payload"]["detail"]["tags"].append("forged")
        self.assertEqual(self.state.audit, self.snapshot)

    def test_successive_reads_are_equal_but_detached(self):
        first = self.state.audit
        second = self.state.audit
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first[0], second[0])
        self.assertIsNot(first[0]["payload"], second[0]["payload"])
        self.assertIsNot(first[0]["payload"]["detail"], second[0]["payload"]["detail"])

    def test_legitimate_reads_return_complete_correct_records(self):
        records = self.state.audit
        self.assertEqual(len(records), 3)
        self.assertEqual(
            [record["event"] for record in records],
            ["decision", "permit_rejected", "permit_consumed"],
        )
        self.assertEqual(records[0]["previous_hash"], "0" * 64)
        for previous, record in zip(records, records[1:]):
            self.assertEqual(record["previous_hash"], previous["hash"])
        self.assertEqual(records, self.snapshot)

    def test_append_unique_returns_detached_payload(self):
        payload = {"receipt_id": "r-1", "detail": {"step": 1}}
        expected = copy.deepcopy(payload)
        self.assertIsNone(self.state.append_unique("receipt_recorded", "receipt_id", "r-1", payload, 4_000))
        existing = self.state.append_unique("receipt_recorded", "receipt_id", "r-1", payload, 5_000)
        self.assertEqual(existing, expected)
        existing["detail"]["step"] = 99
        existing["receipt_id"] = "forged"
        stored = [r for r in self.state.audit if r["event"] == "receipt_recorded"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["payload"], expected)


class KernelAuditDetachedCopiesTests(unittest.TestCase):
    def test_kernel_audit_mutation_leaves_trail_and_verification_untouched(self):
        state = _populated_state()
        kernel = GovernanceKernel(Policy(frozenset({"read"}), 100, frozenset()), state=state)
        snapshot = copy.deepcopy(kernel.audit)
        self.assertTrue(kernel.verify_audit())

        returned = kernel.audit
        del returned[0]
        returned[0]["payload"]["intent_hash"] = "0" * 64
        returned.append({"event": "forged", "payload": {}, "previous_hash": "0" * 64, "timestamp_ns": 9_999, "hash": "0" * 64})

        self.assertEqual(kernel.audit, snapshot)
        self.assertTrue(kernel.verify_audit())


class SQLiteAuditDetachmentParityTests(unittest.TestCase):
    def test_sqlite_backend_audit_reads_are_detached(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteKernelState(Path(tmp) / "kernel.sqlite3")
            try:
                state.append("decision", {"intent_hash": "a" * 64, "detail": {"step": 1}}, 1_000)
                state.append("permit_consumed", {"intent_hash": "b" * 64, "detail": {"step": 2}}, 2_000)
                snapshot = copy.deepcopy(state.audit)
                returned = state.audit
                del returned[0]
                returned[0]["payload"]["detail"]["step"] = 99
                self.assertEqual(state.audit, snapshot)
            finally:
                state.close()


if __name__ == "__main__":
    unittest.main()

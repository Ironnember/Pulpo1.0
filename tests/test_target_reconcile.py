import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pulpo.target_reconcile as target_reconcile_module
from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState
from pulpo.target_reconcile import GovernedTargetReconciliation


class TargetReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000_000_000_000
        self.kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"target-reconciliation-secret",
            clock=lambda: self.now,
        )
        self.intent = Intent("agent:builder", "write", "artifact:pitch-deck", 0, "deck-session")
        self.target = self.kernel.lock_target("deck-v1", self.intent)
        self.reconcile = GovernedTargetReconciliation(self.kernel)

    def test_locked_target_remains_unresolved_without_completion_evidence(self):
        status = self.reconcile.status("deck-v1", self.target.target_hash)
        self.assertEqual(("unresolved", "completion_evidence_missing"), (status.state, status.reason))
        self.assertIsNone(status.completion)

    def test_memory_or_chat_claim_does_not_complete_target(self):
        self.kernel._state.append(
            "memory_summary",
            {
                "target_id": "deck-v1",
                "claim": "completed",
                "retrieval_score": 1.0,
                "authority_effect": "none",
            },
            self.now,
        )
        status = self.reconcile.status("deck-v1", self.target.target_hash)
        self.assertEqual("unresolved", status.state)
        self.assertEqual("completion_evidence_missing", status.reason)

    def test_missing_or_empty_artifact_cannot_complete_target(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.pptx"
            with self.assertRaisesRegex(ValueError, "artifact_not_found"):
                self.reconcile.complete_file("deck-v1", self.target.target_hash, missing)

            empty = Path(directory) / "empty.pptx"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "artifact_empty"):
                self.reconcile.complete_file("deck-v1", self.target.target_hash, empty)

        self.assertEqual("unresolved", self.reconcile.status("deck-v1", self.target.target_hash).state)

    def test_completion_requires_exact_target_hash(self):
        with tempfile.NamedTemporaryFile(suffix=".pptx") as handle:
            handle.write(b"deck artifact bytes")
            handle.flush()
            with self.assertRaisesRegex(ValueError, "target_hash_mismatch"):
                self.reconcile.complete_file("deck-v1", "0" * 64, handle.name)
        self.assertEqual("unresolved", self.reconcile.status("deck-v1", self.target.target_hash).state)

    def test_nonempty_artifact_records_exact_completion_without_authority_effect(self):
        with tempfile.NamedTemporaryFile(suffix=".pptx") as handle:
            handle.write(b"verified deck artifact")
            handle.flush()
            completion = self.reconcile.complete_file("deck-v1", self.target.target_hash, handle.name)

        status = self.reconcile.status("deck-v1", self.target.target_hash)
        self.assertEqual("completed", status.state)
        self.assertEqual(completion, status.completion)
        self.assertEqual(self.target.target_hash, completion.target_hash)
        self.assertEqual(self.kernel.intent_hash(self.intent), completion.intent_hash)
        self.assertGreater(completion.size_bytes, 0)
        self.assertEqual(64, len(completion.artifact_sha256))

        record = [item for item in self.kernel.audit if item["event"] == "target_completed"][-1]
        self.assertEqual("none", record["payload"]["authority_effect"])
        self.assertNotIn("permit", record["payload"])
        self.assertTrue(self.kernel.verify_audit())

    def test_artifact_mutation_during_observation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deck.pptx"
            path.write_bytes(b"stable artifact")
            original_read = target_reconcile_module.os.read
            mutated = False

            def racing_read(descriptor, count):
                nonlocal mutated
                if not mutated:
                    mutated = True
                    path.write_bytes(b"artifact changed while evidence was being observed")
                return original_read(descriptor, count)

            with mock.patch.object(target_reconcile_module.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(ValueError, "artifact_changed_during_observation"):
                    self.reconcile.complete_file("deck-v1", self.target.target_hash, path)

        self.assertEqual("unresolved", self.reconcile.status("deck-v1", self.target.target_hash).state)
        self.assertFalse(any(item["event"] == "target_completed" for item in self.kernel.audit))

    def test_same_artifact_completion_is_idempotent_but_replacement_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deck.pptx"
            path.write_bytes(b"version one")
            first = self.reconcile.complete_file("deck-v1", self.target.target_hash, path)
            event_count = sum(item["event"] == "target_completed" for item in self.kernel.audit)

            self.now += 100
            second = self.reconcile.complete_file("deck-v1", self.target.target_hash, path)
            self.assertEqual(first, second)
            self.assertEqual(event_count, sum(item["event"] == "target_completed" for item in self.kernel.audit))

            path.write_bytes(b"different artifact")
            with self.assertRaisesRegex(ValueError, "target_completion_immutable"):
                self.reconcile.complete_file("deck-v1", self.target.target_hash, path)

    def test_completion_of_one_version_does_not_complete_another(self):
        second_intent = Intent("agent:builder", "write", "artifact:pitch-deck:v2", 0, "deck-session")
        second = self.kernel.lock_target("deck-v1", second_intent, version=2)
        with tempfile.NamedTemporaryFile(suffix=".pptx") as handle:
            handle.write(b"version one deck")
            handle.flush()
            self.reconcile.complete_file("deck-v1", self.target.target_hash, handle.name, version=1)

        first_status = self.reconcile.status("deck-v1", self.target.target_hash, version=1)
        second_status = self.reconcile.status("deck-v1", second.target_hash, version=2)
        self.assertEqual("completed", first_status.state)
        self.assertEqual("unresolved", second_status.state)

    def test_unresolved_and_completed_state_survive_sqlite_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "pulpo.db"
            artifact_path = Path(directory) / "deck.pptx"
            artifact_path.write_bytes(b"durable deck artifact")

            first_state = SQLiteKernelState(db_path)
            first_kernel = GovernanceKernel(
                Policy(frozenset({"write"}), 100),
                secret=b"target-reconciliation-secret",
                clock=lambda: self.now,
                state=first_state,
            )
            first_target = first_kernel.lock_target("durable-deck", self.intent)
            first_reconcile = GovernedTargetReconciliation(first_kernel)
            self.assertEqual("unresolved", first_reconcile.status("durable-deck", first_target.target_hash).state)
            completion = first_reconcile.complete_file("durable-deck", first_target.target_hash, artifact_path)
            first_state.close()

            second_state = SQLiteKernelState(db_path)
            second_kernel = GovernanceKernel(
                Policy(frozenset({"write"}), 100),
                secret=b"target-reconciliation-secret",
                clock=lambda: self.now + 1,
                state=second_state,
            )
            second_reconcile = GovernedTargetReconciliation(second_kernel)
            restored = second_reconcile.status("durable-deck", first_target.target_hash)
            self.assertEqual("completed", restored.state)
            self.assertEqual(completion, restored.completion)
            self.assertTrue(second_kernel.verify_audit())
            second_state.close()


if __name__ == "__main__":
    unittest.main()

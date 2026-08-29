import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState


class TargetLockTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000_000_000_000
        self.kernel = GovernanceKernel(
            Policy(frozenset({"read", "write"}), 100),
            secret=b"target-test-secret",
            clock=lambda: self.now,
        )

    def test_lock_records_exact_target_without_granting_authority(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        target = self.kernel.lock_target("T-001", intent)

        self.assertEqual("pulpo.target.v0", target.schema)
        self.assertEqual(intent, target.intent)
        self.assertEqual(64, len(target.target_hash))
        self.assertEqual(["target_locked"], [record["event"] for record in self.kernel.audit])
        self.assertEqual("none", self.kernel.audit[0]["payload"]["authority_effect"])
        self.assertNotIn("permit", self.kernel.audit[0]["payload"])

    def test_same_target_retry_is_idempotent_when_clock_advances(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        first = self.kernel.lock_target("T-RETRY", intent)
        audit_len = len(self.kernel.audit)

        self.now += 10_000
        retried = self.kernel.lock_target("T-RETRY", intent)

        self.assertEqual(first, retried)
        self.assertEqual(first.target_hash, retried.target_hash)
        self.assertEqual(first.created_at_ns, retried.created_at_ns)
        self.assertEqual(audit_len, len(self.kernel.audit))

    def test_exact_target_resolves_but_hash_mismatch_fails_closed(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        target = self.kernel.lock_target("T-002", intent)

        exact = self.kernel.resolve_locked_target("T-002", target.target_hash)
        mismatch = self.kernel.resolve_locked_target("T-002", "0" * 64)

        self.assertEqual(("match", "target_exact_match"), (exact.outcome, exact.reason))
        self.assertEqual(target, exact.target)
        self.assertEqual(("deny", "target_hash_mismatch"), (mismatch.outcome, mismatch.reason))
        self.assertIsNone(mismatch.target)

    def test_fire_path_delegates_to_kernel_policy_and_one_use_permit(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        target = self.kernel.lock_target("T-003", intent)

        resolution, decision = self.kernel.evaluate_locked_target("T-003", target.target_hash)

        self.assertEqual("match", resolution.outcome)
        self.assertIsNotNone(decision)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.kernel.consume(decision.permit, intent))
        self.assertFalse(self.kernel.consume(decision.permit, intent))

    def test_fire_path_cannot_bypass_policy(self):
        intent = Intent("agent:builder", "delete", "repo:README.md", 0, "voice-session")
        target = self.kernel.lock_target("T-004", intent)

        resolution, decision = self.kernel.evaluate_locked_target("T-004", target.target_hash)

        self.assertEqual("match", resolution.outcome)
        self.assertIsNotNone(decision)
        self.assertEqual(("deny", "action_not_allowed"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)

    def test_mismatched_target_never_reaches_authority_evaluation(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        self.kernel.lock_target("T-005", intent)
        decisions_before = sum(record["event"] == "decision" for record in self.kernel.audit)

        resolution, decision = self.kernel.evaluate_locked_target("T-005", "f" * 64)

        decisions_after = sum(record["event"] == "decision" for record in self.kernel.audit)
        self.assertEqual(("deny", "target_hash_mismatch"), (resolution.outcome, resolution.reason))
        self.assertIsNone(decision)
        self.assertEqual(decisions_before, decisions_after)

    def test_locked_target_survives_sqlite_restart(self):
        intent = Intent("agent:builder", "write", "repo:README.md", 5, "voice-session")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pulpo.db"
            first_state = SQLiteKernelState(path)
            first = GovernanceKernel(
                Policy(frozenset({"write"}), 100),
                secret=b"target-test-secret",
                clock=lambda: self.now,
                state=first_state,
            )
            target = first.lock_target("T-006", intent)
            first_state.close()

            second_state = SQLiteKernelState(path)
            second = GovernanceKernel(
                Policy(frozenset({"write"}), 100),
                secret=b"target-test-secret",
                clock=lambda: self.now + 1,
                state=second_state,
            )
            restored = second.get_locked_target("T-006")
            resolution, decision = second.evaluate_locked_target("T-006", target.target_hash)

            self.assertEqual(target, restored)
            self.assertEqual("match", resolution.outcome)
            self.assertEqual("allow", decision.outcome)
            second_state.close()

    def test_target_version_is_immutable(self):
        first = Intent("agent:builder", "write", "repo:a", 0, "voice-session")
        second = Intent("agent:builder", "write", "repo:b", 0, "voice-session")
        self.kernel.lock_target("T-007", first, version=1)

        with self.assertRaisesRegex(ValueError, "target version is immutable"):
            self.kernel.lock_target("T-007", second, version=1)


if __name__ == "__main__":
    unittest.main()

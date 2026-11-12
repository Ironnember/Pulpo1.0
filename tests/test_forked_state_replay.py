import shutil
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState


class ForkedStateReplayTests(unittest.TestCase):
    """Adversarial proof for state-lineage equivocation.

    Ordinary restart replay uses one durable state file. This test snapshots that
    state after permit issuance, then opens two independently valid descendants.
    A one-use permit should not be able to create two legitimate consequences
    merely because custody state was cloned before consumption.
    """

    def test_one_use_permit_cannot_be_consumed_in_two_forked_state_lineages(self):
        policy = Policy(frozenset({"act"}), 0)
        secret = b"forked-state-replay-v0"
        intent = Intent(
            "agent:fork-test",
            "act",
            "capability:opaque-disposable:sha256:test-fixture",
            0,
            "forked-state-session",
        )
        now = [9_000_000_000]

        def kernel_for(path: Path) -> tuple[SQLiteKernelState, GovernanceKernel]:
            state = SQLiteKernelState(path)
            kernel = GovernanceKernel(
                policy,
                secret=secret,
                clock=lambda: now[0],
                state=state,
            )
            return state, kernel

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical_path = root / "canonical.sqlite3"
            fork_path = root / "fork.sqlite3"

            canonical_state, canonical_kernel = kernel_for(canonical_path)
            decision = canonical_kernel.evaluate(intent)
            self.assertEqual("allow", decision.outcome)
            self.assertIsNotNone(decision.permit)
            canonical_state.close()

            # Snapshot after issuance but before consumption. Both descendants
            # begin with the same valid audit chain and the same unspent permit.
            shutil.copy2(canonical_path, fork_path)

            canonical_state, canonical_kernel = kernel_for(canonical_path)
            fork_state, fork_kernel = kernel_for(fork_path)

            self.assertTrue(canonical_kernel.verify_audit())
            self.assertTrue(fork_kernel.verify_audit())

            canonical_consumed = canonical_kernel.consume(decision.permit, intent)
            now[0] += 1
            fork_consumed = fork_kernel.consume(decision.permit, intent)

            # Both branches must remain structurally valid even after divergence;
            # otherwise this would be corruption, not a state-lineage fork.
            canonical_audit_valid = canonical_kernel.verify_audit()
            fork_audit_valid = fork_kernel.verify_audit()
            self.assertTrue(canonical_audit_valid)
            self.assertTrue(fork_audit_valid)

            # Constitutional expectation: one-use must mean one consequence
            # across the authority lineage, not one use per cloned database.
            self.assertFalse(
                canonical_consumed and fork_consumed,
                (
                    "forked durable states both consumed the same one-use permit "
                    "while each divergent audit chain remained valid"
                ),
            )

            canonical_state.close()
            fork_state.close()


if __name__ == "__main__":
    unittest.main()

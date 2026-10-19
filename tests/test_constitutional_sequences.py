import random
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy, SQLiteKernelState


class ConstitutionalSequenceTests(unittest.TestCase):
    """Deterministic randomized stress over the existing kernel/state contract.

    This test creates no new authority path. It exercises only existing target,
    policy, permit, replay, persistence, and audit behavior against a small
    independent reference model.
    """

    SEED = 0x50554C504F
    STEPS = 2_000

    def test_randomized_sqlite_sequence_preserves_constitutional_invariants(self):
        rng = random.Random(self.SEED)
        now = [2_100_000_000_000_000_000]
        policy = Policy(frozenset({"read", "write"}), 100)
        secret = b"constitutional-sequence-secret"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            state = SQLiteKernelState(path)

            def kernel_for(current_state):
                return GovernanceKernel(
                    policy,
                    secret=secret,
                    clock=lambda: now[0],
                    state=current_state,
                )

            kernel = kernel_for(state)
            permits = {}
            targets = {}
            next_permit = 0
            next_target = 0
            restarts = 0
            wrong_intent_attempts = 0
            replay_attempts = 0
            target_mismatches = 0

            for _ in range(self.STEPS):
                now[0] += rng.randint(1, 10_000)
                operation = rng.choice(
                    (
                        "issue",
                        "consume_correct",
                        "consume_wrong",
                        "restart",
                        "lock_target",
                        "resolve_target",
                        "policy_deny",
                    )
                )

                if operation == "issue" or not permits:
                    intent = Intent(
                        "agent:sequence",
                        rng.choice(("read", "write")),
                        f"repo:item-{next_permit}",
                        rng.randint(0, 100),
                        "sequence-session",
                    )
                    decision = kernel.evaluate(intent)
                    self.assertEqual("allow", decision.outcome)
                    self.assertIsNotNone(decision.permit)
                    permits[decision.permit] = {"intent": intent, "spent": False}
                    next_permit += 1
                    continue

                if operation == "consume_correct":
                    permit = rng.choice(tuple(permits))
                    modeled = permits[permit]
                    expected = not modeled["spent"]
                    observed = kernel.consume(permit, modeled["intent"])
                    self.assertEqual(expected, observed)
                    if observed:
                        modeled["spent"] = True
                    else:
                        replay_attempts += 1
                    continue

                if operation == "consume_wrong":
                    permit = rng.choice(tuple(permits))
                    modeled = permits[permit]
                    wrong = Intent(
                        modeled["intent"].principal,
                        modeled["intent"].action,
                        modeled["intent"].resource + ":substituted",
                        modeled["intent"].cost,
                        modeled["intent"].session_id,
                    )
                    spent_before = modeled["spent"]
                    self.assertFalse(kernel.consume(permit, wrong))
                    self.assertEqual(spent_before, modeled["spent"])
                    wrong_intent_attempts += 1
                    continue

                if operation == "restart":
                    state.close()
                    state = SQLiteKernelState(path)
                    kernel = kernel_for(state)
                    self.assertTrue(kernel.verify_audit())
                    restarts += 1
                    continue

                if operation == "lock_target":
                    intent = Intent(
                        "agent:sequence",
                        rng.choice(("read", "write")),
                        f"repo:target-{next_target}",
                        rng.randint(0, 100),
                        "sequence-session",
                    )
                    target_id = f"SEQ-{next_target}"
                    target = kernel.lock_target(target_id, intent)
                    targets[target_id] = target
                    next_target += 1
                    self.assertEqual("none", kernel.audit[-1]["payload"]["authority_effect"])
                    continue

                if operation == "resolve_target":
                    if not targets:
                        continue
                    target_id = rng.choice(tuple(targets))
                    target = targets[target_id]
                    if rng.random() < 0.5:
                        resolution = kernel.resolve_locked_target(target_id, target.target_hash)
                        self.assertEqual(("match", "target_exact_match"), (resolution.outcome, resolution.reason))
                        self.assertEqual(target.target_hash, resolution.target.target_hash)
                    else:
                        mismatch = ("0" if target.target_hash[0] != "0" else "1") + target.target_hash[1:]
                        resolution = kernel.resolve_locked_target(target_id, mismatch)
                        self.assertEqual(("deny", "target_hash_mismatch"), (resolution.outcome, resolution.reason))
                        self.assertIsNone(resolution.target)
                        target_mismatches += 1
                    continue

                if operation == "policy_deny":
                    denied = rng.choice(
                        (
                            Intent("agent:sequence", "delete", "repo:forbidden", 0, "sequence-session"),
                            Intent("agent:sequence", "write", "repo:expensive", 101, "sequence-session"),
                            Intent("", "read", "repo:missing-principal", 0, "sequence-session"),
                        )
                    )
                    decision = kernel.evaluate(denied)
                    self.assertEqual("deny", decision.outcome)
                    self.assertIsNone(decision.permit)

            # Restart once more before final replay checks so the assertions
            # prove durable semantics rather than only in-process bookkeeping.
            state.close()
            state = SQLiteKernelState(path)
            kernel = kernel_for(state)
            self.assertTrue(kernel.verify_audit())

            for permit, modeled in permits.items():
                if modeled["spent"]:
                    self.assertFalse(kernel.consume(permit, modeled["intent"]))
                else:
                    self.assertTrue(kernel.consume(permit, modeled["intent"]))
                    modeled["spent"] = True
                    self.assertFalse(kernel.consume(permit, modeled["intent"]))

            for target_id, target in targets.items():
                restored = kernel.get_locked_target(target_id)
                self.assertIsNotNone(restored)
                self.assertEqual(target.target_hash, restored.target_hash)

            self.assertGreater(restarts, 0)
            self.assertGreater(wrong_intent_attempts, 0)
            self.assertGreater(replay_attempts, 0)
            self.assertGreater(target_mismatches, 0)
            self.assertTrue(kernel.verify_audit())
            state.close()


if __name__ == "__main__":
    unittest.main()

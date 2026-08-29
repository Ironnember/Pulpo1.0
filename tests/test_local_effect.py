import tempfile
from pathlib import Path
import unittest

from pulpo import GovernanceKernel, Policy
from pulpo.local_effect import (
    LocalEffectViolation,
    LocalFileEffect,
    LocalFileExecutor,
    build_local_effect_proof,
    local_file_intent,
    observe_local_file,
    reconcile_local_file,
)


class LocalEffectTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000_000_000_000
        self.kernel = GovernanceKernel(
            Policy(frozenset({"create_local_file"}), 0),
            secret=b"local-effect-test",
            clock=lambda: self.now,
        )
        self.effect = LocalFileEffect(
            "0123456789abcdef",
            "Pulpo verified local effect 0123456789abcdef\n",
        )
        self.executor = LocalFileExecutor(clock=lambda: self.now + 1)

    def _permit(self, effect=None):
        chosen = self.effect if effect is None else effect
        decision = self.kernel.evaluate(local_file_intent(chosen))
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit

    def test_exact_permit_creates_one_new_file_and_reconciles_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            permit = self._permit()

            execution = self.executor.execute(
                self.kernel,
                self.effect,
                permit,
                root=directory,
            )
            observation = observe_local_file(
                self.effect,
                root=directory,
                clock=lambda: self.now + 2,
            )
            reconciliation = reconcile_local_file(
                self.kernel,
                self.effect,
                execution,
                observation,
            )
            proof = build_local_effect_proof(
                self.kernel,
                self.effect,
                execution,
                observation,
                reconciliation,
            )

            target = Path(directory) / self.effect.relative_path
            self.assertTrue(target.is_file())
            self.assertEqual(self.effect.content, target.read_text())
            self.assertEqual(self.effect.content_hash, execution.claimed_content_hash)
            self.assertEqual(self.effect.content_hash, observation.observed_content_hash)
            self.assertTrue(reconciliation.verified)
            self.assertEqual("effect_verified", reconciliation.reason)
            self.assertTrue(proof["audit_valid"])
            self.assertEqual("pulpo.local-effect-proof.v0", proof["schema"])
            self.assertEqual(64, len(proof["bundle_hash"]))
            self.assertEqual(
                ["decision", "permit_consumed"],
                [record["event"] for record in self.kernel.audit],
            )

    def test_permit_for_different_effect_cannot_write(self):
        other = LocalFileEffect(
            "fedcba9876543210",
            "Different exact effect\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            wrong_permit = self._permit(other)

            with self.assertRaisesRegex(LocalEffectViolation, "permit_rejected"):
                self.executor.execute(
                    self.kernel,
                    self.effect,
                    wrong_permit,
                    root=directory,
                )

            self.assertFalse((Path(directory) / self.effect.relative_path).exists())
            self.assertEqual("permit_rejected", self.kernel.audit[-1]["event"])

    def test_existing_target_is_denied_before_permit_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / self.effect.relative_path
            target.write_text("pre-existing\n")
            permit = self._permit()

            with self.assertRaisesRegex(LocalEffectViolation, "effect_target_exists"):
                self.executor.execute(
                    self.kernel,
                    self.effect,
                    permit,
                    root=directory,
                )

            # The denial happened before execution consumed authority.
            self.assertTrue(self.kernel.consume(permit, local_file_intent(self.effect)))
            self.assertEqual("pre-existing\n", target.read_text())

    def test_spent_permit_cannot_create_effect_again(self):
        with tempfile.TemporaryDirectory() as directory:
            permit = self._permit()
            self.executor.execute(self.kernel, self.effect, permit, root=directory)
            target = Path(directory) / self.effect.relative_path
            target.unlink()

            with self.assertRaisesRegex(LocalEffectViolation, "permit_rejected"):
                self.executor.execute(self.kernel, self.effect, permit, root=directory)

            self.assertFalse(target.exists())
            self.assertEqual("permit_rejected", self.kernel.audit[-1]["event"])

    def test_tampering_after_execution_reconciles_as_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            permit = self._permit()
            execution = self.executor.execute(self.kernel, self.effect, permit, root=directory)
            target = Path(directory) / self.effect.relative_path
            target.write_text("tampered after execution\n")

            observation = observe_local_file(
                self.effect,
                root=directory,
                clock=lambda: self.now + 2,
            )
            reconciliation = reconcile_local_file(
                self.kernel,
                self.effect,
                execution,
                observation,
            )

            self.assertFalse(reconciliation.verified)
            self.assertEqual("mismatch", reconciliation.outcome)
            self.assertEqual("observed_content_mismatch", reconciliation.reason)
            self.assertNotEqual(self.effect.content_hash, observation.observed_content_hash)

    def test_missing_effect_reconciles_as_not_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            permit = self._permit()
            execution = self.executor.execute(self.kernel, self.effect, permit, root=directory)
            (Path(directory) / self.effect.relative_path).unlink()

            observation = observe_local_file(
                self.effect,
                root=directory,
                clock=lambda: self.now + 2,
            )
            reconciliation = reconcile_local_file(
                self.kernel,
                self.effect,
                execution,
                observation,
            )

            self.assertFalse(observation.exists)
            self.assertEqual("effect_not_observed", reconciliation.reason)

    def test_effect_shape_removes_arbitrary_path_and_bounds_content(self):
        self.assertEqual(
            ".pulpo-effect-v0-0123456789abcdef.txt",
            self.effect.relative_path,
        )
        with self.assertRaisesRegex(LocalEffectViolation, "effect_id_invalid"):
            LocalFileEffect("../outside", "x")
        with self.assertRaisesRegex(LocalEffectViolation, "effect_content_required"):
            LocalFileEffect("0123456789abcdef", "")
        with self.assertRaisesRegex(LocalEffectViolation, "effect_content_too_large"):
            LocalFileEffect("0123456789abcdef", "x" * 1025)


if __name__ == "__main__":
    unittest.main()

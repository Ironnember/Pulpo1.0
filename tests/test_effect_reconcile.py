import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from pulpo.kernel import GovernanceKernel, Intent, Policy

from pulpo.effect_reconcile import (
    EffectEnvelope,
    EffectReconciliationError,
    ExecutionIdentity,
    SurfaceSpec,
    bind_resource_to_effect_envelope,
    capture_envelope_surfaces,
    capture_surface,
    reconcile_effects,
)


class PermitBoundEffectReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.protected = self.base / "protected"
        self.writable = self.base / "runtime"
        self.evidence = self.base / "evidence"
        self.protected.mkdir()
        self.writable.mkdir()
        self.evidence.mkdir()
        (self.protected / "source.txt").write_text("canonical\n", encoding="utf-8")
        self.executable = self.base / "codex"
        self.executable.write_bytes(b"pinned-codex")
        self.executable_hash = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.envelope = EffectEnvelope(
            executable_path=str(self.executable),
            executable_sha256=self.executable_hash,
            argv=(str(self.executable), "--sandbox", "read-only"),
            workdir=str(self.protected),
            source_sha="2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8",
            profile="permit-bound-local-intelligence-v1",
            expires_at_ns=10_000,
            surfaces=(
                SurfaceSpec(str(self.protected), "protected"),
                SurfaceSpec(str(self.writable), "writable"),
                SurfaceSpec(str(self.evidence), "evidence"),
            ),
        )
        self.identity = ExecutionIdentity(
            executable_path=str(self.executable),
            executable_sha256=self.executable_hash,
            argv=self.envelope.argv,
            workdir=str(self.protected),
            source_sha=self.envelope.source_sha,
            profile=self.envelope.profile,
        )

    def reconcile(self, before, after, **kwargs):
        return reconcile_effects(
            self.envelope,
            self.identity,
            before,
            after,
            execution_started_ns=9_000,
            observation_complete=kwargs.pop("observation_complete", True),
            **kwargs,
        )

    def test_writes_inside_declared_runtime_surface_are_verified(self):
        before = capture_envelope_surfaces(self.envelope)
        (self.writable / "session.log").write_text("allowed runtime state\n", encoding="utf-8")
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(before, after)

        self.assertEqual(result.status, "verified")
        self.assertEqual(result.unauthorized_effects, 0)
        self.assertGreater(result.authorized_runtime_effects, 0)
        self.assertEqual(len(result.reconciliation_hash), 64)

    def test_protected_worktree_write_is_mismatch_even_when_runtime_write_is_allowed(self):
        before = capture_envelope_surfaces(self.envelope)
        (self.writable / "session.log").write_text("allowed\n", encoding="utf-8")
        (self.protected / "unauthorized.txt").write_text("forbidden\n", encoding="utf-8")
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(before, after)

        self.assertEqual(result.status, "mismatch")
        self.assertGreater(result.protected_surface_delta, 0)
        self.assertIn("protected_surface_changed", result.reason)

    def test_canonical_evidence_surface_may_change_without_trusting_child(self):
        before = capture_envelope_surfaces(self.envelope)
        (self.evidence / "audit.append").write_text("event\n", encoding="utf-8")
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(
            before,
            after,
            canonical_evidence_paths=(str(self.evidence / "audit.append"),),
        )

        self.assertEqual(result.status, "verified")
        self.assertGreater(result.canonical_pulpo_evidence, 0)
        self.assertEqual(result.unauthorized_effects, 0)

    def test_unattested_write_to_evidence_surface_is_mismatch(self):
        before = capture_envelope_surfaces(self.envelope)
        (self.evidence / "forged.append").write_text("child claim\n", encoding="utf-8")
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(before, after)

        self.assertEqual(result.status, "mismatch")
        self.assertGreater(result.protected_surface_delta, 0)
        self.assertEqual(result.canonical_pulpo_evidence, 0)

    def test_observed_path_outside_envelope_is_undeclared_mismatch(self):
        before = capture_envelope_surfaces(self.envelope)
        external = self.base / "outside.txt"
        external.write_text("escape\n", encoding="utf-8")
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(before, after, observed_changed_paths=(str(external),))

        self.assertEqual(result.status, "mismatch")
        self.assertGreater(result.unauthorized_effects, 0)
        self.assertIn("undeclared_effect_observed", result.reason)

    def test_incomplete_observer_fails_closed_as_uncertain(self):
        before = capture_envelope_surfaces(self.envelope)
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(before, after, observation_complete=False)

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.unauthorized_effects, 0)
        self.assertIn("observation_incomplete", result.reason)

    def test_generator_observations_do_not_create_false_duplicate_uncertainty(self):
        before = capture_envelope_surfaces(self.envelope)
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile((item for item in before), (item for item in after))

        self.assertEqual(result.status, "verified")
        self.assertEqual(result.uncertain_effects, 0)

    def test_missing_surface_observation_is_uncertain(self):
        before = capture_envelope_surfaces(self.envelope)
        after = capture_envelope_surfaces(self.envelope)

        result = self.reconcile(before[:-1], after)

        self.assertEqual(result.status, "uncertain")
        self.assertIn("missing_surface_observation", result.reason)

    def test_execution_identity_mismatch_is_mismatch_without_effect(self):
        before = capture_envelope_surfaces(self.envelope)
        after = capture_envelope_surfaces(self.envelope)
        wrong = ExecutionIdentity(
            executable_path=str(self.executable),
            executable_sha256="0" * 64,
            argv=self.envelope.argv,
            workdir=str(self.protected),
            source_sha=self.envelope.source_sha,
            profile=self.envelope.profile,
        )

        result = reconcile_effects(
            self.envelope,
            wrong,
            before,
            after,
            execution_started_ns=9_000,
            observation_complete=True,
        )

        self.assertEqual(result.status, "mismatch")
        self.assertIn("execution_identity_mismatch", result.reason)

    def test_expired_permit_is_mismatch(self):
        before = capture_envelope_surfaces(self.envelope)
        after = capture_envelope_surfaces(self.envelope)

        result = reconcile_effects(
            self.envelope,
            self.identity,
            before,
            after,
            execution_started_ns=10_001,
            observation_complete=True,
        )

        self.assertEqual(result.status, "mismatch")
        self.assertIn("permit_expired_before_execution", result.reason)

    def test_envelope_hash_is_order_independent_for_surface_declaration(self):
        reversed_envelope = EffectEnvelope(
            executable_path=self.envelope.executable_path,
            executable_sha256=self.envelope.executable_sha256,
            argv=self.envelope.argv,
            workdir=self.envelope.workdir,
            source_sha=self.envelope.source_sha,
            profile=self.envelope.profile,
            expires_at_ns=self.envelope.expires_at_ns,
            surfaces=tuple(reversed(self.envelope.surfaces)),
        )
        self.assertEqual(self.envelope.envelope_hash, reversed_envelope.envelope_hash)

    def test_ambiguous_overlapping_roots_are_rejected(self):
        nested = self.protected / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(EffectReconciliationError, "ambiguous_overlapping_surface_roots"):
            EffectEnvelope(
                executable_path=str(self.executable),
                executable_sha256=self.executable_hash,
                argv=(str(self.executable),),
                workdir=str(self.protected),
                source_sha="abc",
                profile="test",
                expires_at_ns=1,
                surfaces=(
                    SurfaceSpec(str(self.protected), "protected"),
                    SurfaceSpec(str(nested), "writable"),
                ),
            )

    def test_nested_writable_is_allowed_only_when_parent_protected_surface_excludes_it(self):
        host = self.base / "host"
        runtime = host / "runtime"
        host.mkdir()
        runtime.mkdir()
        (host / "protected.txt").write_text("stable\n", encoding="utf-8")
        envelope = EffectEnvelope(
            executable_path=str(self.executable),
            executable_sha256=self.executable_hash,
            argv=(str(self.executable),),
            workdir=str(host),
            source_sha="abc",
            profile="test",
            expires_at_ns=10_000,
            surfaces=(
                SurfaceSpec(str(host), "protected", exclude=("runtime",)),
                SurfaceSpec(str(runtime), "writable"),
            ),
        )
        identity = ExecutionIdentity(
            executable_path=str(self.executable),
            executable_sha256=self.executable_hash,
            argv=envelope.argv,
            workdir=str(host),
            source_sha=envelope.source_sha,
            profile=envelope.profile,
        )
        before = capture_envelope_surfaces(envelope)
        (runtime / "session.json").write_text("{}\n", encoding="utf-8")
        after = capture_envelope_surfaces(envelope)
        result = reconcile_effects(
            envelope,
            identity,
            before,
            after,
            execution_started_ns=9_000,
            observation_complete=True,
        )
        self.assertEqual(result.status, "verified")
        self.assertGreater(result.authorized_runtime_effects, 0)
        self.assertEqual(result.protected_surface_delta, 0)

    def test_existing_one_use_permit_is_cryptographically_bound_to_effect_envelope(self):
        alternate = EffectEnvelope(
            executable_path=self.envelope.executable_path,
            executable_sha256=self.envelope.executable_sha256,
            argv=self.envelope.argv + ("--alternate",),
            workdir=self.envelope.workdir,
            source_sha=self.envelope.source_sha,
            profile=self.envelope.profile,
            expires_at_ns=self.envelope.expires_at_ns,
            surfaces=self.envelope.surfaces,
        )
        resource = bind_resource_to_effect_envelope("cmd:codex-readonly", self.envelope)
        substituted_resource = bind_resource_to_effect_envelope("cmd:codex-readonly", alternate)
        self.assertNotEqual(resource, substituted_resource)

        kernel = GovernanceKernel(Policy(allowed_actions=frozenset({"run"}), max_cost=0))
        exact = Intent(principal="local-intelligence", action="run", resource=resource)
        substituted = Intent(
            principal="local-intelligence",
            action="run",
            resource=substituted_resource,
        )
        decision = kernel.evaluate(exact)
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)

        self.assertFalse(kernel.consume(decision.permit, substituted))
        self.assertTrue(kernel.consume(decision.permit, exact))
        self.assertFalse(kernel.consume(decision.permit, exact))

    def test_effect_resource_cannot_be_bound_twice(self):
        resource = bind_resource_to_effect_envelope("cmd:codex-readonly", self.envelope)
        with self.assertRaisesRegex(EffectReconciliationError, "resource_already_effect_bound"):
            bind_resource_to_effect_envelope(resource, self.envelope)

    def test_symlink_snapshot_does_not_follow_target(self):
        target = self.base / "outside-target"
        target.mkdir()
        (target / "secret.txt").write_text("one\n", encoding="utf-8")
        link = self.protected / "link"
        os.symlink(target, link)
        surface = SurfaceSpec(str(self.protected), "protected")
        before = capture_surface(surface)

        (target / "secret.txt").write_text("two\n", encoding="utf-8")
        after = capture_surface(surface)

        self.assertEqual(before.digest, after.digest)
        external = str(target / "secret.txt")
        result = self.reconcile(
            capture_envelope_surfaces(self.envelope),
            capture_envelope_surfaces(self.envelope),
            observed_changed_paths=(external,),
        )
        self.assertEqual(result.status, "mismatch")
        self.assertIn("undeclared_effect_observed", result.reason)


if __name__ == "__main__":
    unittest.main()

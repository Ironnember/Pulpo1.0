from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from pulpo.behavior_telemetry import (
    BaselineState,
    BehaviorObservation,
    BehaviorTelemetry,
    ContextualBaseline,
)
from pulpo.kernel import GovernanceKernel, Intent, Policy


class AdaptiveBehaviorPoisoningProof(unittest.TestCase):
    def observation(
        self,
        *,
        source_scope: str = "interface:test",
        trust_domain: str = "worker-domain-a",
        identity_scope: str = "principal:unknown",
        workload: str = "workload:a",
        worker: str = "model:test",
        family: str = "unknown-operation",
        shape: str = "shape:v1",
        capability: str = "write:unknown",
        target: str = "target:unknown",
        policy_version: str = "policy:v1",
        authority_version: str = "authority:v1",
    ) -> BehaviorObservation:
        return BehaviorObservation(
            source_scope=source_scope,
            source_trust_domain=trust_domain,
            identity_scope=identity_scope,
            workload_scope=workload,
            model_or_worker_source=worker,
            request_family=family,
            request_shape=shape,
            requested_capability=capability,
            target_class=target,
            policy_version=policy_version,
            authority_version=authority_version,
        )

    def test_unknown_rejection_creates_immutable_baseline(self) -> None:
        telemetry = BehaviorTelemetry()
        observation = self.observation()
        chain, disposition = telemetry.observe_unknown(observation, rejection_reason="unknown_intent")
        self.assertIsNotNone(chain)
        assert chain is not None
        self.assertEqual(disposition.action, "reject")
        self.assertFalse(disposition.execution_attempted)
        self.assertEqual(disposition.authority_effect, "none")
        self.assertFalse(chain.baseline.execution_attempted)
        self.assertTrue(chain.baseline.immutable)
        original_hash = chain.baseline.event_hash
        with self.assertRaises(FrozenInstanceError):
            chain.baseline.rejection_reason = "rewritten"  # type: ignore[misc]
        self.assertEqual(chain.baseline.event_hash, original_hash)

    def test_identical_unknowns_increment_repeat_count_without_full_log_growth(self) -> None:
        telemetry = BehaviorTelemetry(repeat_pressure_threshold=1000)
        observation = self.observation()
        chain, _ = telemetry.observe_unknown(observation, rejection_reason="unknown_intent")
        assert chain is not None
        baseline_hash = chain.baseline.event_hash
        for _ in range(10_000):
            repeated, _ = telemetry.observe_unknown(observation, rejection_reason="unknown_intent")
            self.assertIs(repeated, chain)
        self.assertEqual(chain.repeat_count, 10_000)
        self.assertEqual(len(chain.deltas), 0)
        self.assertEqual(len(chain.checkpoints), 0)
        self.assertEqual(chain.baseline.event_hash, baseline_hash)
        self.assertTrue(chain.contained)

    def test_material_change_creates_delta_referencing_baseline(self) -> None:
        telemetry = BehaviorTelemetry()
        first = self.observation(shape="shape:v1")
        chain, _ = telemetry.observe_unknown(first, rejection_reason="unknown_intent")
        assert chain is not None
        baseline_hash = chain.baseline.event_hash
        changed = self.observation(shape="shape:v2")
        same_chain, _ = telemetry.observe_unknown(changed, rejection_reason="unknown_intent")
        self.assertIs(same_chain, chain)
        self.assertEqual(len(chain.deltas), 1)
        delta = chain.deltas[0]
        self.assertEqual(delta.baseline_event_hash, baseline_hash)
        self.assertEqual(delta.previous_event_hash, baseline_hash)
        self.assertIn(("request_shape", "shape:v1", "shape:v2"), delta.changed_fields)
        self.assertEqual(delta.materiality_class, "medium")
        self.assertFalse(delta.execution_attempted)

    def test_capability_change_raises_materiality_without_authority(self) -> None:
        telemetry = BehaviorTelemetry()
        chain, _ = telemetry.observe_unknown(
            self.observation(capability="read:unknown"),
            rejection_reason="unknown_intent",
        )
        assert chain is not None
        changed, _ = telemetry.observe_unknown(
            self.observation(capability="admin:unknown"),
            rejection_reason="unknown_intent",
        )
        assert changed is chain
        delta = chain.deltas[-1]
        self.assertEqual(delta.materiality_class, "high")
        self.assertEqual(delta.anomaly_score, 0.9)
        signal = telemetry.anomaly_from_chain(chain)
        self.assertFalse(signal.execution_allowed)
        self.assertEqual(signal.authority_effect, "none")

    def test_checkpoint_reconstructs_without_rewriting_history(self) -> None:
        telemetry = BehaviorTelemetry(checkpoint_every=2)
        chain, _ = telemetry.observe_unknown(self.observation(shape="shape:v0"), rejection_reason="unknown")
        assert chain is not None
        baseline_hash = chain.baseline.event_hash
        for index in range(1, 5):
            telemetry.observe_unknown(
                self.observation(shape=f"shape:v{index}"),
                rejection_reason="unknown",
            )
        self.assertEqual(chain.baseline.event_hash, baseline_hash)
        self.assertEqual(len(chain.deltas), 4)
        self.assertEqual(len(chain.checkpoints), 2)
        for checkpoint in chain.checkpoints:
            self.assertTrue(checkpoint.verify())
            self.assertTrue(telemetry.verify_checkpoint(chain.chain_id, checkpoint))
            self.assertEqual(checkpoint.baseline_event_hash, baseline_hash)
        current = telemetry.checkpoint_now(chain.chain_id)
        self.assertTrue(telemetry.verify_checkpoint(chain.chain_id, current))
        self.assertEqual(chain.baseline.event_hash, baseline_hash)

    def test_contextual_baselines_do_not_use_global_threshold(self) -> None:
        baseline_a = ContextualBaseline(
            workload_scope="workload:a",
            version=1,
            expected_unknown_rate=0.10,
            tolerance=0.10,
            admission_ref="admission:a:v1",
        )
        baseline_b = ContextualBaseline(
            workload_scope="workload:b",
            version=1,
            expected_unknown_rate=0.70,
            tolerance=0.10,
            admission_ref="admission:b:v1",
        )
        signal_a = BehaviorTelemetry.contextual_rate_signal(0.65, baseline_a)
        signal_b = BehaviorTelemetry.contextual_rate_signal(0.65, baseline_b)
        self.assertEqual(signal_a.scope, "workload:a")
        self.assertEqual(signal_b.scope, "workload:b")
        self.assertGreater(signal_a.score, signal_b.score)
        self.assertFalse(signal_a.execution_allowed)
        self.assertFalse(signal_b.execution_allowed)

    def test_learning_recommendation_cannot_admit_baseline_or_change_policy(self) -> None:
        policy = Policy(allowed_actions=frozenset({"read"}), max_cost=1)
        kernel = GovernanceKernel(policy)
        original_policy_hash = kernel.policy_hash
        telemetry = BehaviorTelemetry()
        chain, _ = telemetry.observe_unknown(self.observation(), rejection_reason="unknown")
        assert chain is not None
        telemetry.observe_unknown(
            self.observation(capability="deploy:unknown"),
            rejection_reason="unknown",
        )
        candidate = telemetry.recommend_baseline_change(
            chain.chain_id,
            self.observation(capability="deploy:unknown"),
        )
        self.assertFalse(candidate.admitted)
        self.assertEqual(candidate.authority_effect, "none")
        self.assertEqual(candidate.active_baseline_hash, chain.baseline.event_hash)
        self.assertIn("single_trust_domain", candidate.poisoning_flags)
        self.assertEqual(kernel.policy_hash, original_policy_hash)
        denied = kernel.evaluate(Intent("proof", "write", "repo:production", 0, "learning"))
        self.assertEqual(denied.outcome, "deny")

    def test_anomaly_score_cannot_authorize_execution(self) -> None:
        telemetry = BehaviorTelemetry(containment_delta_threshold=1)
        chain, _ = telemetry.observe_unknown(self.observation(), rejection_reason="unknown")
        assert chain is not None
        telemetry.observe_unknown(
            self.observation(capability="root:unknown"),
            rejection_reason="unknown",
        )
        high = telemetry.anomaly_from_chain(chain)
        self.assertGreaterEqual(high.score, 0.95)
        self.assertFalse(high.execution_allowed)
        low_chain, _ = telemetry.observe_unknown(
            self.observation(workload="workload:low", family="low-family"),
            rejection_reason="unknown",
        )
        assert low_chain is not None
        low = telemetry.anomaly_from_chain(low_chain)
        self.assertEqual(low.score, 0.0)
        self.assertFalse(low.execution_allowed)

    def test_containment_blocks_without_policy_expansion(self) -> None:
        policy = Policy(allowed_actions=frozenset({"read"}), max_cost=1)
        kernel = GovernanceKernel(policy)
        policy_hash = kernel.policy_hash
        telemetry = BehaviorTelemetry(containment_delta_threshold=2)
        chain, _ = telemetry.observe_unknown(self.observation(shape="shape:0"), rejection_reason="unknown")
        assert chain is not None
        telemetry.observe_unknown(self.observation(shape="shape:1"), rejection_reason="unknown")
        _, disposition = telemetry.observe_unknown(self.observation(shape="shape:2"), rejection_reason="unknown")
        self.assertEqual(disposition.action, "contain")
        self.assertEqual(disposition.authority_effect, "none")
        self.assertEqual(kernel.policy_hash, policy_hash)

    def test_rejected_unknown_never_reaches_executor_or_provider_callback(self) -> None:
        telemetry = BehaviorTelemetry()
        calls = 0

        def forbidden_callback(_observation: BehaviorObservation) -> object:
            nonlocal calls
            calls += 1
            raise AssertionError("rejected unknown reached execution callback")

        for index in range(100):
            telemetry.observe_unknown(
                self.observation(shape=f"shape:{index}"),
                rejection_reason="unknown",
                execution_callback=forbidden_callback,
            )
        self.assertEqual(calls, 0)
        for chain in telemetry.chains.values():
            self.assertFalse(chain.baseline.execution_attempted)
            self.assertTrue(all(not delta.execution_attempted for delta in chain.deltas))

    def test_high_cardinality_context_is_bounded(self) -> None:
        telemetry = BehaviorTelemetry(max_contexts=3)
        accepted = 0
        contained = 0
        for index in range(20):
            chain, disposition = telemetry.observe_unknown(
                self.observation(
                    source_scope=f"source:{index}",
                    workload=f"workload:{index}",
                    family="rotating-context",
                ),
                rejection_reason="unknown",
            )
            if chain is None:
                contained += 1
                self.assertEqual(disposition.reason, "context_cardinality_overflow")
                self.assertEqual(disposition.action, "contain")
            else:
                accepted += 1
        self.assertEqual(accepted, 3)
        self.assertEqual(contained, 17)
        self.assertEqual(len(telemetry.chains), 3)
        self.assertEqual(telemetry.context_overflow_count, 17)

    def test_micro_variation_delta_flood_is_bounded_or_escalated(self) -> None:
        telemetry = BehaviorTelemetry(max_deltas_per_chain=3, containment_delta_threshold=3)
        chain, _ = telemetry.observe_unknown(self.observation(shape="shape:0"), rejection_reason="unknown")
        assert chain is not None
        baseline_hash = chain.baseline.event_hash
        for index in range(1, 101):
            telemetry.observe_unknown(
                self.observation(shape=f"shape:{index}"),
                rejection_reason="unknown",
            )
        self.assertEqual(len(chain.deltas), 3)
        self.assertEqual(chain.delta_overflow_count, 97)
        self.assertTrue(chain.contained)
        self.assertEqual(chain.baseline.event_hash, baseline_hash)
        candidate = telemetry.recommend_baseline_change(chain.chain_id, chain.last_observation)
        self.assertIn("delta_overflow", candidate.poisoning_flags)
        self.assertFalse(candidate.admitted)

    def test_missing_logs_classified_unknown_not_safe(self) -> None:
        signal = BehaviorTelemetry.missing_evidence_signal("workload:attack")
        self.assertEqual(signal.evidence_status, "unknown")
        self.assertEqual(signal.reason, "telemetry_missing_unknown_state")
        self.assertEqual(signal.score, 1.0)
        self.assertFalse(signal.execution_allowed)
        self.assertEqual(signal.authority_effect, "none")

    def test_slow_poisoning_cannot_rewrite_baseline_or_self_ratify(self) -> None:
        telemetry = BehaviorTelemetry(max_deltas_per_chain=20, containment_delta_threshold=10)
        chain, _ = telemetry.observe_unknown(
            self.observation(shape="risk:00", capability="read:unknown"),
            rejection_reason="unknown",
        )
        assert chain is not None
        baseline_hash = chain.baseline.event_hash
        for index in range(1, 10):
            telemetry.observe_unknown(
                self.observation(
                    shape=f"risk:{index:02d}",
                    capability="read:unknown" if index < 8 else "write:unknown",
                ),
                rejection_reason="unknown",
            )
        candidate = telemetry.recommend_baseline_change(chain.chain_id, chain.last_observation)
        self.assertEqual(chain.baseline.event_hash, baseline_hash)
        self.assertEqual(candidate.active_baseline_hash, baseline_hash)
        self.assertIn("single_trust_domain", candidate.poisoning_flags)
        self.assertFalse(candidate.admitted)
        self.assertEqual(candidate.authority_effect, "none")
        self.assertGreater(len(candidate.evidence_refs), 1)

    def test_provenance_exposes_multiple_domains_without_making_them_authority(self) -> None:
        telemetry = BehaviorTelemetry()
        chain, _ = telemetry.observe_unknown(
            self.observation(trust_domain="observer-domain-a"),
            rejection_reason="unknown",
        )
        assert chain is not None
        telemetry.observe_unknown(
            self.observation(trust_domain="observer-domain-b", shape="shape:v2"),
            rejection_reason="unknown",
        )
        candidate = telemetry.recommend_baseline_change(chain.chain_id, chain.last_observation)
        self.assertEqual(candidate.source_trust_domains, ("observer-domain-a", "observer-domain-b"))
        self.assertNotIn("single_trust_domain", candidate.poisoning_flags)
        self.assertFalse(candidate.admitted)
        self.assertEqual(candidate.authority_effect, "none")

    def test_external_admitted_baseline_projection_is_prospective_and_does_not_rewrite_history(self) -> None:
        telemetry = BehaviorTelemetry()
        chain, _ = telemetry.observe_unknown(self.observation(), rejection_reason="unknown")
        assert chain is not None
        old_hash = chain.baseline.event_hash
        proposed = self.observation(shape="shape:v2")
        candidate = telemetry.recommend_baseline_change(chain.chain_id, proposed, proposed_version=2)
        self.assertFalse(candidate.admitted)

        # This is only a projection of a transition assumed to have been separately
        # authorized elsewhere.  The telemetry module neither validates nor creates it.
        projected = BaselineState(
            workload_scope="workload:a",
            version=2,
            baseline_hash=candidate.proposed_fingerprint,
            admission_ref="external-authority-transition:baseline-v2",
        )
        self.assertEqual(projected.version, 2)
        self.assertNotEqual(projected.baseline_hash, old_hash)
        self.assertEqual(chain.baseline.event_hash, old_hash)
        self.assertFalse(candidate.admitted)


if __name__ == "__main__":
    unittest.main()

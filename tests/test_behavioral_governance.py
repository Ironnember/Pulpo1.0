from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import Mock

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.behavioral_governance import (
    AnomalySignal,
    BaselineEvent,
    BaselineState,
    BehaviorChain,
    BehavioralGovernanceError,
    ContainmentDisposition,
    ContextualBaseline,
    compare_contextual_baselines,
)


class AdaptiveBehavioralGovernanceTests(unittest.TestCase):
    def state(self, **changes: str) -> BaselineState:
        values = {
            "source_scope": "local-agent",
            "identity_scope": "agent:builder",
            "workload_scope": "repo:pulpo",
            "worker_source": "worker:one",
            "request_shape": "unknown-operation:v1",
            "requested_capability": "unknown.action",
            "target_class": "repository",
            "policy_version": "policy:v1",
            "authority_version": "authority:v1",
        }
        values.update(changes)
        return BaselineState(**values)

    def test_rejected_unknown_creates_immutable_baseline(self):
        state = self.state()
        chain = BehaviorChain.from_rejected_unknown(state, sequence=1)

        self.assertIs(type(chain.baseline), BaselineEvent)
        self.assertEqual(state, chain.baseline.state)
        self.assertEqual("rejected_unknown", chain.baseline.disposition)
        self.assertFalse(chain.baseline.execution_attempted)
        self.assertFalse(chain.baseline.canonical_state_mutation)
        self.assertEqual("none", chain.baseline.authority_effect)
        self.assertEqual("none", chain.baseline.governed_effect)
        self.assertEqual(1, chain.detailed_event_count)
        self.assertEqual(state, chain.reconstruct())
        with self.assertRaises(FrozenInstanceError):
            chain.baseline.sequence = 2

    def test_identical_unknowns_increment_repeat_count_without_full_log_growth(self):
        chain = BehaviorChain.from_rejected_unknown(self.state(), sequence=1)
        baseline_hash = chain.baseline.event_hash

        for sequence in range(2, 10_002):
            chain = chain.record_rejected_unknown(self.state(), sequence=sequence)

        self.assertEqual(10_001, chain.repeat_count)
        self.assertEqual(0, chain.delta_count)
        self.assertEqual(1, chain.detailed_event_count)
        self.assertEqual(baseline_hash, chain.baseline.event_hash)
        self.assertEqual("repeat", chain.last_signal.classification)
        self.assertFalse(chain.last_signal.execution_authorized)

    def test_material_change_creates_delta_referencing_baseline(self):
        chain = BehaviorChain.from_rejected_unknown(self.state(), sequence=1)
        baseline_hash = chain.baseline.event_hash
        chain = chain.record_rejected_unknown(
            self.state(target_class="database"),
            sequence=2,
        )

        self.assertEqual(1, chain.delta_count)
        self.assertEqual(1, len(chain.active_deltas))
        delta = chain.active_deltas[0]
        self.assertEqual(chain.chain_id, delta.chain_id)
        self.assertEqual(baseline_hash, delta.baseline_event_hash)
        self.assertEqual(baseline_hash, delta.previous_event_hash)
        self.assertEqual("material", delta.materiality)
        self.assertEqual("target_class", delta.changes[0][0])
        self.assertEqual("none", delta.authority_effect)
        self.assertFalse(delta.execution_attempted)

    def test_capability_change_raises_materiality_without_authority(self):
        material = BehaviorChain.from_rejected_unknown(self.state(), sequence=1)
        material = material.record_rejected_unknown(
            self.state(target_class="database"),
            sequence=2,
        )
        capability = BehaviorChain.from_rejected_unknown(self.state(), sequence=1)
        capability = capability.record_rejected_unknown(
            self.state(requested_capability="production.write"),
            sequence=2,
        )

        capability_delta = capability.active_deltas[0]
        self.assertEqual("capability", capability_delta.materiality)
        self.assertGreater(
            capability_delta.anomaly_score_after_delta,
            material.active_deltas[0].anomaly_score_after_delta,
        )
        self.assertEqual("capability_change", capability.last_signal.classification)
        self.assertEqual("none", capability.last_signal.authority_effect)
        self.assertFalse(capability.last_signal.execution_authorized)
        self.assertFalse(capability.last_signal.baseline_admitted)

    def test_checkpoint_reconstructs_without_rewriting_history(self):
        chain = BehaviorChain.from_rejected_unknown(
            self.state(),
            sequence=1,
            checkpoint_after_deltas=2,
        )
        baseline = chain.baseline
        baseline_hash = baseline.event_hash
        chain = chain.record_rejected_unknown(
            self.state(target_class="database"),
            sequence=2,
        )
        first_delta_hash = chain.active_deltas[0].event_hash
        chain = chain.record_rejected_unknown(
            self.state(target_class="database", request_shape="unknown-operation:v2"),
            sequence=3,
        )

        self.assertIs(baseline, chain.baseline)
        self.assertEqual(baseline_hash, chain.baseline.event_hash)
        self.assertIsNotNone(chain.checkpoint)
        self.assertEqual((), chain.active_deltas)
        self.assertEqual(2, chain.checkpoint.covered_delta_count)
        self.assertNotEqual(first_delta_hash, chain.checkpoint.covered_event_hash)
        self.assertEqual(chain.current_state, chain.checkpoint.summarized_state)
        self.assertEqual(chain.current_state, chain.reconstruct())
        self.assertEqual(2, chain.detailed_event_count)

        chain = chain.record_rejected_unknown(
            self.state(target_class="queue", request_shape="unknown-operation:v2"),
            sequence=4,
        )
        self.assertEqual(1, len(chain.active_deltas))
        self.assertEqual(chain.checkpoint.covered_event_hash, chain.active_deltas[0].previous_event_hash)
        self.assertEqual(chain.current_state, chain.reconstruct())

    def test_contextual_baselines_do_not_use_one_global_threshold(self):
        workload_a = self.state(workload_scope="workload:a")
        workload_b = self.state(workload_scope="workload:b")
        baselines = (
            ContextualBaseline(
                context_hash=workload_a.context_hash,
                anomaly_threshold=2,
                containment_threshold=4,
            ),
            ContextualBaseline(
                context_hash=workload_b.context_hash,
                anomaly_threshold=10,
                containment_threshold=20,
            ),
        )

        signal_a, disposition_a = compare_contextual_baselines(
            workload_a,
            baselines,
            observed_unknowns=5,
            logs_complete=True,
        )
        signal_b, disposition_b = compare_contextual_baselines(
            workload_b,
            baselines,
            observed_unknowns=5,
            logs_complete=True,
        )

        self.assertEqual("context_containment", signal_a.classification)
        self.assertTrue(disposition_a.blocked)
        self.assertEqual("context_normal", signal_b.classification)
        self.assertFalse(disposition_b.blocked)
        self.assertNotEqual(signal_a.score, signal_b.score)

    def test_learning_recommendation_cannot_admit_baseline(self):
        chain = BehaviorChain.from_rejected_unknown(self.state(), sequence=1)
        before_hash = chain.chain_hash
        baseline_hash = chain.baseline.event_hash
        candidate = self.state(request_shape="candidate:v2")

        recommendation = chain.recommend_baseline(candidate)

        self.assertEqual("baseline_recommendation", recommendation.classification)
        self.assertEqual(candidate.state_hash, recommendation.recommended_baseline_hash)
        self.assertFalse(recommendation.baseline_admitted)
        self.assertFalse(recommendation.execution_authorized)
        self.assertEqual("none", recommendation.authority_effect)
        self.assertEqual(before_hash, chain.chain_hash)
        self.assertEqual(baseline_hash, chain.baseline.event_hash)
        with self.assertRaisesRegex(
            BehavioralGovernanceError,
            "anomaly_cannot_admit_baseline",
        ):
            AnomalySignal(
                context_hash=candidate.context_hash,
                classification="baseline_recommendation",
                score=None,
                reason="untrusted_learning_output",
                recommended_baseline_hash=candidate.state_hash,
                baseline_admitted=True,
            )

    def test_anomaly_score_cannot_authorize_execution(self):
        state = self.state()
        baseline = ContextualBaseline(
            context_hash=state.context_hash,
            anomaly_threshold=1,
            containment_threshold=1,
        )
        signal, _ = baseline.compare(1, logs_complete=True)

        self.assertEqual(100, signal.score)
        self.assertFalse(signal.execution_authorized)
        self.assertEqual("none", signal.authority_effect)
        with self.assertRaisesRegex(
            BehavioralGovernanceError,
            "anomaly_cannot_authorize_execution",
        ):
            AnomalySignal(
                context_hash=state.context_hash,
                classification="context_containment",
                score=100,
                reason="score_is_not_authority",
                execution_authorized=True,
            )

    def test_containment_blocks_without_policy_expansion(self):
        state = self.state()
        baseline = ContextualBaseline(
            context_hash=state.context_hash,
            anomaly_threshold=2,
            containment_threshold=3,
        )
        _, disposition = baseline.compare(3, logs_complete=True)

        self.assertTrue(disposition.blocked)
        self.assertFalse(disposition.execution_allowed)
        self.assertFalse(disposition.policy_expansion)
        self.assertEqual("none", disposition.authority_effect)
        self.assertLessEqual(
            set(disposition.containment_scope),
            set(disposition.evidence_scope),
        )
        with self.assertRaisesRegex(
            BehavioralGovernanceError,
            "containment_cannot_expand_policy",
        ):
            ContainmentDisposition(
                action="block",
                reason="invalid_expansion",
                evidence_scope=(state.context_hash,),
                containment_scope=(state.context_hash,),
                policy_expansion=True,
            )

    def test_rejected_unknown_never_reaches_executor_or_provider_callback(self):
        provider_callback = Mock(side_effect=AssertionError("provider reached"))
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=b"adaptive-governance-test",
            clock=lambda: 2_000_000,
        )
        intent = Intent(
            "agent:builder",
            "unknown.action",
            "repo:pulpo",
            0,
            "session-1",
        )

        decision = kernel.evaluate(intent)
        if decision.outcome == "allow":
            provider_callback()
        else:
            chain = BehaviorChain.from_rejected_unknown(
                self.state(),
                sequence=1,
                rejection_reason=decision.reason,
            )

        self.assertEqual("deny", decision.outcome)
        self.assertIsNone(decision.permit)
        provider_callback.assert_not_called()
        self.assertFalse(chain.baseline.execution_attempted)
        self.assertFalse(chain.containment.execution_allowed)

    def test_high_cardinality_context_is_bounded(self):
        chain = BehaviorChain.from_rejected_unknown(
            self.state(worker_source="worker:0"),
            sequence=1,
            checkpoint_after_deltas=2,
            max_contexts=3,
            micro_variation_limit=100,
        )
        for sequence in range(2, 5):
            chain = chain.record_rejected_unknown(
                self.state(worker_source=f"worker:{sequence - 1}"),
                sequence=sequence,
            )

        self.assertEqual(3, len(chain.seen_context_hashes))
        self.assertEqual("context_overflow", chain.last_signal.classification)
        self.assertTrue(chain.containment.blocked)
        self.assertEqual(1, chain.suppressed_count)
        self.assertLess(
            len(chain.active_deltas),
            chain.checkpoint_after_deltas,
        )
        self.assertLessEqual(chain.detailed_event_count, 1 + chain.checkpoint_after_deltas)

    def test_micro_variation_delta_flood_is_bounded_and_escalated(self):
        chain = BehaviorChain.from_rejected_unknown(
            self.state(),
            sequence=1,
            checkpoint_after_deltas=2,
            micro_variation_limit=4,
        )
        for sequence in range(2, 6):
            chain = chain.record_rejected_unknown(
                self.state(request_shape=f"unknown-operation:v{sequence}"),
                sequence=sequence,
            )

        self.assertEqual("delta_flood", chain.last_signal.classification)
        self.assertTrue(chain.containment.blocked)
        self.assertIsNotNone(chain.checkpoint)
        self.assertLess(
            len(chain.active_deltas),
            chain.checkpoint_after_deltas,
        )
        retained_records = chain.detailed_event_count

        for sequence in range(6, 106):
            chain = chain.record_rejected_unknown(
                self.state(request_shape=f"noise:{sequence}"),
                sequence=sequence,
            )

        self.assertEqual(retained_records, chain.detailed_event_count)
        self.assertEqual(100, chain.suppressed_count)
        self.assertTrue(chain.containment.blocked)

    def test_missing_logs_are_unknown_not_safe(self):
        state = self.state()
        baseline = ContextualBaseline(
            context_hash=state.context_hash,
            anomaly_threshold=2,
            containment_threshold=4,
        )

        signal, disposition = compare_contextual_baselines(
            state,
            (baseline,),
            observed_unknowns=0,
            logs_complete=False,
        )

        self.assertEqual("unknown", signal.classification)
        self.assertEqual("unknown", signal.safety)
        self.assertIsNone(signal.score)
        self.assertFalse(signal.is_safe)
        self.assertFalse(signal.execution_authorized)
        self.assertTrue(disposition.blocked)
        self.assertEqual("behavior_logs_missing", disposition.reason)


if __name__ == "__main__":
    unittest.main()

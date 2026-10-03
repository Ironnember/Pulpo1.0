import sqlite3
from contextlib import closing
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from pulpo.effect_authority import (
    AggregateConsequenceAuthority,
    AggregateConsequenceViolation,
    ConsequenceVector,
    EffectAuthorityEnvelope,
    RemoteEffect,
    SQLiteAggregateConsequenceBudget,
    authorize_remote_effect_attempt_with_aggregate,
    bind_resource_to_effect_authority,
    reconcile_remote_effect,
)
from pulpo.execution_context import ExecutionContext, bind_resource_to_execution_context
from pulpo.kernel import GovernanceKernel, Intent, Policy

NOW = 12_000_000


class RollingAggregateConsequenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'governance.sqlite3'
        self.context = ExecutionContext(
            'github', 'repo:Ironnember/Pulpo1.0',
            principal='human:owner', connection='chatgpt-github',
        )
        self.aggregate = AggregateConsequenceAuthority(
            sequence_id='github-reconcile-sequence-v0',
            principal='agent:assistant', session_id='aggregate-proof',
            surface='github',
            authority_scope='repo:Ironnember/Pulpo1.0',
            ceiling=ConsequenceVector(mutations=3, notifications=1, compute_units=3, spend_cents=500),
            expires_at_ns=NOW + 100_000,
        )
        self.budget = SQLiteAggregateConsequenceBudget(self.path, self.aggregate)
        self.kernel = GovernanceKernel(Policy(frozenset({'remote_write'}), 0))

    def effect(self, index: int, *, operation='update_ref') -> RemoteEffect:
        return RemoteEffect(
            surface='github', authority_scope='repo:Ironnember/Pulpo1.0',
            operation=operation, resource=f'refs/heads/proof/aggregate-{index}',
            expected_pre_state=(f'{index:x}' * 40)[:40],
            desired_post_state=(f'{index + 1:x}' * 40)[:40],
            parameters=(('force', 'false'),),
        )

    def envelope(self, effect: RemoteEffect, consequence=None, aggregate=None):
        consequence = consequence or ConsequenceVector(mutations=1, compute_units=1)
        aggregate = aggregate or self.aggregate
        return EffectAuthorityEnvelope(
            effect=effect,
            allowed_derived_effects=('github_actions_trigger',),
            planned_consequence=consequence,
            consequence_ceiling=consequence,
            expires_at_ns=NOW + 10_000,
            aggregate_authority=aggregate,
        )

    def intent_and_permit(self, envelope):
        resource = bind_resource_to_effect_authority('github:aggregate-proof', envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = Intent('agent:assistant', 'remote_write', resource, 0, 'aggregate-proof')
        decision = self.kernel.evaluate(intent)
        self.assertEqual('allow', decision.outcome)
        return intent, decision.permit

    def authorize(self, envelope, effect, intent, permit, budget=None, consequence=None):
        consequence = consequence or envelope.planned_consequence
        return authorize_remote_effect_attempt_with_aggregate(
            self.kernel, permit, intent, envelope, effect, self.context,
            budget or self.budget,
            observed_pre_state=effect.expected_pre_state,
            requested_derived_effects=('github_actions_trigger',),
            requested_consequence=consequence,
            now_ns=NOW,
        )

    def test_01_three_separate_permits_share_one_durable_ceiling(self):
        for index in range(3):
            effect = self.effect(index)
            envelope = self.envelope(effect)
            intent, permit = self.intent_and_permit(envelope)
            result = self.authorize(envelope, effect, intent, permit)
            self.assertEqual(('allow', True, True), (result.outcome, result.permit_consumed, result.execution_authorized))
        self.assertEqual(ConsequenceVector(mutations=3, compute_units=3), self.budget.used)

    def test_02_fourth_separate_permit_denied_before_consumption_when_ceiling_already_full(self):
        self.test_01_three_separate_permits_share_one_durable_ceiling()
        effect = self.effect(3)
        envelope = self.envelope(effect)
        intent, permit = self.intent_and_permit(envelope)
        result = self.authorize(envelope, effect, intent, permit)
        self.assertEqual(('deny', False, False), (result.outcome, result.permit_consumed, result.execution_authorized))
        self.assertIn('aggregate_ceiling_exceeded:mutations,compute_units', result.reason)
        self.assertTrue(self.kernel.consume(permit, intent))

    def test_03_restart_preserves_aggregate_usage_and_denies_overrun(self):
        for index in range(2):
            effect = self.effect(index)
            envelope = self.envelope(effect)
            intent, permit = self.intent_and_permit(envelope)
            self.assertTrue(self.authorize(envelope, effect, intent, permit).execution_authorized)
        restarted = SQLiteAggregateConsequenceBudget(self.path, self.aggregate)
        self.assertEqual(2, restarted.used.mutations)
        effect = self.effect(2)
        envelope = self.envelope(effect)
        intent, permit = self.intent_and_permit(envelope)
        self.assertTrue(self.authorize(envelope, effect, intent, permit, restarted).execution_authorized)
        second_restart = SQLiteAggregateConsequenceBudget(self.path, self.aggregate)
        effect = self.effect(3)
        envelope = self.envelope(effect)
        intent, permit = self.intent_and_permit(envelope)
        denied = self.authorize(envelope, effect, intent, permit, second_restart)
        self.assertFalse(denied.execution_authorized)
        self.assertEqual(3, second_restart.used.mutations)

    def test_04_concurrent_permits_never_overrun_ceiling(self):
        barrier = threading.Barrier(5)
        results = []
        lock = threading.Lock()

        def worker(index):
            effect = self.effect(index)
            envelope = self.envelope(effect)
            intent, permit = self.intent_and_permit(envelope)
            barrier.wait()
            result = self.authorize(envelope, effect, intent, permit)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(5, len(results))
        self.assertEqual(3, sum(result.execution_authorized for result in results))
        self.assertEqual(3, self.budget.used.mutations)
        self.assertTrue(all(not r.execution_authorized for r in results if r.outcome == 'deny'))

    def test_05_duplicate_effect_cannot_consume_aggregate_twice(self):
        effect = self.effect(0)
        first = self.envelope(effect)
        intent, permit = self.intent_and_permit(first)
        self.assertTrue(self.authorize(first, effect, intent, permit).execution_authorized)
        second = self.envelope(effect)
        intent2, permit2 = self.intent_and_permit(second)
        denied = self.authorize(second, effect, intent2, permit2)
        self.assertEqual(('deny', False, False), (denied.outcome, denied.permit_consumed, denied.execution_authorized))
        self.assertEqual('aggregate_effect_already_counted', denied.reason)
        self.assertTrue(self.kernel.consume(permit2, intent2))

    def test_06_multidimensional_ceiling_is_enforced(self):
        consequence = ConsequenceVector(mutations=1, notifications=1, compute_units=1, spend_cents=300)
        effect = self.effect(0)
        envelope = self.envelope(effect, consequence)
        intent, permit = self.intent_and_permit(envelope)
        self.assertTrue(self.authorize(envelope, effect, intent, permit, consequence=consequence).execution_authorized)
        effect2 = self.effect(1)
        envelope2 = self.envelope(effect2, consequence)
        intent2, permit2 = self.intent_and_permit(envelope2)
        denied = self.authorize(envelope2, effect2, intent2, permit2, consequence=consequence)
        self.assertIn('notifications', denied.reason)
        self.assertIn('spend_cents', denied.reason)
        self.assertFalse(denied.permit_consumed)

    def test_07_aggregate_authority_is_cryptographically_part_of_effect_envelope(self):
        effect = self.effect(0)
        envelope = self.envelope(effect)
        wider = replace(self.aggregate, ceiling=ConsequenceVector(mutations=4, notifications=1, compute_units=4, spend_cents=500))
        tampered = replace(envelope, aggregate_authority=wider)
        self.assertNotEqual(envelope.envelope_hash, tampered.envelope_hash)

    def test_08_budget_authority_mismatch_denies_without_spending_permit(self):
        effect = self.effect(0)
        envelope = self.envelope(effect)
        intent, permit = self.intent_and_permit(envelope)
        other = AggregateConsequenceAuthority(
            sequence_id='other-sequence', principal='agent:assistant', session_id='aggregate-proof', surface='github', authority_scope='repo:Ironnember/Pulpo1.0',
            ceiling=ConsequenceVector(mutations=3, compute_units=3), expires_at_ns=NOW + 100_000,
        )
        other_path = Path(self.temp.name) / 'other.sqlite3'
        other_budget = SQLiteAggregateConsequenceBudget(other_path, other)
        result = self.authorize(envelope, effect, intent, permit, other_budget)
        self.assertEqual(('deny', 'aggregate_budget_authority_mismatch', False), (result.outcome, result.reason, result.permit_consumed))
        self.assertTrue(self.kernel.consume(permit, intent))

    def test_09_expired_aggregate_authority_denies_before_permit_consumption(self):
        expired = replace(self.aggregate, sequence_id='expired', expires_at_ns=NOW)
        path = Path(self.temp.name) / 'expired.sqlite3'
        budget = SQLiteAggregateConsequenceBudget(path, expired)
        effect = self.effect(0)
        envelope = EffectAuthorityEnvelope(
            effect=effect, allowed_derived_effects=('github_actions_trigger',),
            planned_consequence=ConsequenceVector(mutations=1),
            consequence_ceiling=ConsequenceVector(mutations=1),
            expires_at_ns=NOW,
            aggregate_authority=expired,
        )
        # Envelope expiry and aggregate expiry coincide; aggregate preflight must fail closed.
        intent, permit = self.intent_and_permit(envelope)
        result = self.authorize(envelope, effect, intent, permit, budget, ConsequenceVector(mutations=1))
        self.assertEqual(('deny', 'aggregate_authority_expired', False), (result.outcome, result.reason, result.permit_consumed))

    def test_10_unknown_provider_outcome_does_not_refund_aggregate_capacity(self):
        one = replace(self.aggregate, sequence_id='one-shot', ceiling=ConsequenceVector(mutations=1, compute_units=1))
        path = Path(self.temp.name) / 'oneshot.sqlite3'
        budget = SQLiteAggregateConsequenceBudget(path, one)
        effect = self.effect(0)
        envelope = self.envelope(effect, aggregate=one)
        intent, permit = self.intent_and_permit(envelope)
        self.assertTrue(self.authorize(envelope, effect, intent, permit, budget).execution_authorized)
        unknown = reconcile_remote_effect(envelope, provider_outcome='unknown', observed_post_state=None, observed_derived_effects=('github_actions_trigger',))
        self.assertEqual('uncertain', unknown.status)
        effect2 = self.effect(1)
        envelope2 = self.envelope(effect2, aggregate=one)
        intent2, permit2 = self.intent_and_permit(envelope2)
        denied = self.authorize(envelope2, effect2, intent2, permit2, budget)
        self.assertFalse(denied.execution_authorized)
        self.assertEqual(1, budget.used.mutations)

    def test_11_compensation_is_a_new_effect_and_consumes_new_aggregate_capacity(self):
        cap = replace(self.aggregate, sequence_id='compensation', ceiling=ConsequenceVector(mutations=1, compute_units=1))
        path = Path(self.temp.name) / 'comp.sqlite3'
        budget = SQLiteAggregateConsequenceBudget(path, cap)
        original = self.effect(0)
        envelope = self.envelope(original, aggregate=cap)
        intent, permit = self.intent_and_permit(envelope)
        self.assertTrue(self.authorize(envelope, original, intent, permit, budget).execution_authorized)
        compensation = replace(original, expected_pre_state=original.desired_post_state, desired_post_state=original.expected_pre_state)
        comp_envelope = self.envelope(compensation, aggregate=cap)
        comp_intent, comp_permit = self.intent_and_permit(comp_envelope)
        denied = self.authorize(comp_envelope, compensation, comp_intent, comp_permit, budget)
        self.assertFalse(denied.execution_authorized)
        self.assertFalse(denied.permit_consumed)

    def test_12_same_sequence_id_cannot_be_reopened_with_wider_authority(self):
        widened = replace(self.aggregate, ceiling=ConsequenceVector(mutations=99, notifications=99, compute_units=99, spend_cents=99999))
        with self.assertRaisesRegex(AggregateConsequenceViolation, 'aggregate_authority_mismatch'):
            SQLiteAggregateConsequenceBudget(self.path, widened)

    def test_13_persisted_authority_tamper_is_detected_on_reopen(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute('UPDATE effect_aggregate_authority SET mutations = 99 WHERE sequence_id = ?', (self.aggregate.sequence_id,))
            connection.commit()
        with self.assertRaisesRegex(AggregateConsequenceViolation, 'aggregate_authority_mismatch'):
            SQLiteAggregateConsequenceBudget(self.path, self.aggregate)

    def test_14_effect_scope_and_surface_must_fit_aggregate_authority(self):
        wrong_surface = replace(self.effect(0), surface='slack')
        with self.assertRaisesRegex(ValueError, 'aggregate_effect_surface_mismatch'):
            self.envelope(wrong_surface)
        wrong_scope = replace(self.effect(0), authority_scope='repo:Ironnember/Other')
        with self.assertRaisesRegex(ValueError, 'aggregate_effect_scope_mismatch'):
            self.envelope(wrong_scope)

    def test_15_effect_authority_cannot_outlive_aggregate_authority(self):
        short = replace(self.aggregate, sequence_id='short', expires_at_ns=NOW + 5)
        effect = self.effect(0)
        with self.assertRaisesRegex(ValueError, 'effect_authority_outlives_aggregate_authority'):
            EffectAuthorityEnvelope(
                effect=effect, allowed_derived_effects=(),
                planned_consequence=ConsequenceVector(mutations=1),
                consequence_ceiling=ConsequenceVector(mutations=1),
                expires_at_ns=NOW + 10, aggregate_authority=short,
            )

    def test_16_receipt_binds_authority_effect_permit_and_aggregate_after(self):
        effect = self.effect(0)
        envelope = self.envelope(effect)
        intent, permit = self.intent_and_permit(envelope)
        result = self.authorize(envelope, effect, intent, permit)
        receipt = result.aggregate_receipt
        self.assertIsNotNone(receipt)
        self.assertEqual(self.aggregate.authority_hash, receipt.authority_hash)
        self.assertEqual(effect.effect_hash, receipt.effect_hash)
        self.assertEqual(64, len(receipt.permit_hash))
        self.assertEqual(64, len(receipt.receipt_hash))
        self.assertEqual(ConsequenceVector(mutations=1, compute_units=1), receipt.aggregate_after)

    def test_17_missing_aggregate_authority_fails_before_permit_consumption(self):
        effect = self.effect(0)
        envelope = self.envelope(effect, aggregate=None)
        # Build an explicit envelope without the aggregate authority.
        envelope = replace(envelope, aggregate_authority=None)
        resource = bind_resource_to_effect_authority('github:no-aggregate', envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = Intent('agent:assistant', 'remote_write', resource, 0, 'aggregate-proof')
        permit = self.kernel.evaluate(intent).permit
        result = authorize_remote_effect_attempt_with_aggregate(
            self.kernel, permit, intent, envelope, effect, self.context, self.budget,
            observed_pre_state=effect.expected_pre_state,
            requested_consequence=envelope.planned_consequence, now_ns=NOW,
        )
        self.assertEqual(('deny', 'aggregate_authority_missing', False), (result.outcome, result.reason, result.permit_consumed))
        self.assertTrue(self.kernel.consume(permit, intent))

    def test_18_unavailable_budget_path_fails_closed(self):
        missing = Path(self.temp.name) / 'missing-parent' / 'budget.sqlite3'
        with self.assertRaisesRegex(AggregateConsequenceViolation, 'aggregate_budget_parent_missing'):
            SQLiteAggregateConsequenceBudget(missing, self.aggregate)


    def test_19_budget_failure_after_permit_consumption_denies_external_effect_and_replay(self):
        effect = self.effect(0)
        envelope = self.envelope(effect)
        intent, permit = self.intent_and_permit(envelope)

        class FailingAfterPreflight:
            authority = self.budget.authority
            def preflight(inner, *args, **kwargs):
                return self.budget.preflight(*args, **kwargs)
            def record_attempt(inner, *args, **kwargs):
                raise AggregateConsequenceViolation('aggregate_budget_unavailable')

        result = self.authorize(envelope, effect, intent, permit, FailingAfterPreflight())
        self.assertEqual(
            ('deny', 'aggregate_budget_unavailable:permit_spent', True, False),
            (result.outcome, result.reason, result.permit_consumed, result.execution_authorized),
        )
        self.assertFalse(self.kernel.consume(permit, intent))
        self.assertEqual(0, self.budget.used.mutations)

    def test_20_aggregate_principal_mismatch_denies_before_permit_consumption(self):
        effect = self.effect(0)
        envelope = self.envelope(effect)
        resource = bind_resource_to_effect_authority('github:principal-mismatch', envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = Intent('agent:other', 'remote_write', resource, 0, 'aggregate-proof')
        permit = self.kernel.evaluate(intent).permit
        result = authorize_remote_effect_attempt_with_aggregate(
            self.kernel, permit, intent, envelope, effect, self.context, self.budget,
            observed_pre_state=effect.expected_pre_state,
            requested_consequence=envelope.planned_consequence, now_ns=NOW,
        )
        self.assertEqual(('deny', 'aggregate_principal_mismatch', False), (result.outcome, result.reason, result.permit_consumed))
        self.assertTrue(self.kernel.consume(permit, intent))

    def test_21_aggregate_session_mismatch_denies_before_permit_consumption(self):
        effect = self.effect(0)
        envelope = self.envelope(effect)
        resource = bind_resource_to_effect_authority('github:session-mismatch', envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = Intent('agent:assistant', 'remote_write', resource, 0, 'other-session')
        permit = self.kernel.evaluate(intent).permit
        result = authorize_remote_effect_attempt_with_aggregate(
            self.kernel, permit, intent, envelope, effect, self.context, self.budget,
            observed_pre_state=effect.expected_pre_state,
            requested_consequence=envelope.planned_consequence, now_ns=NOW,
        )
        self.assertEqual(('deny', 'aggregate_session_mismatch', False), (result.outcome, result.reason, result.permit_consumed))
        self.assertTrue(self.kernel.consume(permit, intent))


if __name__ == '__main__':
    unittest.main()

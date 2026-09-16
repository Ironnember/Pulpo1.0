import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from pulpo.effect_authority import (
    ConsequenceVector,
    EffectAuthorityEnvelope,
    RemoteEffect,
    bind_resource_to_effect_authority,
    consume_remote_effect_permit,
    evaluate_sequence_ceiling,
    reconcile_remote_effect,
    required_effect_authority_hash,
    verify_effect_authority,
)
from pulpo.execution_context import ExecutionContext, bind_resource_to_execution_context
from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.state import SQLiteKernelState


NOW = 9_000_000
OLD_SHA = "a" * 40
NEW_SHA = "b" * 40
OTHER_SHA = "c" * 40


class RemoteEffectAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.context = ExecutionContext(
            "github",
            "repo:Ironnember/Pulpo1.0",
            principal="human:owner",
            connection="chatgpt-github",
        )
        self.effect = RemoteEffect(
            surface="github",
            authority_scope="repo:Ironnember/Pulpo1.0",
            operation="update_ref",
            resource="refs/heads/proof/effect-authority-v0",
            expected_pre_state=OLD_SHA,
            desired_post_state=NEW_SHA,
            parameters=(("force", "false"),),
        )
        self.consequence = ConsequenceVector(mutations=1, compute_units=1)
        self.envelope = EffectAuthorityEnvelope(
            effect=self.effect,
            allowed_derived_effects=("github_actions_trigger", "review_invalidation"),
            planned_consequence=self.consequence,
            consequence_ceiling=ConsequenceVector(mutations=1, compute_units=1),
            expires_at_ns=NOW + 10_000,
        )
        resource = bind_resource_to_effect_authority("github:branch-reconcile", self.envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        self.intent = Intent("agent:assistant", "remote_write", resource, 0, "effect-proof")
        self.kernel = GovernanceKernel(
            Policy(frozenset({"remote_write"}), 0),
            secret=b"remote-effect-proof-secret",
            clock=lambda: NOW,
        )

    def _permit(self):
        decision = self.kernel.evaluate(self.intent)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit

    def _consume(self, permit, **changes):
        values = {
            "kernel": self.kernel,
            "permit": permit,
            "intent": self.intent,
            "envelope": self.envelope,
            "requested_effect": self.effect,
            "observed_context": self.context,
            "observed_pre_state": OLD_SHA,
            "requested_derived_effects": ("github_actions_trigger",),
            "requested_consequence": self.consequence,
            "now_ns": NOW,
            "observation_complete": True,
        }
        values.update(changes)
        return consume_remote_effect_permit(**values)

    def test_01_exact_repo_branch_sha_parameters_context_and_consequence_consume_once(self):
        permit = self._permit()
        check, consumed = self._consume(permit)
        self.assertEqual(("allow", "exact_effect_authority_match", True), (check.outcome, check.reason, consumed))
        replay, replayed = self._consume(permit)
        self.assertEqual(("deny", "permit_unavailable_or_replayed", False), (replay.outcome, replay.reason, replayed))

    def test_02_wrong_repository_denies_before_permit_consumption(self):
        permit = self._permit()
        wrong = replace(self.effect, authority_scope="repo:Ironnember/Other")
        check, consumed = self._consume(permit, requested_effect=wrong)
        self.assertEqual(("deny", "effect_authority_scope_mismatch", False), (check.outcome, check.reason, consumed))
        self.assertTrue(self._consume(permit)[1])

    def test_03_wrong_branch_denies_before_permit_consumption(self):
        permit = self._permit()
        wrong = replace(self.effect, resource="refs/heads/main")
        check, consumed = self._consume(permit, requested_effect=wrong)
        self.assertEqual(("deny", "effect_resource_mismatch", False), (check.outcome, check.reason, consumed))
        self.assertTrue(self._consume(permit)[1])

    def test_04_branch_head_race_denies_before_permit_consumption(self):
        permit = self._permit()
        check, consumed = self._consume(permit, observed_pre_state=OTHER_SHA)
        self.assertEqual(("deny", "pre_state_mismatch", False), (check.outcome, check.reason, consumed))
        self.assertTrue(self._consume(permit)[1])

    def test_05_force_push_parameter_substitution_denies(self):
        permit = self._permit()
        wrong = replace(self.effect, parameters=(("force", "true"),))
        check, consumed = self._consume(permit, requested_effect=wrong)
        self.assertEqual(("deny", "effect_parameters_mismatch", False), (check.outcome, check.reason, consumed))

    def test_06_wrong_execution_context_denies_before_permit_consumption(self):
        permit = self._permit()
        wrong_context = replace(self.context, authority_scope="repo:Ironnember/Other")
        check, consumed = self._consume(permit, observed_context=wrong_context)
        self.assertEqual(("deny", "execution_context_mismatch", False), (check.outcome, check.reason, consumed))
        self.assertTrue(self._consume(permit)[1])

    def test_07_unstructured_or_ambiguous_instruction_cannot_cross_remote_write_boundary(self):
        plain = Intent("agent:assistant", "remote_write", "github:continue-our-work", 0, "effect-proof")
        decision = self.kernel.evaluate(plain)
        self.assertEqual("allow", decision.outcome)  # policy alone is intentionally insufficient here
        check, consumed = consume_remote_effect_permit(
            self.kernel,
            decision.permit,
            plain,
            None,
            None,
            self.context,
            observed_pre_state=OLD_SHA,
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("deny", "effect_authority_binding_missing", False), (check.outcome, check.reason, consumed))

    def test_08_missing_pre_execution_observation_is_uncertain_and_does_not_spend_permit(self):
        permit = self._permit()
        check, consumed = self._consume(permit, observed_pre_state=None)
        self.assertEqual(("uncertain", "pre_state_observation_missing", False), (check.outcome, check.reason, consumed))
        self.assertTrue(self._consume(permit)[1])

    def test_09_expired_effect_authority_denies_without_spending_permit(self):
        permit = self._permit()
        check, consumed = self._consume(permit, now_ns=self.envelope.expires_at_ns)
        self.assertEqual(("deny", "effect_authority_expired", False), (check.outcome, check.reason, consumed))

    def test_10_undeclared_ci_consequence_denies_before_permit_consumption(self):
        strict = replace(self.envelope, allowed_derived_effects=())
        resource = bind_resource_to_effect_authority("github:branch-reconcile", strict)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = replace(self.intent, resource=resource)
        permit = self.kernel.evaluate(intent).permit
        check, consumed = consume_remote_effect_permit(
            self.kernel,
            permit,
            intent,
            strict,
            self.effect,
            self.context,
            observed_pre_state=OLD_SHA,
            requested_derived_effects=("github_actions_trigger",),
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("deny", "derived_effect_not_authorized", False), (check.outcome, check.reason, consumed))

    def test_11_human_notification_escalation_denies(self):
        permit = self._permit()
        check, consumed = self._consume(
            permit,
            requested_derived_effects=("github_actions_trigger", "human_notification"),
        )
        self.assertEqual(("deny", "derived_effect_not_authorized", False), (check.outcome, check.reason, consumed))

    def test_12_consequence_understatement_or_drift_denies(self):
        permit = self._permit()
        drifted = ConsequenceVector(mutations=1, compute_units=0)
        check, consumed = self._consume(permit, requested_consequence=drifted)
        self.assertEqual(("deny", "consequence_plan_mismatch", False), (check.outcome, check.reason, consumed))

    def test_13_envelope_tamper_changes_intent_binding_and_denies(self):
        permit = self._permit()
        tampered = replace(self.envelope, expires_at_ns=self.envelope.expires_at_ns + 1)
        check, consumed = self._consume(permit, envelope=tampered)
        self.assertEqual(("deny", "effect_authority_envelope_mismatch", False), (check.outcome, check.reason, consumed))

    def test_14_original_authority_does_not_authorize_compensation(self):
        permit = self._permit()
        compensation = replace(
            self.effect,
            expected_pre_state=NEW_SHA,
            desired_post_state=OLD_SHA,
        )
        check, consumed = self._consume(
            permit,
            requested_effect=compensation,
            observed_pre_state=NEW_SHA,
        )
        self.assertEqual(("deny", "effect_expected_pre_state_mismatch", False), (check.outcome, check.reason, consumed))

    def test_15_compensation_requires_a_fresh_exact_permit(self):
        original_permit = self._permit()
        self.assertTrue(self._consume(original_permit)[1])

        compensation_effect = replace(
            self.effect,
            expected_pre_state=NEW_SHA,
            desired_post_state=OLD_SHA,
        )
        compensation_envelope = replace(self.envelope, effect=compensation_effect)
        resource = bind_resource_to_effect_authority("github:branch-compensation", compensation_envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        compensation_intent = replace(self.intent, resource=resource)

        check, consumed = consume_remote_effect_permit(
            self.kernel,
            original_permit,
            compensation_intent,
            compensation_envelope,
            compensation_effect,
            self.context,
            observed_pre_state=NEW_SHA,
            requested_derived_effects=("github_actions_trigger",),
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("deny", "permit_unavailable_or_replayed", False), (check.outcome, check.reason, consumed))

        fresh = self.kernel.evaluate(compensation_intent)
        self.assertEqual("allow", fresh.outcome)
        check, consumed = consume_remote_effect_permit(
            self.kernel,
            fresh.permit,
            compensation_intent,
            compensation_envelope,
            compensation_effect,
            self.context,
            observed_pre_state=NEW_SHA,
            requested_derived_effects=("github_actions_trigger",),
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("allow", True), (check.outcome, consumed))

    def test_16_spent_effect_authority_stays_spent_across_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            state = SQLiteKernelState(path)
            kernel = GovernanceKernel(
                Policy(frozenset({"remote_write"}), 0),
                secret=b"restart-secret",
                clock=lambda: NOW,
                state=state,
            )
            decision = kernel.evaluate(self.intent)
            self.assertEqual("allow", decision.outcome)
            check, consumed = consume_remote_effect_permit(
                kernel,
                decision.permit,
                self.intent,
                self.envelope,
                self.effect,
                self.context,
                observed_pre_state=OLD_SHA,
                requested_derived_effects=("github_actions_trigger",),
                requested_consequence=self.consequence,
                now_ns=NOW,
            )
            self.assertEqual(("allow", True), (check.outcome, consumed))
            state.close()

            restarted_state = SQLiteKernelState(path)
            restarted = GovernanceKernel(
                Policy(frozenset({"remote_write"}), 0),
                secret=b"restart-secret",
                clock=lambda: NOW,
                state=restarted_state,
            )
            check, consumed = consume_remote_effect_permit(
                restarted,
                decision.permit,
                self.intent,
                self.envelope,
                self.effect,
                self.context,
                observed_pre_state=OLD_SHA,
                requested_derived_effects=("github_actions_trigger",),
                requested_consequence=self.consequence,
                now_ns=NOW,
            )
            self.assertEqual(("deny", "permit_unavailable_or_replayed", False), (check.outcome, check.reason, consumed))
            self.assertTrue(restarted.verify_audit())
            restarted_state.close()

    def test_17_provider_commit_unknown_is_uncertain_and_never_authorizes_retry(self):
        permit = self._permit()
        self.assertTrue(self._consume(permit)[1])
        reconciliation = reconcile_remote_effect(
            self.envelope,
            provider_outcome="unknown",
            observed_post_state=None,
            observed_derived_effects=("github_actions_trigger",),
        )
        self.assertEqual(("uncertain", "provider_commit_outcome_unknown"), (reconciliation.status, reconciliation.reason))
        retry, consumed = self._consume(permit)
        self.assertEqual(("deny", "permit_unavailable_or_replayed", False), (retry.outcome, retry.reason, consumed))

    def test_18_unexpected_post_execution_derived_effect_is_mismatch(self):
        reconciliation = reconcile_remote_effect(
            self.envelope,
            provider_outcome="succeeded",
            observed_post_state=NEW_SHA,
            observed_derived_effects=("github_actions_trigger", "human_notification"),
        )
        self.assertEqual(("mismatch", "unexpected_derived_effect"), (reconciliation.status, reconciliation.reason))

    def test_19_exact_post_execution_state_reconciles_verified(self):
        reconciliation = reconcile_remote_effect(
            self.envelope,
            provider_outcome="succeeded",
            observed_post_state=NEW_SHA,
            observed_derived_effects=("github_actions_trigger",),
        )
        self.assertEqual(("verified", "remote_effect_verified"), (reconciliation.status, reconciliation.reason))

    def test_20_low_severity_effects_cannot_compose_past_sequence_ceiling(self):
        envelopes = []
        for index in range(5):
            effect = replace(
                self.effect,
                resource=f"refs/heads/proof/effect-{index}",
                expected_pre_state=(str(index) * 40)[:40],
                desired_post_state=(str(index + 1) * 40)[:40],
            )
            envelopes.append(replace(self.envelope, effect=effect))
        result = evaluate_sequence_ceiling(
            envelopes,
            ConsequenceVector(mutations=3, compute_units=5),
        )
        self.assertEqual("deny", result.outcome)
        self.assertIn("mutations", result.reason)
        self.assertEqual(5, result.aggregate.mutations)

    def test_21_sequence_within_all_consequence_dimensions_is_allowed(self):
        first = self.envelope
        second_effect = replace(
            self.effect,
            resource="refs/heads/proof/effect-authority-v1",
            expected_pre_state=NEW_SHA,
            desired_post_state=OTHER_SHA,
        )
        second = replace(self.envelope, effect=second_effect)
        result = evaluate_sequence_ceiling(
            (first, second),
            ConsequenceVector(mutations=2, compute_units=2),
        )
        self.assertEqual(("allow", "sequence_within_ceiling"), (result.outcome, result.reason))

    def test_22_duplicate_effect_in_sequence_is_denied(self):
        result = evaluate_sequence_ceiling(
            (self.envelope, self.envelope),
            ConsequenceVector(mutations=2, compute_units=2),
        )
        self.assertEqual(("deny", "sequence_duplicate_effect"), (result.outcome, result.reason))

    def test_23_binding_hash_is_carried_inside_context_bound_intent(self):
        self.assertEqual(self.envelope.envelope_hash, required_effect_authority_hash(self.intent.resource))
        check = verify_effect_authority(
            self.intent,
            self.envelope,
            self.effect,
            observed_pre_state=OLD_SHA,
            requested_derived_effects=("github_actions_trigger",),
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("allow", "exact_effect_authority_match"), (check.outcome, check.reason))

    def test_24_effect_scope_must_match_bound_execution_context_scope(self):
        mismatched_effect = replace(self.effect, authority_scope="repo:Ironnember/Other")
        mismatched_envelope = replace(self.envelope, effect=mismatched_effect)
        resource = bind_resource_to_effect_authority("github:branch-reconcile", mismatched_envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = replace(self.intent, resource=resource)
        permit = self.kernel.evaluate(intent).permit
        check, consumed = consume_remote_effect_permit(
            self.kernel,
            permit,
            intent,
            mismatched_envelope,
            mismatched_effect,
            self.context,
            observed_pre_state=OLD_SHA,
            requested_derived_effects=("github_actions_trigger",),
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("deny", "effect_context_scope_mismatch", False), (check.outcome, check.reason, consumed))

    def test_25_effect_surface_must_match_bound_execution_context_surface(self):
        mismatched_effect = replace(self.effect, surface="slack")
        mismatched_envelope = replace(self.envelope, effect=mismatched_effect)
        resource = bind_resource_to_effect_authority("github:branch-reconcile", mismatched_envelope)
        resource = bind_resource_to_execution_context(resource, self.context)
        intent = replace(self.intent, resource=resource)
        permit = self.kernel.evaluate(intent).permit
        check, consumed = consume_remote_effect_permit(
            self.kernel,
            permit,
            intent,
            mismatched_envelope,
            mismatched_effect,
            self.context,
            observed_pre_state=OLD_SHA,
            requested_derived_effects=("github_actions_trigger",),
            requested_consequence=self.consequence,
            now_ns=NOW,
        )
        self.assertEqual(("deny", "effect_context_surface_mismatch", False), (check.outcome, check.reason, consumed))

    def test_26_separately_issued_permits_do_not_yet_share_a_rolling_sequence_ceiling(self):
        # This is an executable boundary finding, not a success claim.
        envelopes = []
        consumed_count = 0
        for index in range(4):
            effect = replace(
                self.effect,
                resource=f"refs/heads/proof/separate-{index}",
                expected_pre_state=(str(index) * 40)[:40],
                desired_post_state=(str(index + 1) * 40)[:40],
            )
            envelope = replace(self.envelope, effect=effect)
            envelopes.append(envelope)
            resource = bind_resource_to_effect_authority(f"github:separate-{index}", envelope)
            resource = bind_resource_to_execution_context(resource, self.context)
            intent = replace(self.intent, resource=resource)
            permit = self.kernel.evaluate(intent).permit
            check, consumed = consume_remote_effect_permit(
                self.kernel,
                permit,
                intent,
                envelope,
                effect,
                self.context,
                observed_pre_state=effect.expected_pre_state,
                requested_derived_effects=("github_actions_trigger",),
                requested_consequence=self.consequence,
                now_ns=NOW,
            )
            self.assertEqual("allow", check.outcome)
            consumed_count += int(consumed)

        aggregate = evaluate_sequence_ceiling(
            envelopes,
            ConsequenceVector(mutations=3, compute_units=4),
        )
        self.assertEqual(4, consumed_count)
        self.assertEqual("deny", aggregate.outcome)
        self.assertIn("mutations", aggregate.reason)


if __name__ == "__main__":
    unittest.main()

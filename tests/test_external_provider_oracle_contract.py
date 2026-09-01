from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import unittest

from tests.external_provider_oracle_contract import (
    AttackExecutionEvidence,
    ExternalObservedEffect,
    StageCContract,
    StageCContractError,
    StageCObservation,
    evaluate_stage_c,
)


ATTACKS = tuple(f"F{index:02d}" for index in range(1, 11))
ATTACK_VECTOR_SHA256 = "ff3edebf38171f5d0eb2b8bf0b9132fff89fb8272a9a27446c0bfb5b398d1c9e"
FREEZE_PATH = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "unauthorized-effect-stage-c-v0"
    / "freeze.json"
)


class StageCExternalProviderOracleContractTests(unittest.TestCase):
    def contract(self, **overrides) -> StageCContract:
        values = dict(
            benchmark_commit_sha="f9242eb67fe46eb201281e54f692a0cdc2d3b840",
            attack_vector_sha256=ATTACK_VECTOR_SHA256,
            attack_ids=ATTACKS,
            provider_id="provider://stage-c",
            provider_environment_id="sandbox://disposable-zero-cost",
            provider_effect_scope="scope://pulpo-stage-c-v0",
            known_good_effect_id="effect://calibration/known-good",
            allowed_observer_sources=("provider_read_api", "provider_audit_log"),
            authorized_measurement_effect_ids=(),
            required_external_provider=True,
            required_disposable_sandbox=True,
            required_zero_cost=True,
        )
        values.update(overrides)
        return StageCContract(**values)

    def attack_executions(self) -> tuple[AttackExecutionEvidence, ...]:
        return tuple(
            AttackExecutionEvidence(
                attack_id=attack_id,
                trial_id=f"trial://{attack_id}",
                action_object_sha256=sha256(f"action:{attack_id}".encode()).hexdigest(),
                adversarial_proposal_observed=True,
                pulpo_admission="deny",
                executor_transmission_observed=False,
                trial_evidence_sha256=sha256(f"trial:{attack_id}".encode()).hexdigest(),
            )
            for attack_id in ATTACKS
        )

    def observation(self, contract: StageCContract, **overrides) -> StageCObservation:
        values = dict(
            contract_hash=contract.contract_hash,
            observation_id="observation://stage-c/1",
            observer_id="principal://observer",
            executor_id="principal://executor",
            observer_principal_fingerprint="b" * 64,
            executor_principal_fingerprint="c" * 64,
            source_kind="provider_read_api",
            provider_effect_scope=contract.provider_effect_scope,
            observer_authenticated=True,
            observer_credential_exposed_to_worker=False,
            calibration_state="verified",
            calibration_effect_id=contract.known_good_effect_id,
            calibration_cleanup_verified=True,
            measurement_state="complete",
            observed_effects=(),
            pre_snapshot_sha256="d" * 64,
            post_snapshot_sha256="e" * 64,
            provider_evidence_sha256="f" * 64,
            provider_sequence_start=100,
            provider_sequence_end=200,
            attack_execution_state="complete",
            attack_executions=self.attack_executions(),
            attack_execution_evidence_sha256="1" * 64,
            matched_conversion_state="verified",
            matched_conversion_attack_id="F01",
            matched_conversion_effect_id="provider-effect://ablation/F01",
            matched_conversion_evidence_sha256="2" * 64,
            matched_conversion_cleanup_verified=True,
        )
        values.update(overrides)
        return StageCObservation(**values)

    def test_freeze_hash_matches_exact_ten_family_vector(self) -> None:
        freeze = json.loads(FREEZE_PATH.read_text())
        attack_vector = freeze["attack_vector"]
        canonical = json.dumps(
            attack_vector,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertEqual(sha256(canonical).hexdigest(), ATTACK_VECTOR_SHA256)
        self.assertEqual(freeze["attack_vector_sha256"], ATTACK_VECTOR_SHA256)
        self.assertEqual(tuple(item["id"] for item in attack_vector), ATTACKS)
        self.assertEqual(
            freeze["source_benchmark_head"],
            "f9242eb67fe46eb201281e54f692a0cdc2d3b840",
        )
        self.assertEqual(freeze["measurement_authorized_effects"], [])
        self.assertEqual(freeze["authority_effect"], "none")

    def test_complete_independent_observation_can_establish_zero(self) -> None:
        contract = self.contract()
        observation = self.observation(contract)

        result = evaluate_stage_c(contract, observation)

        self.assertEqual(result.outcome, "verified_zero_unauthorized")
        self.assertEqual(result.unauthorized_effect_rate, 0.0)
        self.assertEqual(result.attack_count, 10)
        self.assertEqual(result.executed_attack_count, 10)
        self.assertTrue(result.matched_conversion_verified)
        self.assertEqual(result.unauthorized_provider_effect_ids, ())
        self.assertEqual(result.authority_effect, "none")

    def test_empty_external_observation_without_attack_execution_cannot_establish_zero(self) -> None:
        contract = self.contract()
        result = evaluate_stage_c(
            contract,
            self.observation(
                contract,
                attack_executions=(),
                attack_execution_evidence_sha256="3" * 64,
            ),
        )

        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.reason, "attack_execution_coverage_incomplete")
        self.assertEqual(result.executed_attack_count, 0)
        self.assertIsNone(result.unauthorized_effect_rate)

    def test_missing_one_frozen_attack_execution_cannot_establish_zero(self) -> None:
        contract = self.contract()
        result = evaluate_stage_c(
            contract,
            self.observation(contract, attack_executions=self.attack_executions()[:-1]),
        )

        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.reason, "attack_execution_coverage_incomplete")
        self.assertEqual(result.executed_attack_count, 9)

    def test_unobserved_adversarial_proposal_cannot_establish_zero(self) -> None:
        contract = self.contract()
        executions = list(self.attack_executions())
        first = executions[0]
        executions[0] = AttackExecutionEvidence(
            attack_id=first.attack_id,
            trial_id=first.trial_id,
            action_object_sha256=first.action_object_sha256,
            adversarial_proposal_observed=False,
            pulpo_admission=first.pulpo_admission,
            executor_transmission_observed=first.executor_transmission_observed,
            trial_evidence_sha256=first.trial_evidence_sha256,
        )

        result = evaluate_stage_c(
            contract,
            self.observation(contract, attack_executions=tuple(executions)),
        )

        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.reason, "adversarial_attack_not_observed")

    def test_missing_matched_conversion_cannot_establish_zero(self) -> None:
        contract = self.contract()
        result = evaluate_stage_c(
            contract,
            self.observation(
                contract,
                matched_conversion_state="unknown",
                matched_conversion_attack_id=None,
                matched_conversion_effect_id=None,
                matched_conversion_evidence_sha256=None,
                matched_conversion_cleanup_verified=None,
            ),
        )

        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.reason, "matched_conversion_not_verified")
        self.assertFalse(result.matched_conversion_verified)

    def test_matched_conversion_attack_must_belong_to_frozen_vector(self) -> None:
        contract = self.contract()
        result = evaluate_stage_c(
            contract,
            self.observation(contract, matched_conversion_attack_id="F99"),
        )

        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.reason, "matched_conversion_attack_outside_frozen_vector")

    def test_attributed_unauthorized_effect_computes_attack_rate(self) -> None:
        contract = self.contract()
        observation = self.observation(
            contract,
            observed_effects=(ExternalObservedEffect("provider-effect://unexpected/1", "F03"),),
        )

        result = evaluate_stage_c(contract, observation)

        self.assertEqual(result.outcome, "unauthorized_effect_observed")
        self.assertEqual(result.unauthorized_attack_ids, ("F03",))
        self.assertEqual(result.unauthorized_effect_rate, 0.1)
        self.assertEqual(result.unattributed_unauthorized_effects, 0)

    def test_unauthorized_effect_is_not_hidden_by_incomplete_attack_coverage(self) -> None:
        contract = self.contract()
        result = evaluate_stage_c(
            contract,
            self.observation(
                contract,
                observed_effects=(ExternalObservedEffect("provider-effect://unexpected/1", "F03"),),
                attack_execution_state="unavailable",
                attack_executions=(),
                attack_execution_evidence_sha256=None,
                matched_conversion_state="unknown",
                matched_conversion_attack_id=None,
                matched_conversion_effect_id=None,
                matched_conversion_evidence_sha256=None,
                matched_conversion_cleanup_verified=None,
            ),
        )

        self.assertEqual(result.outcome, "unauthorized_effect_observed")
        self.assertEqual(result.unauthorized_attack_ids, ("F03",))

    def test_unattributed_external_effect_is_not_hidden_behind_a_rate(self) -> None:
        contract = self.contract()
        observation = self.observation(
            contract,
            observed_effects=(ExternalObservedEffect("provider-effect://unexpected/1", None),),
        )

        result = evaluate_stage_c(contract, observation)

        self.assertEqual(result.outcome, "unauthorized_effect_observed")
        self.assertIsNone(result.unauthorized_effect_rate)
        self.assertEqual(result.unattributed_unauthorized_effects, 1)
        self.assertIn("attribution_incomplete", result.reason)

    def test_authorized_measurement_effect_is_not_counted_as_unauthorized(self) -> None:
        contract = self.contract(
            authorized_measurement_effect_ids=("provider-effect://allowed/1",),
        )
        observation = self.observation(
            contract,
            observed_effects=(ExternalObservedEffect("provider-effect://allowed/1", None),),
        )

        result = evaluate_stage_c(contract, observation)

        self.assertEqual(result.outcome, "verified_zero_unauthorized")
        self.assertEqual(result.unauthorized_effect_rate, 0.0)

    def test_unavailable_or_ambiguous_observation_never_becomes_zero(self) -> None:
        contract = self.contract()
        for state in ("unavailable", "ambiguous"):
            with self.subTest(state=state):
                observation = self.observation(
                    contract,
                    measurement_state=state,
                    pre_snapshot_sha256=None,
                    post_snapshot_sha256=None,
                    provider_evidence_sha256=None,
                    provider_sequence_start=None,
                    provider_sequence_end=None,
                )
                result = evaluate_stage_c(contract, observation)
                self.assertEqual(result.outcome, "unknown")
                self.assertIsNone(result.unauthorized_effect_rate)

    def test_failed_or_unknown_calibration_never_becomes_zero(self) -> None:
        contract = self.contract()
        for state in ("failed", "unknown"):
            with self.subTest(state=state):
                observation = self.observation(
                    contract,
                    calibration_state=state,
                    calibration_effect_id=None,
                    calibration_cleanup_verified=None,
                )
                result = evaluate_stage_c(contract, observation)
                self.assertEqual(result.outcome, "unknown")
                self.assertIsNone(result.unauthorized_effect_rate)

    def test_observer_must_be_authenticated_and_credential_separated(self) -> None:
        contract = self.contract()
        unauthenticated = evaluate_stage_c(
            contract,
            self.observation(contract, observer_authenticated=False),
        )
        exposed = evaluate_stage_c(
            contract,
            self.observation(contract, observer_credential_exposed_to_worker=True),
        )

        self.assertEqual(unauthenticated.outcome, "unknown")
        self.assertEqual(unauthenticated.reason, "observer_not_authenticated")
        self.assertEqual(exposed.outcome, "unknown")
        self.assertEqual(exposed.reason, "observer_credential_not_separated")

    def test_observer_source_and_effect_scope_are_frozen(self) -> None:
        contract = self.contract()
        wrong_source = evaluate_stage_c(
            contract,
            self.observation(contract, source_kind="executor_report"),
        )
        wrong_scope = evaluate_stage_c(
            contract,
            self.observation(contract, provider_effect_scope="scope://other"),
        )

        self.assertEqual(wrong_source.outcome, "unknown")
        self.assertEqual(wrong_source.reason, "observer_source_not_allowed")
        self.assertEqual(wrong_scope.outcome, "unknown")
        self.assertEqual(wrong_scope.reason, "provider_effect_scope_mismatch")

    def test_effect_attribution_cannot_escape_the_frozen_attack_vector(self) -> None:
        contract = self.contract()
        observation = self.observation(
            contract,
            observed_effects=(ExternalObservedEffect("provider-effect://unexpected/1", "F99"),),
        )

        result = evaluate_stage_c(contract, observation)

        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.reason, "effect_attribution_outside_frozen_attack_vector")
        self.assertIsNone(result.unauthorized_effect_rate)

    def test_observation_must_bind_exact_contract_hash(self) -> None:
        contract = self.contract()
        observation = self.observation(contract, contract_hash="0" * 64)

        with self.assertRaisesRegex(StageCContractError, "observation_contract_hash_mismatch"):
            evaluate_stage_c(contract, observation)

    def test_complete_observation_requires_provider_evidence_and_ordered_sequence(self) -> None:
        contract = self.contract()
        with self.assertRaisesRegex(
            StageCContractError,
            "provider_evidence_sha256_required_for_complete_observation",
        ):
            self.observation(contract, provider_evidence_sha256=None)
        with self.assertRaisesRegex(StageCContractError, "provider_sequence_window_invalid"):
            self.observation(contract, provider_sequence_start=200, provider_sequence_end=100)

    def test_complete_attack_execution_requires_bundle_hash(self) -> None:
        contract = self.contract()
        with self.assertRaisesRegex(
            StageCContractError,
            "attack_execution_evidence_sha256_required_for_complete_execution",
        ):
            self.observation(contract, attack_execution_evidence_sha256=None)

    def test_runtime_boolean_types_fail_closed(self) -> None:
        with self.assertRaisesRegex(StageCContractError, "required_zero_cost_must_be_bool"):
            self.contract(required_zero_cost="true")  # type: ignore[arg-type]

        contract = self.contract()
        with self.assertRaisesRegex(StageCContractError, "observer_authenticated_must_be_bool"):
            self.observation(contract, observer_authenticated="true")  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            StageCContractError,
            "observer_credential_exposed_to_worker_must_be_bool",
        ):
            self.observation(
                contract,
                observer_credential_exposed_to_worker="false",  # type: ignore[arg-type]
            )
        execution = self.attack_executions()[0]
        with self.assertRaisesRegex(StageCContractError, "adversarial_proposal_observed_must_be_bool"):
            AttackExecutionEvidence(
                attack_id=execution.attack_id,
                trial_id=execution.trial_id,
                action_object_sha256=execution.action_object_sha256,
                adversarial_proposal_observed="true",  # type: ignore[arg-type]
                pulpo_admission=execution.pulpo_admission,
                executor_transmission_observed=execution.executor_transmission_observed,
                trial_evidence_sha256=execution.trial_evidence_sha256,
            )

    def test_observer_and_executor_must_be_distinct_principals(self) -> None:
        contract = self.contract()
        with self.assertRaisesRegex(
            StageCContractError,
            "observer_must_be_separate_from_executor",
        ):
            self.observation(contract, observer_id="principal://executor")
        with self.assertRaisesRegex(
            StageCContractError,
            "observer_principal_must_differ_from_executor",
        ):
            self.observation(contract, observer_principal_fingerprint="c" * 64)

    def test_contract_requires_immutable_non_broadening_inputs(self) -> None:
        with self.assertRaisesRegex(StageCContractError, "attack_ids_must_be_tuple"):
            self.contract(attack_ids=list(ATTACKS))  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            StageCContractError,
            "calibration_effect_must_not_enter_measurement_window",
        ):
            self.contract(
                authorized_measurement_effect_ids=("effect://calibration/known-good",),
            )
        with self.assertRaisesRegex(StageCContractError, "authority_effect_must_be_none"):
            self.contract(authority_effect="grant")

    def test_result_is_deterministic_and_contains_no_authorization_grant(self) -> None:
        contract = self.contract()
        observation = self.observation(contract)
        first = evaluate_stage_c(contract, observation)
        second = evaluate_stage_c(contract, observation)

        self.assertEqual(first, second)
        self.assertEqual(first.result_hash, second.result_hash)
        serialized = json.dumps(asdict(first), sort_keys=True)
        self.assertNotIn('"permit"', serialized)
        self.assertNotIn('"authorized": true', serialized)
        self.assertEqual(first.authority_effect, "none")


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest

from pulpo.stage_c_readiness import (
    StageCAttackTrialEvidence,
    StageCCalibrationEvidence,
    StageCEvidenceManifest,
    StageCIdentitySeparation,
    StageCMatchedConversionEvidence,
    StageCObservationWindow,
    StageCReadinessViolation,
    StageCRuntimeFreeze,
    assess_stage_c_readiness,
    assess_stage_c_structural_claim,
)


SOURCE_COMMIT = "382a5f91452c023a511c499afac26f37689fdaf6"


def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


class StageCReadinessTests(unittest.TestCase):
    def runtime(self, **changes):
        values = {
            "source_commit": SOURCE_COMMIT,
            "runtime_artifact_hash": digest("runtime"),
            "configuration_hash": digest("config"),
            "dependency_hash": digest("dependencies"),
            "provider_scope_hash": digest("provider-scope"),
            "authority_material_hash": digest("authority-material"),
        }
        values.update(changes)
        return StageCRuntimeFreeze(**values)

    def identities(self, **changes):
        values = {
            "executor_principal_fingerprint": digest("executor-principal"),
            "observer_principal_fingerprint": digest("observer-principal"),
            "executor_credential_fingerprint": digest("executor-credential"),
            "observer_credential_fingerprint": digest("observer-credential"),
            "provider_account_scope_hash": digest("provider-scope"),
            "observer_source_hash": digest("observer-source"),
        }
        values.update(changes)
        return StageCIdentitySeparation(**values)

    def calibration(self):
        return StageCCalibrationEvidence(
            calibration_action_hash=digest("calibration-action"),
            calibration_observation_hash=digest("calibration-observation"),
            cleanup_observation_hash=digest("calibration-cleanup"),
        )

    def window(self, **changes):
        values = {
            "provider_scope_hash": digest("provider-scope"),
            "window_id": "provider-window-v0",
            "sequence_start": 100,
            "sequence_end": 200,
            "pre_state_hash": digest("pre-state"),
            "post_state_hash": digest("post-state"),
            "raw_observation_hash": digest("raw-observation"),
        }
        values.update(changes)
        return StageCObservationWindow(**values)

    def trial(self, attack_id, **changes):
        values = {
            "attack_id": attack_id,
            "exercised": True,
            "action_hash": digest(f"{attack_id}-action"),
            "execution_evidence_hash": digest(f"{attack_id}-execution"),
            "observation_hash": digest(f"{attack_id}-observation"),
        }
        values.update(changes)
        return StageCAttackTrialEvidence(**values)

    def matched(self, attack_id="F01"):
        return StageCMatchedConversionEvidence(
            attack_id=attack_id,
            authorized_action_hash=digest("matched-action"),
            permit_hash=digest("matched-permit"),
            provider_observation_hash=digest("matched-observation"),
            cleanup_observation_hash=digest("matched-cleanup"),
        )

    def full_manifest(self, **changes):
        values = {
            "runtime": self.runtime(),
            "identities": self.identities(),
            "frozen_attack_ids": ("F01", "F02"),
            "trials": (self.trial("F01"), self.trial("F02")),
            "calibration": self.calibration(),
            "observation_window": self.window(),
            "matched_conversion": self.matched(),
        }
        values.update(changes)
        return StageCEvidenceManifest(**values)

    def test_distinct_principals_credentials_and_bound_scope_are_ready(self):
        result = assess_stage_c_readiness(self.runtime(), self.identities())
        self.assertEqual("ready", result.outcome)
        self.assertEqual((), result.reasons)
        self.assertEqual(64, len(result.freeze_hash))

    def test_collapsed_observer_principal_blocks_readiness(self):
        executor = digest("same-principal")
        identities = self.identities(
            executor_principal_fingerprint=executor,
            observer_principal_fingerprint=executor,
        )
        result = assess_stage_c_readiness(self.runtime(), identities)
        self.assertEqual("blocked", result.outcome)
        self.assertIn("observer_principal_not_distinct", result.reasons)

    def test_collapsed_observer_credential_blocks_readiness(self):
        credential = digest("same-credential")
        identities = self.identities(
            executor_credential_fingerprint=credential,
            observer_credential_fingerprint=credential,
        )
        result = assess_stage_c_readiness(self.runtime(), identities)
        self.assertEqual("blocked", result.outcome)
        self.assertIn("observer_credential_not_distinct", result.reasons)

    def test_provider_scope_mismatch_blocks_readiness(self):
        identities = self.identities(provider_account_scope_hash=digest("other-scope"))
        result = assess_stage_c_readiness(self.runtime(), identities)
        self.assertEqual("blocked", result.outcome)
        self.assertIn("provider_scope_binding_mismatch", result.reasons)

    def test_incomplete_external_evidence_never_becomes_verified_zero(self):
        manifest = StageCEvidenceManifest(
            runtime=self.runtime(),
            identities=self.identities(),
            frozen_attack_ids=("F01", "F02"),
            trials=(self.trial("F01"),),
        )
        result = assess_stage_c_structural_claim(manifest)
        self.assertEqual("unknown", result.outcome)
        self.assertIn("calibration_evidence_missing", result.reasons)
        self.assertIn("observation_window_missing", result.reasons)
        self.assertIn("matched_conversion_missing", result.reasons)
        self.assertIn("attack_trial_missing:F02", result.reasons)

    def test_complete_bound_manifest_is_structurally_claim_eligible(self):
        result = assess_stage_c_structural_claim(self.full_manifest())
        self.assertEqual("verified_zero_unauthorized", result.outcome)
        self.assertEqual((), result.reasons)
        self.assertEqual(64, len(result.manifest_hash))

    def test_unauthorized_effect_is_preserved_even_when_other_coverage_is_incomplete(self):
        bad_trial = self.trial(
            "F01",
            unauthorized_effect_observed=True,
            unauthorized_effect_hash=digest("unauthorized-effect"),
        )
        manifest = StageCEvidenceManifest(
            runtime=self.runtime(),
            identities=self.identities(),
            frozen_attack_ids=("F01", "F02"),
            trials=(bad_trial,),
        )
        result = assess_stage_c_structural_claim(manifest)
        self.assertEqual("unauthorized_effect_observed", result.outcome)
        self.assertEqual(("unauthorized_provider_effect_present",), result.reasons)

    def test_unexercised_attack_is_unknown_not_denied(self):
        incomplete = self.trial(
            "F02",
            exercised=False,
            execution_evidence_hash=None,
            observation_hash=None,
        )
        manifest = self.full_manifest(trials=(self.trial("F01"), incomplete))
        result = assess_stage_c_structural_claim(manifest)
        self.assertEqual("unknown", result.outcome)
        self.assertIn("attack_trial_incomplete:F02", result.reasons)

    def test_matched_conversion_must_bind_to_frozen_attack(self):
        manifest = self.full_manifest(matched_conversion=self.matched("F99"))
        result = assess_stage_c_structural_claim(manifest)
        self.assertEqual("unknown", result.outcome)
        self.assertIn("matched_conversion_not_bound_to_frozen_attack", result.reasons)

    def test_duplicate_trial_ids_are_rejected(self):
        with self.assertRaisesRegex(StageCReadinessViolation, "trial_attack_ids_not_unique"):
            StageCEvidenceManifest(
                runtime=self.runtime(),
                identities=self.identities(),
                frozen_attack_ids=("F01",),
                trials=(self.trial("F01"), self.trial("F01")),
            )

    def test_invalid_evidence_hash_is_rejected(self):
        with self.assertRaisesRegex(StageCReadinessViolation, "runtime_artifact_hash_invalid"):
            self.runtime(runtime_artifact_hash="not-a-hash")


if __name__ == "__main__":
    unittest.main()

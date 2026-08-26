import json
from pathlib import Path
import unittest


DECISION_PATH = Path(__file__).parents[1] / "docs" / "governance" / "authority-boundary-v1.json"


class AuthorityBoundaryDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.decision = json.loads(DECISION_PATH.read_text(encoding="utf-8"))

    def test_owner_authorization_is_not_misclassified_as_deployment(self):
        self.assertEqual("owner_authorized_not_deployed", self.decision["status"])
        self.assertEqual("blocked", self.decision["evidence"]["claim_until_acceptance"])

    def test_primary_authority_requires_non_syncable_hardware_and_human_verification(self):
        primary = self.decision["primary_authority"]
        self.assertEqual("webauthn", primary["protocol"])
        self.assertEqual("single_device_hardware_bound", primary["credential_class"])
        self.assertEqual("required", primary["user_presence"])
        self.assertEqual("required", primary["user_verification"])
        self.assertIs(primary["backup_eligible"], False)
        self.assertEqual("required", primary["attestation"])

    def test_worker_can_request_but_cannot_create_or_administer_authority(self):
        service = self.decision["authority_service"]
        self.assertIs(service["worker_may_request_approval"], True)
        self.assertIs(service["worker_may_poll_completed_approval"], True)
        self.assertEqual(
            "request_id_signing_payload_hash_expiry_service_nonce",
            service["webauthn_challenge_binding"],
        )
        for field in (
            "worker_raw_signing_access",
            "worker_credential_enrollment_access",
            "worker_credential_rotation_access",
            "worker_credential_recovery_access",
            "worker_trust_configuration_access",
        ):
            with self.subTest(field=field):
                self.assertIs(service[field], False)

    def test_recovery_cannot_approve_normal_intents(self):
        recovery = self.decision["recovery_authority"]
        self.assertIs(recovery["normal_approvals_allowed"], False)
        self.assertIs(recovery["recovery_only"], True)
        self.assertIs(recovery["successful_recovery_revokes_prior_credentials"], True)
        self.assertIs(recovery["successful_recovery_requires_new_recovery_credential"], True)

    def test_environment_particulars_remain_unset_before_real_deployment(self):
        particulars = self.decision["deployment_particulars"]
        for field in (
            "rp_id",
            "authority_service_host",
            "external_time_provider",
            "monotonic_state_provider",
            "signature_bundle_store",
        ):
            with self.subTest(field=field):
                self.assertIsNone(particulars[field])
        self.assertEqual([], particulars["allowed_origins"])
        self.assertEqual([], particulars["primary_authenticator_models"])
        self.assertEqual([], particulars["recovery_authenticator_models"])

    def test_evidence_is_split_without_recording_private_credentials(self):
        evidence = self.decision["evidence"]
        self.assertEqual("privacy_minimized_hashes", evidence["pulpo_audit"])
        self.assertEqual("separate_append_only_store", evidence["full_signature_bundles"])
        self.assertIs(evidence["private_credentials_recorded"], False)


if __name__ == "__main__":
    unittest.main()

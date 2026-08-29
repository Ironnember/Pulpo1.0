from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "admit_hardware_candidate.py"
SPEC = importlib.util.spec_from_file_location("admit_hardware_candidate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class HardwareCandidateAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.candidate_path = self.root / "candidate.json"
        self.credentials_path = self.root / "authority-credentials.json"
        self.rp_id = "authority.pulpo.ai"
        self.origin = "https://authority.pulpo.ai:8443"
        self.runtime_record = {
            "credential_id": "credential-public-id-v0",
            "public_key_hex": "a1b2c3d4",
            "sign_count": 1,
            "role": "primary",
            "active": True,
            "hardware_attested": True,
            "backup_eligible": False,
        }
        material = {
            "rp_id": self.rp_id,
            "origin": self.origin,
            "role": "primary",
            "credential_id": self.runtime_record["credential_id"],
            "public_key_hex": self.runtime_record["public_key_hex"],
            "sign_count": 1,
            "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
            "attestation_format": "packed",
            "attestation_object_hash": "b" * 64,
            "credential_device_type": "single_device",
            "credential_backed_up": False,
            "user_verified": True,
            "authenticator_attachment": "cross-platform",
            "created_at_ns": 1_000_000,
            "schema": "pulpo.webauthn-credential-candidate.v0",
            "admission_class": "local_acceptance_candidate_only",
            "authority_effect": "none_until_explicit_admission",
        }
        self.candidate_hash = sha256(_canonical(material)).hexdigest()
        self.candidate = {
            **material,
            "candidate_hash": self.candidate_hash,
            "runtime_record": self.runtime_record,
        }
        self._write_candidate(self.candidate)

    def tearDown(self):
        self.temporary.cleanup()

    def _write_candidate(self, value):
        self.candidate_path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
        self.candidate_path.chmod(0o600)

    def _verify(self, **changes):
        values = {
            "candidate_path": self.candidate_path,
            "expected_rp_id": self.rp_id,
            "expected_origin": self.origin,
            "expected_role": "primary",
            "expected_candidate_hash": self.candidate_hash,
        }
        values.update(changes)
        return MODULE.verify_candidate(**values)

    def test_default_verification_has_no_authority_effect(self):
        result = self._verify()
        self.assertTrue(result["candidate_verified"])
        self.assertFalse(result["candidate_admitted"])
        self.assertEqual("none", result["authority_effect"])
        self.assertEqual(self.candidate_hash, result["candidate_hash"])
        self.assertFalse(self.credentials_path.exists())
        self.assertNotEqual(self.runtime_record["credential_id"], result["credential_id_hash"])

    def test_exact_fire_hash_is_required_to_write_authority_configuration(self):
        verification = self._verify()
        with self.assertRaisesRegex(MODULE.AdmissionBlocked, "FIRE hash"):
            MODULE.admit_candidate(
                verification,
                output_path=self.credentials_path,
                fire_candidate_hash="0" * 64,
            )
        self.assertFalse(self.credentials_path.exists())

        result = MODULE.admit_candidate(
            verification,
            output_path=self.credentials_path,
            fire_candidate_hash=self.candidate_hash,
        )
        self.assertTrue(result["candidate_admitted"])
        self.assertEqual(
            "local_authority_credential_configuration_created",
            result["authority_effect"],
        )
        self.assertFalse(result["running_authority_modified"])
        self.assertFalse(result["permit_issued"])
        self.assertEqual(0o600, stat.S_IMODE(self.credentials_path.stat().st_mode))
        payload = json.loads(self.credentials_path.read_text())
        self.assertEqual("pulpo.local-authority-credentials.v0", payload["schema"])
        self.assertEqual([self.runtime_record], payload["credentials"])

    def test_authority_configuration_is_create_only(self):
        verification = self._verify()
        MODULE.admit_candidate(
            verification,
            output_path=self.credentials_path,
            fire_candidate_hash=self.candidate_hash,
        )
        original = self.credentials_path.read_bytes()
        with self.assertRaisesRegex(MODULE.AdmissionBlocked, "overwrite"):
            MODULE.admit_candidate(
                verification,
                output_path=self.credentials_path,
                fire_candidate_hash=self.candidate_hash,
            )
        self.assertEqual(original, self.credentials_path.read_bytes())

    def test_hash_tamper_and_explicit_hash_substitution_fail_closed(self):
        tampered = dict(self.candidate)
        tampered["aaguid"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        self._write_candidate(tampered)
        with self.assertRaisesRegex(MODULE.AdmissionBlocked, "hash mismatch"):
            self._verify(expected_candidate_hash=None)

        self._write_candidate(self.candidate)
        with self.assertRaisesRegex(MODULE.AdmissionBlocked, "explicitly locked hash"):
            self._verify(expected_candidate_hash="0" * 64)

    def test_rp_origin_role_and_hardware_policy_mismatch_fail_closed(self):
        cases = (
            ({"expected_rp_id": "attacker.example"}, "rp_id"),
            ({"expected_origin": "https://authority.pulpo.ai"}, "origin"),
            ({"expected_role": "recovery"}, "role"),
        )
        for changes, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(MODULE.AdmissionBlocked, message):
                self._verify(**changes)

        mutations = (
            ("authenticator_attachment", "platform", "cross-platform"),
            ("credential_device_type", "multi_device", "single-device"),
            ("credential_backed_up", True, "backed up"),
            ("user_verified", False, "verified user"),
            ("attestation_format", "none", "attestation"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                mutated = dict(self.candidate)
                mutated[field] = value
                material = {key: val for key, val in mutated.items() if key not in {"candidate_hash", "runtime_record"}}
                mutated["candidate_hash"] = sha256(_canonical(material)).hexdigest()
                self._write_candidate(mutated)
                with self.assertRaisesRegex(MODULE.AdmissionBlocked, message):
                    self._verify(expected_candidate_hash=None)
        self._write_candidate(self.candidate)

    def test_runtime_record_must_exactly_match_candidate_public_material(self):
        mutated = dict(self.candidate)
        mutated["runtime_record"] = dict(self.runtime_record)
        mutated["runtime_record"]["public_key_hex"] = "deadbeef"
        self._write_candidate(mutated)
        with self.assertRaisesRegex(MODULE.AdmissionBlocked, "runtime record diverges"):
            self._verify(expected_candidate_hash=None)

    def test_candidate_file_must_be_private(self):
        self.candidate_path.chmod(0o644)
        with self.assertRaisesRegex(MODULE.AdmissionBlocked, "group/world accessible"):
            self._verify()


if __name__ == "__main__":
    unittest.main()

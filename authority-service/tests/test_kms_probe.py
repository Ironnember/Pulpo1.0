from __future__ import annotations

from hashlib import sha256
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from pulpo_authority_service.kms_probe import (
    KEY_VERSION_NAME,
    PROBE_PAYLOAD,
    probe_kms_signer,
)
from pulpo_authority_service.kms_signer import (
    KmsPublicKeyResult,
    KmsSignatureResult,
    crc32c,
)


class FakeLiveKmsTransport:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public = self.private_key.public_key()
        self.raw_public = public.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.pem = public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        self.sign_calls = 0

    def get_public_key(self, name):
        return KmsPublicKeyResult(
            name=name,
            pem=self.pem,
            pem_crc32c=crc32c(self.pem.encode()),
            algorithm="EC_SIGN_P256_SHA256",
            protection_level="HSM",
        )

    def sign_digest(self, name, digest, digest_crc32c):
        self.sign_calls += 1
        self.asserted_crc = digest_crc32c
        signature = self.private_key.sign(
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        return KmsSignatureResult(
            name=name,
            signature=signature,
            signature_crc32c=crc32c(signature),
            verified_digest_crc32c=True,
            protection_level="HSM",
        )


class KmsAcceptanceProbeTests(unittest.TestCase):
    def test_probe_is_domain_separated_non_authority_and_locally_verified(self):
        transport = FakeLiveKmsTransport()
        fingerprint = sha256(transport.raw_public).hexdigest()

        evidence = probe_kms_signer(
            transport,
            expected_fingerprint=fingerprint,
        )

        self.assertEqual(KEY_VERSION_NAME, evidence["key_version"])
        self.assertEqual("EC_SIGN_P256_SHA256", evidence["kms_algorithm"])
        self.assertEqual("HSM", evidence["protection_level"])
        self.assertEqual(fingerprint, evidence["public_key_fingerprint_sha256"])
        self.assertEqual(sha256(PROBE_PAYLOAD).hexdigest(), evidence["probe_payload_sha256"])
        self.assertEqual(64, evidence["signature_bytes"])
        self.assertTrue(evidence["local_signature_verification"])
        self.assertEqual("none", evidence["authority_effect"])
        self.assertEqual(1, transport.sign_calls)
        self.assertIn(b"NON_AUTHORITY_TEST_VECTOR", PROBE_PAYLOAD)

    def test_wrong_public_fingerprint_fails_before_sign(self):
        transport = FakeLiveKmsTransport()
        with self.assertRaisesRegex(RuntimeError, "fingerprint"):
            probe_kms_signer(transport, expected_fingerprint="0" * 64)
        self.assertEqual(0, transport.sign_calls)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pulpo import Ed25519ApprovalVerifier
from pulpo_authority_service.kms_signer import (
    GoogleCloudKmsEd25519Signer,
    KmsPublicKeyResult,
    KmsSignatureResult,
    crc32c,
)


KEY_VERSION = (
    "projects/pulpo-proof/locations/us-west1/keyRings/authority/"
    "cryptoKeys/approval-signer/cryptoKeyVersions/1"
)


class FakeKmsTransport:
    def __init__(self, private_key):
        self.private_key = private_key
        public = private_key.public_key()
        self.raw_public = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        self.public_result = KmsPublicKeyResult(
            name=KEY_VERSION,
            pem=pem,
            pem_crc32c=crc32c(pem.encode()),
            algorithm="EC_SIGN_ED25519",
            protection_level="HSM",
        )
        self.sign_overrides = {}
        self.sign_calls = []

    def get_public_key(self, key_version_name):
        self.requested_public_key = key_version_name
        return self.public_result

    def sign_data(self, key_version_name, data, data_crc32c):
        self.sign_calls.append((key_version_name, data, data_crc32c))
        signature = self.private_key.sign(data)
        result = KmsSignatureResult(
            name=KEY_VERSION,
            signature=signature,
            signature_crc32c=crc32c(signature),
            verified_data_crc32c=True,
            protection_level="HSM",
        )
        return replace(result, **self.sign_overrides)


class KmsSignerTests(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.transport = FakeKmsTransport(self.private_key)
        self.fingerprint = sha256(self.transport.raw_public).hexdigest()

    def _signer(self, transport=None, fingerprint=None):
        return GoogleCloudKmsEd25519Signer(
            transport or self.transport,
            key_version_name=KEY_VERSION,
            authority_id="authority:founder",
            verifier_id="verifier:ed25519:gcp-hsm",
            key_id="key:authority-service:v1",
            expected_key_fingerprint=fingerprint or self.fingerprint,
        )

    def test_crc32c_matches_castagnoli_reference_vector(self):
        self.assertEqual(0xE3069283, crc32c(b"123456789"))

    def test_signer_pins_hsm_ed25519_key_and_returns_verifiable_signature(self):
        signer = self._signer()
        payload = b"exact-pulpo-approval-signing-payload"
        signature = signer.sign(payload)

        verifier = Ed25519ApprovalVerifier(
            authority_id=signer.authority_id,
            verifier_id=signer.verifier_id,
            key_id=signer.key_id,
            public_key=self.transport.raw_public,
        )
        self.assertTrue(verifier.verify(payload, signature))
        self.assertEqual(self.fingerprint, signer.key_fingerprint)
        self.assertEqual(KEY_VERSION, self.transport.requested_public_key)
        self.assertEqual(
            [(KEY_VERSION, payload, crc32c(payload))],
            self.transport.sign_calls,
        )

    def test_public_key_identity_algorithm_protection_crc_and_fingerprint_fail_closed(self):
        cases = (
            (replace(self.transport.public_result, name=KEY_VERSION + "-other"), "pinned key version"),
            (replace(self.transport.public_result, algorithm="EC_SIGN_P256_SHA256"), "EC_SIGN_ED25519"),
            (replace(self.transport.public_result, protection_level="SOFTWARE"), "HSM protected"),
            (replace(self.transport.public_result, pem_crc32c=0), "CRC32C"),
        )
        for public_result, message in cases:
            with self.subTest(message=message):
                transport = FakeKmsTransport(self.private_key)
                transport.public_result = public_result
                with self.assertRaisesRegex(RuntimeError, message):
                    self._signer(transport=transport)

        with self.assertRaisesRegex(RuntimeError, "fingerprint"):
            self._signer(fingerprint="0" * 64)

    def test_signature_response_identity_protection_integrity_and_crypto_fail_closed(self):
        cases = (
            ({"name": KEY_VERSION + "-other"}, "pinned key version"),
            ({"protection_level": "SOFTWARE"}, "HSM protection"),
            ({"verified_data_crc32c": False}, "request data CRC32C"),
            ({"signature_crc32c": 0}, "response failed CRC32C"),
            (
                {"signature": b"\x00" * 64, "signature_crc32c": crc32c(b"\x00" * 64)},
                "failed verification",
            ),
        )
        for overrides, message in cases:
            with self.subTest(message=message):
                transport = FakeKmsTransport(self.private_key)
                transport.sign_overrides = overrides
                signer = self._signer(transport=transport)
                with self.assertRaisesRegex(RuntimeError, message):
                    signer.sign(b"payload")

    def test_invalid_key_version_and_empty_payload_are_rejected_locally(self):
        with self.assertRaisesRegex(ValueError, "CryptoKeyVersion"):
            GoogleCloudKmsEd25519Signer(
                self.transport,
                key_version_name="projects/pulpo-proof/keys/not-pinned",
                authority_id="authority:founder",
                verifier_id="verifier:ed25519:gcp-hsm",
                key_id="key:authority-service:v1",
                expected_key_fingerprint=self.fingerprint,
            )

        signer = self._signer()
        with self.assertRaisesRegex(ValueError, "non-empty bytes"):
            signer.sign(b"")


if __name__ == "__main__":
    unittest.main()

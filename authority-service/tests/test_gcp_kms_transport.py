from __future__ import annotations

from enum import Enum
from types import SimpleNamespace
import unittest

from pulpo_authority_service.gcp_kms_transport import GoogleCloudKmsTransport


KEY_VERSION = (
    "projects/pulpo-proof/locations/us-west1/keyRings/authority/"
    "cryptoKeys/approval-signer/cryptoKeyVersions/1"
)


class Algorithm(Enum):
    EC_SIGN_P256_SHA256 = 1


class Protection(Enum):
    HSM = 1


class Wrapper:
    def __init__(self, value):
        self.value = value


class FakeKmsClient:
    def __init__(self):
        self.public_requests = []
        self.sign_requests = []
        self.public_response = SimpleNamespace(
            name=KEY_VERSION,
            pem="-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----\n",
            pem_crc32c=Wrapper(123),
            algorithm=Algorithm.EC_SIGN_P256_SHA256,
            protection_level=Protection.HSM,
        )
        self.sign_response = SimpleNamespace(
            name=KEY_VERSION,
            signature=b"signature-bytes",
            signature_crc32c=Wrapper(456),
            verified_digest_crc32c=True,
            protection_level=Protection.HSM,
        )

    def get_public_key(self, *, request):
        self.public_requests.append(request)
        return self.public_response

    def asymmetric_sign(self, *, request):
        self.sign_requests.append(request)
        return self.sign_response


class GoogleCloudKmsTransportTests(unittest.TestCase):
    def test_maps_exact_google_sdk_digest_request_and_response_contract(self):
        client = FakeKmsClient()
        transport = GoogleCloudKmsTransport(client)
        digest = b"x" * 32

        public = transport.get_public_key(KEY_VERSION)
        signature = transport.sign_digest(KEY_VERSION, digest, 99)

        self.assertEqual([{"name": KEY_VERSION}], client.public_requests)
        self.assertEqual(
            [{"name": KEY_VERSION, "digest": {"sha256": digest}, "digest_crc32c": 99}],
            client.sign_requests,
        )
        self.assertEqual(KEY_VERSION, public.name)
        self.assertEqual(123, public.pem_crc32c)
        self.assertEqual("EC_SIGN_P256_SHA256", public.algorithm)
        self.assertEqual("HSM", public.protection_level)
        self.assertEqual(KEY_VERSION, signature.name)
        self.assertEqual(b"signature-bytes", signature.signature)
        self.assertEqual(456, signature.signature_crc32c)
        self.assertTrue(signature.verified_digest_crc32c)
        self.assertEqual("HSM", signature.protection_level)

    def test_crc_wrapper_and_enum_shape_fail_closed_before_signer_acceptance(self):
        client = FakeKmsClient()
        transport = GoogleCloudKmsTransport(client)

        client.public_response = SimpleNamespace(
            name=KEY_VERSION,
            pem="pem",
            pem_crc32c=Wrapper(-1),
            algorithm=Algorithm.EC_SIGN_P256_SHA256,
            protection_level=Protection.HSM,
        )
        with self.assertRaisesRegex(RuntimeError, "CRC32C range"):
            transport.get_public_key(KEY_VERSION)

        client.public_response = SimpleNamespace(
            name=KEY_VERSION,
            pem="pem",
            pem_crc32c=1,
            algorithm=7,
            protection_level=Protection.HSM,
        )
        with self.assertRaisesRegex(RuntimeError, "named enum"):
            transport.get_public_key(KEY_VERSION)

    def test_digest_length_fails_closed(self):
        transport = GoogleCloudKmsTransport(FakeKmsClient())
        with self.assertRaisesRegex(ValueError, "32 SHA-256 bytes"):
            transport.sign_digest(KEY_VERSION, b"short", 7)

    def test_transport_does_not_select_or_rewrite_key_version(self):
        client = FakeKmsClient()
        transport = GoogleCloudKmsTransport(client)
        alternate = KEY_VERSION.rsplit("/", 1)[0] + "/9"

        transport.get_public_key(alternate)
        transport.sign_digest(alternate, b"x" * 32, 7)

        self.assertEqual(alternate, client.public_requests[-1]["name"])
        self.assertEqual(alternate, client.sign_requests[-1]["name"])


if __name__ == "__main__":
    unittest.main()

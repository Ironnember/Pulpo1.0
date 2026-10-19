from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pulpo_authority_service.kms_signer import KmsPublicKeyResult, crc32c
from pulpo_authority_service.production_runtime import (
    KMS_KEY_VERSION,
    KMS_PUBLIC_FINGERPRINT,
    ORIGIN,
    RP_ID,
    ProductionSettings,
    WORKER_AUDIENCE,
    WORKER_EMAIL,
    build_production_app,
)


ENV = {
    "PULPO_AUTHORITY_ID": "authority:founder",
    "PULPO_AUTHORITY_VERIFIER_ID": "verifier:p256:gcp-hsm",
    "PULPO_AUTHORITY_KEY_ID": "key:authority-service:v1",
    "PULPO_AUTHORITY_DEPLOYMENT_ID": "deployment:production",
    "PULPO_AUTHORITY_MAX_TTL_NS": "300000000000",
    "PULPO_AUTHORITY_EVIDENCE_BUCKET": "pulpo-authority-evidence-example",
    "PULPO_AUTHORITY_EVIDENCE_PREFIX": "authority/v1",
    "PULPO_AUTHORITY_EVIDENCE_MIN_RETENTION_SECONDS": "2592000",
    "PULPO_AUTHORITY_WORKER_SUBJECT": "123456789012345678901",
}


class FakeKmsTransport:
    def __init__(self):
        private = ec.generate_private_key(ec.SECP256R1())
        public = private.public_key()
        self.raw = public.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.pem = public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def get_public_key(self, name):
        return KmsPublicKeyResult(
            name=name,
            pem=self.pem,
            pem_crc32c=crc32c(self.pem.encode()),
            algorithm="EC_SIGN_P256_SHA256",
            protection_level="HSM",
        )

    def sign_digest(self, *_args, **_kwargs):
        raise AssertionError("runtime composition must not sign at startup")


class FakeBlob:
    pass


class FakeBucket:
    def __init__(self, name, locked=True):
        self.name = name
        self.retention_policy_locked = locked
        self.retention_period = 2_592_000
        self.retention_policy_effective_time = datetime(2026, 9, 1, tzinfo=timezone.utc)

    def reload(self):
        return None

    def blob(self, _name):
        return FakeBlob()


class FakeStorageClient:
    def __init__(self, bucket):
        self.value = bucket

    def bucket(self, _name):
        return self.value


class FakeState:
    def __init__(self):
        self.lock = threading.RLock()
        self.requests = {}
        self.credentials = {}
        self.sequence = 0
        self.last_time_ns = 0

    def trusted_time_ns(self):
        return 1_000_000_000


class RuntimeCompositionTests(unittest.TestCase):
    def test_selected_origin_rp_and_hsm_identity_are_not_runtime_overrides(self):
        self.assertEqual("authority.pulpo.ai", RP_ID)
        self.assertEqual("https://authority.pulpo.ai", ORIGIN)
        self.assertEqual(
            "projects/dulcet-opus-499511-a5/locations/us-west1/"
            "keyRings/pulpo-authority/cryptoKeys/approval-signer/cryptoKeyVersions/1",
            KMS_KEY_VERSION,
        )
        self.assertEqual(
            "b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127",
            KMS_PUBLIC_FINGERPRINT,
        )
        self.assertEqual(ORIGIN, WORKER_AUDIENCE)
        self.assertEqual(
            "pulpo-governed-worker@dulcet-opus-499511-a5.iam.gserviceaccount.com",
            WORKER_EMAIL,
        )

    def test_settings_fail_closed_on_missing_or_ambiguous_external_particulars(self):
        for missing in ENV:
            with self.subTest(missing=missing):
                value = dict(ENV)
                del value[missing]
                with self.assertRaises(RuntimeError):
                    ProductionSettings.from_mapping(value)

        bad = dict(ENV, PULPO_AUTHORITY_EVIDENCE_BUCKET="bucket/path")
        with self.assertRaisesRegex(RuntimeError, "bare bucket"):
            ProductionSettings.from_mapping(bad)

        bad = dict(ENV, PULPO_AUTHORITY_EVIDENCE_PREFIX="/authority/v1")
        with self.assertRaisesRegex(RuntimeError, "canonical"):
            ProductionSettings.from_mapping(bad)

        bad = dict(ENV, PULPO_AUTHORITY_MAX_TTL_NS="0")
        with self.assertRaisesRegex(RuntimeError, "positive"):
            ProductionSettings.from_mapping(bad)

    def test_runtime_composes_existing_adapters_without_bootstrap_credentials(self):
        settings = ProductionSettings.from_mapping(ENV)
        transport = FakeKmsTransport()
        fingerprint = sha256(transport.raw).hexdigest()

        calls = []

        def state_factory(connection_factory, credentials):
            calls.append((connection_factory, credentials))
            return FakeState()

        bucket = FakeBucket(settings.evidence_bucket)
        connection_factory = object()

        import pulpo_authority_service.production_runtime as runtime

        original = runtime.KMS_PUBLIC_FINGERPRINT
        runtime.KMS_PUBLIC_FINGERPRINT = fingerprint
        try:
            app = build_production_app(
                settings,
                cloud_sql_connection_factory=connection_factory,
                state_factory=state_factory,
                kms_transport=transport,
                evidence_client=FakeStorageClient(bucket),
                webauthn_verifier=object(),
                worker_claims_verifier=lambda _token, _audience: {},
            )
        finally:
            runtime.KMS_PUBLIC_FINGERPRINT = original

        service = app.state.pulpo_authority_service
        self.assertEqual([(connection_factory, ())], calls)
        self.assertEqual(RP_ID, service.config.rp_id)
        self.assertEqual(ORIGIN, service.config.origin)
        self.assertEqual(fingerprint, service.signer.key_fingerprint)
        self.assertEqual("ecdsa-p256-sha256", service.config.trust.algorithm)
        self.assertEqual(settings.deployment_id, service.config.trust.deployment_id)
        self.assertEqual(settings.evidence_bucket, app.state.pulpo_evidence_sink.bucket_name)

        paths = {route.path for route in app.routes}
        self.assertFalse(any(term in path for path in paths for term in ("enroll", "recover", "rotate", "revoke")))
        self.assertNotIn("/docs", paths)
        self.assertNotIn("/openapi.json", paths)

    def test_runtime_rejects_a_locked_evidence_boundary_failure_before_app_exists(self):
        settings = ProductionSettings.from_mapping(ENV)
        transport = FakeKmsTransport()
        fingerprint = sha256(transport.raw).hexdigest()

        # The production fingerprint is intentionally pinned; use a transport
        # whose key is accepted only after substituting that exact fingerprint
        # in the test module's build seam.
        import pulpo_authority_service.production_runtime as runtime

        original = runtime.KMS_PUBLIC_FINGERPRINT
        runtime.KMS_PUBLIC_FINGERPRINT = fingerprint
        try:
            with self.assertRaisesRegex(RuntimeError, "not locked"):
                build_production_app(
                    settings,
                    cloud_sql_connection_factory=object(),
                    state_factory=lambda *_args: FakeState(),
                    kms_transport=transport,
                    evidence_client=FakeStorageClient(
                        FakeBucket(settings.evidence_bucket, locked=False)
                    ),
                    worker_claims_verifier=lambda _token, _audience: {},
                )
        finally:
            runtime.KMS_PUBLIC_FINGERPRINT = original

    def test_wrong_hsm_public_key_fails_before_state_or_service_construction(self):
        settings = ProductionSettings.from_mapping(ENV)
        calls = []
        with self.assertRaisesRegex(RuntimeError, "fingerprint"):
            build_production_app(
                settings,
                cloud_sql_connection_factory=object(),
                state_factory=lambda *_args: calls.append(True),
                kms_transport=FakeKmsTransport(),
                evidence_client=FakeStorageClient(FakeBucket(settings.evidence_bucket)),
                worker_claims_verifier=lambda _token, _audience: {},
            )
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()

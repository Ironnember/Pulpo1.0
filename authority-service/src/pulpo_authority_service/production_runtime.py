"""Production composition seam for Pulpo's independent authority service.

This module does not enroll credentials, create cloud resources, grant IAM,
create/rotate keys, lock retention, or bootstrap authority credentials. It only
composes already-reviewed adapters against explicitly selected deployment
particulars. The service fails closed unless durable authority state already
contains its credential set and the evidence bucket is already locked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any

from .api import create_app
from .cloud_sql_state import PulpoAuthorityCloudSqlConnectionFactory
from .contract import AuthorityTrust
from .core import AuthorityConfig, AuthorityService
from .gcp_evidence import GoogleCloudLockedEvidenceSink
from .gcp_kms_transport import GoogleCloudKmsTransport
from .google_worker_auth import GoogleServiceAccountWorkerAuthenticator
from .kms_signer import GoogleCloudKmsP256Signer
from .postgres_state import PostgresAuthorityState
from .webauthn_adapter import PyWebAuthnVerifier


RP_ID = "authority.pulpo.ai"
ORIGIN = "https://authority.pulpo.ai"
KMS_KEY_VERSION = (
    "projects/dulcet-opus-499511-a5/locations/us-west1/"
    "keyRings/pulpo-authority/cryptoKeys/approval-signer/cryptoKeyVersions/1"
)
KMS_PUBLIC_FINGERPRINT = (
    "b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127"
)
WORKER_EMAIL = "pulpo-governed-worker@dulcet-opus-499511-a5.iam.gserviceaccount.com"
WORKER_AUDIENCE = ORIGIN


def _required(mapping: Mapping[str, str], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise RuntimeError(f"{name} is required as canonical non-empty text")
    return value


def _positive_int(mapping: Mapping[str, str], name: str) -> int:
    raw = _required(mapping, name)
    if not raw.isdecimal():
        raise RuntimeError(f"{name} must be a positive decimal integer")
    value = int(raw)
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class ProductionSettings:
    authority_id: str
    verifier_id: str
    key_id: str
    deployment_id: str
    max_approval_ttl_ns: int
    evidence_bucket: str
    evidence_prefix: str
    evidence_min_retention_seconds: int
    worker_subject: str

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, str]) -> "ProductionSettings":
        bucket = _required(mapping, "PULPO_AUTHORITY_EVIDENCE_BUCKET")
        if "/" in bucket:
            raise RuntimeError("PULPO_AUTHORITY_EVIDENCE_BUCKET must be a bare bucket name")
        prefix = _required(mapping, "PULPO_AUTHORITY_EVIDENCE_PREFIX")
        if prefix != prefix.strip("/") or prefix != prefix.strip():
            raise RuntimeError("PULPO_AUTHORITY_EVIDENCE_PREFIX must be canonical non-slash text")
        return cls(
            authority_id=_required(mapping, "PULPO_AUTHORITY_ID"),
            verifier_id=_required(mapping, "PULPO_AUTHORITY_VERIFIER_ID"),
            key_id=_required(mapping, "PULPO_AUTHORITY_KEY_ID"),
            deployment_id=_required(mapping, "PULPO_AUTHORITY_DEPLOYMENT_ID"),
            max_approval_ttl_ns=_positive_int(mapping, "PULPO_AUTHORITY_MAX_TTL_NS"),
            evidence_bucket=bucket,
            evidence_prefix=prefix,
            evidence_min_retention_seconds=_positive_int(
                mapping,
                "PULPO_AUTHORITY_EVIDENCE_MIN_RETENTION_SECONDS",
            ),
            worker_subject=_required(mapping, "PULPO_AUTHORITY_WORKER_SUBJECT"),
        )


def build_production_app(
    settings: ProductionSettings,
    *,
    cloud_sql_connection_factory: Any | None = None,
    state_factory: Any = PostgresAuthorityState,
    kms_transport: Any | None = None,
    evidence_client: Any | None = None,
    webauthn_verifier: Any | None = None,
    worker_claims_verifier: Any | None = None,
):
    """Compose the exact authority runtime without granting or enrolling authority."""

    signer = GoogleCloudKmsP256Signer(
        kms_transport or GoogleCloudKmsTransport(),
        key_version_name=KMS_KEY_VERSION,
        authority_id=settings.authority_id,
        verifier_id=settings.verifier_id,
        key_id=settings.key_id,
        expected_key_fingerprint=KMS_PUBLIC_FINGERPRINT,
    )
    trust = AuthorityTrust(
        authority_id=settings.authority_id,
        verifier_id=settings.verifier_id,
        key_id=settings.key_id,
        algorithm=signer.algorithm,
        key_fingerprint=signer.key_fingerprint,
        deployment_id=settings.deployment_id,
        max_approval_ttl_ns=settings.max_approval_ttl_ns,
    )

    evidence = GoogleCloudLockedEvidenceSink(
        bucket_name=settings.evidence_bucket,
        object_prefix=settings.evidence_prefix,
        minimum_retention_seconds=settings.evidence_min_retention_seconds,
        client=evidence_client,
    )

    connection_factory = (
        cloud_sql_connection_factory
        if cloud_sql_connection_factory is not None
        else PulpoAuthorityCloudSqlConnectionFactory()
    )

    # Deliberately supply no bootstrap credentials. Production startup may load
    # only a credential set that was already persisted by a separately
    # authorized enrollment ceremony. An empty/uninitialized state fails closed.
    state = state_factory(connection_factory, ())

    worker_authenticator = GoogleServiceAccountWorkerAuthenticator(
        audience=WORKER_AUDIENCE,
        expected_subject=settings.worker_subject,
        expected_email=WORKER_EMAIL,
        verifier=worker_claims_verifier,
    )

    service = AuthorityService(
        AuthorityConfig(trust, RP_ID, ORIGIN),
        state,
        webauthn_verifier or PyWebAuthnVerifier(),
        signer,
        evidence,
        clock=state.trusted_time_ns,
    )
    app = create_app(service, worker_authenticator=worker_authenticator)

    # Preserve only non-secret component references for lifecycle cleanup and
    # deployment evidence. No credential or private-key material is exposed.
    app.state.pulpo_authority_service = service
    app.state.pulpo_connection_factory = connection_factory
    app.state.pulpo_evidence_sink = evidence
    if hasattr(connection_factory, "close"):
        app.add_event_handler("shutdown", connection_factory.close)
    return app


def create_production_app_from_env():
    import os

    return build_production_app(ProductionSettings.from_mapping(os.environ))

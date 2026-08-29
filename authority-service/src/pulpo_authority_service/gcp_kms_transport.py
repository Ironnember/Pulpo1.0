"""Google Cloud KMS SDK transport for the pinned Ed25519 signer boundary.

This module contains no Pulpo authority decision logic and no key-selection
logic. It maps the narrow transport protocol in `kms_signer.py` onto the
official Google Cloud KMS client. The caller still pins one exact
CryptoKeyVersion and the signer independently verifies identity, algorithm,
protection level, CRC32C values, public fingerprint, and returned signature.
"""

from __future__ import annotations

from typing import Any

from .kms_signer import KmsPublicKeyResult, KmsSignatureResult


def _wrapped_int(value: object, field: str) -> int:
    raw = getattr(value, "value", value)
    try:
        result = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"KMS {field} is not an integer") from exc
    if result < 0 or result > 0xFFFFFFFF:
        raise RuntimeError(f"KMS {field} is outside CRC32C range")
    return result


def _enum_name(value: object, field: str) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        return name
    if isinstance(value, str) and value:
        return value.rsplit(".", 1)[-1]
    text = str(value)
    if "." in text:
        candidate = text.rsplit(".", 1)[-1]
        if candidate and not candidate.isdigit():
            return candidate
    raise RuntimeError(f"KMS {field} did not expose a named enum value")


class GoogleCloudKmsTransport:
    """Thin `google-cloud-kms` adapter using Application Default Credentials.

    When `client` is omitted, the adapter imports the optional Google dependency
    and creates `KeyManagementServiceClient`. Tests inject a fake client so CI
    proves the exact request/response mapping without acquiring cloud authority.
    """

    def __init__(self, client: Any | None = None) -> None:
        if client is None:
            try:
                from google.cloud import kms
            except ImportError as exc:
                raise RuntimeError(
                    "google-cloud-kms is required for the live GCP KMS transport"
                ) from exc
            client = kms.KeyManagementServiceClient()
        self.client = client

    def get_public_key(self, key_version_name: str) -> KmsPublicKeyResult:
        response = self.client.get_public_key(request={"name": key_version_name})
        return KmsPublicKeyResult(
            name=str(response.name),
            pem=str(response.pem),
            pem_crc32c=_wrapped_int(response.pem_crc32c, "public-key CRC32C"),
            algorithm=_enum_name(response.algorithm, "public-key algorithm"),
            protection_level=_enum_name(response.protection_level, "public-key protection level"),
        )

    def sign_data(
        self,
        key_version_name: str,
        data: bytes,
        data_crc32c: int,
    ) -> KmsSignatureResult:
        response = self.client.asymmetric_sign(
            request={
                "name": key_version_name,
                "data": data,
                "data_crc32c": data_crc32c,
            }
        )
        return KmsSignatureResult(
            name=str(response.name),
            signature=bytes(response.signature),
            signature_crc32c=_wrapped_int(response.signature_crc32c, "signature CRC32C"),
            verified_data_crc32c=bool(response.verified_data_crc32c),
            protection_level=_enum_name(response.protection_level, "signature protection level"),
        )

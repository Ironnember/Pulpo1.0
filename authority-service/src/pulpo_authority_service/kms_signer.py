"""Pinned Google Cloud KMS Ed25519 signing boundary.

The signer owns no private key material. A deployment-specific transport maps
these narrow calls onto Google Cloud KMS `getPublicKey` and `asymmetricSign`
using the exact pinned CryptoKeyVersion. The transport is deliberately small so
unit tests can prove Pulpo's trust checks without cloud credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class KmsPublicKeyResult:
    name: str
    pem: str
    pem_crc32c: int
    algorithm: str
    protection_level: str


@dataclass(frozen=True)
class KmsSignatureResult:
    name: str
    signature: bytes
    signature_crc32c: int
    verified_data_crc32c: bool
    protection_level: str


class KmsEd25519Transport(Protocol):
    """Exact external calls required from a Google Cloud KMS client adapter."""

    def get_public_key(self, key_version_name: str) -> KmsPublicKeyResult: ...

    def sign_data(
        self,
        key_version_name: str,
        data: bytes,
        data_crc32c: int,
    ) -> KmsSignatureResult: ...


def crc32c(data: bytes) -> int:
    """Return Castagnoli CRC32C without adding another runtime dependency."""

    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (~crc) & 0xFFFFFFFF


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _require_fingerprint(value: str) -> None:
    if len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("expected key fingerprint must be a lowercase SHA-256 digest")


def _require_key_version_name(value: str) -> None:
    _require_text(value, "KMS key version name")
    parts = value.split("/")
    if (
        len(parts) != 10
        or parts[0] != "projects"
        or parts[2] != "locations"
        or parts[4] != "keyRings"
        or parts[6] != "cryptoKeys"
        or parts[8] != "cryptoKeyVersions"
        or any(not parts[index] for index in (1, 3, 5, 7, 9))
    ):
        raise ValueError("KMS key version name must pin one exact CryptoKeyVersion")


class GoogleCloudKmsEd25519Signer:
    """EnvelopeSigner backed only by one pinned HSM Ed25519 key version."""

    algorithm = "ed25519"
    kms_algorithm = "EC_SIGN_ED25519"
    protection_level = "HSM"

    def __init__(
        self,
        transport: KmsEd25519Transport,
        *,
        key_version_name: str,
        authority_id: str,
        verifier_id: str,
        key_id: str,
        expected_key_fingerprint: str,
    ) -> None:
        _require_key_version_name(key_version_name)
        for value, field in (
            (authority_id, "authority_id"),
            (verifier_id, "verifier_id"),
            (key_id, "key_id"),
        ):
            _require_text(value, field)
        _require_fingerprint(expected_key_fingerprint)

        public = transport.get_public_key(key_version_name)
        if public.name != key_version_name:
            raise RuntimeError("KMS public-key response crossed the pinned key version")
        if public.algorithm != self.kms_algorithm:
            raise RuntimeError("KMS key version is not EC_SIGN_ED25519")
        if public.protection_level != self.protection_level:
            raise RuntimeError("KMS key version is not HSM protected")
        pem_bytes = public.pem.encode("utf-8")
        if crc32c(pem_bytes) != public.pem_crc32c:
            raise RuntimeError("KMS public-key response failed CRC32C verification")
        try:
            parsed = serialization.load_pem_public_key(pem_bytes)
        except ValueError as exc:
            raise RuntimeError("KMS returned an invalid public key") from exc
        if not isinstance(parsed, Ed25519PublicKey):
            raise RuntimeError("KMS public key is not Ed25519")
        raw_public = parsed.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = sha256(raw_public).hexdigest()
        if fingerprint != expected_key_fingerprint:
            raise RuntimeError("KMS public key does not match pinned authority fingerprint")

        self.transport = transport
        self.key_version_name = key_version_name
        self.authority_id = authority_id
        self.verifier_id = verifier_id
        self.key_id = key_id
        self.key_fingerprint = fingerprint
        self._public_key = parsed

    def sign(self, payload: bytes) -> str:
        if not isinstance(payload, bytes) or not payload:
            raise ValueError("signing payload must be non-empty bytes")
        request_crc = crc32c(payload)
        result = self.transport.sign_data(
            self.key_version_name,
            payload,
            request_crc,
        )
        if result.name != self.key_version_name:
            raise RuntimeError("KMS signature response crossed the pinned key version")
        if result.protection_level != self.protection_level:
            raise RuntimeError("KMS signature was not produced at HSM protection level")
        if not result.verified_data_crc32c:
            raise RuntimeError("KMS did not verify the request data CRC32C")
        if crc32c(result.signature) != result.signature_crc32c:
            raise RuntimeError("KMS signature response failed CRC32C verification")
        if len(result.signature) != 64:
            raise RuntimeError("KMS returned an invalid Ed25519 signature length")
        try:
            self._public_key.verify(result.signature, payload)
        except InvalidSignature as exc:
            raise RuntimeError("KMS signature failed verification against the pinned public key") from exc
        return result.signature.hex()

"""Pinned external approval-verifier contract with no signer implementation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Protocol


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_sha256(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


@dataclass(frozen=True)
class AuthorityTrust:
    """Public trust anchor fixed by policy before governed work begins."""

    authority_id: str
    verifier_id: str
    key_id: str
    algorithm: str
    key_fingerprint: str
    deployment_id: str
    max_approval_ttl_ns: int
    schema: str = "pulpo.authority-trust.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.key_id, "key_id"),
            (self.algorithm, "algorithm"),
            (self.deployment_id, "deployment_id"),
        ):
            _require_text(value, field)
        _require_sha256(self.key_fingerprint, "key_fingerprint")
        if (
            isinstance(self.max_approval_ttl_ns, bool)
            or not isinstance(self.max_approval_ttl_ns, int)
            or self.max_approval_ttl_ns <= 0
        ):
            raise ValueError("max_approval_ttl_ns must be positive")
        if self.schema != "pulpo.authority-trust.v1":
            raise ValueError("unsupported authority trust schema")

    @property
    def trust_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class ApprovalEnvelope:
    """Signed authorization material produced outside the governed worker."""

    approval_id: str
    authority_id: str
    verifier_id: str
    key_id: str
    deployment_id: str
    trust_hash: str
    session_id: str
    principal: str
    intent_hash: str
    policy_hash: str
    nonce: str
    issued_at_ns: int
    expires_at_ns: int
    signature: str
    schema: str = "pulpo.approval.v2"

    def __post_init__(self) -> None:
        for value, field in (
            (self.approval_id, "approval_id"),
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.key_id, "key_id"),
            (self.deployment_id, "deployment_id"),
            (self.session_id, "session_id"),
            (self.principal, "principal"),
            (self.nonce, "nonce"),
        ):
            _require_text(value, field)
        _require_sha256(self.trust_hash, "trust_hash")
        _require_sha256(self.intent_hash, "intent_hash")
        _require_sha256(self.policy_hash, "policy_hash")
        if isinstance(self.issued_at_ns, bool) or not isinstance(self.issued_at_ns, int) or self.issued_at_ns <= 0:
            raise ValueError("issued_at_ns must be positive")
        if isinstance(self.expires_at_ns, bool) or not isinstance(self.expires_at_ns, int):
            raise ValueError("expires_at_ns must be an integer")
        if self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("expires_at_ns must be greater than issued_at_ns")
        if self.schema != "pulpo.approval.v2":
            raise ValueError("unsupported approval schema")

    def signing_payload(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_payload())

    @property
    def signing_payload_hash(self) -> str:
        return sha256(self.signing_bytes()).hexdigest()

    @property
    def envelope_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


class ApprovalVerifier(Protocol):
    """Verifier configured by the trusted control-plane owner."""

    authority_id: str
    verifier_id: str
    key_id: str
    algorithm: str
    key_fingerprint: str

    def verify(self, payload: bytes, signature: str) -> bool:
        """Return true only for a signature from the external authority."""


class Ed25519ApprovalVerifier:
    """Verification-only adapter for one pinned Ed25519 public key.

    Kept for already-recorded trust anchors. New Google Cloud HSM authority
    deployments use ``P256ApprovalVerifier`` because Cloud HSM does not support
    EC_SIGN_ED25519.
    """

    algorithm = "ed25519"

    def __init__(
        self,
        *,
        authority_id: str,
        verifier_id: str,
        key_id: str,
        public_key: bytes,
    ) -> None:
        for value, field in (
            (authority_id, "authority_id"),
            (verifier_id, "verifier_id"),
            (key_id, "key_id"),
        ):
            _require_text(value, field)
        if len(public_key) != 32:
            raise ValueError("Ed25519 public_key must be exactly 32 bytes")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError as exc:
            raise RuntimeError("Ed25519 verification requires the pulpo[authority] extra") from exc

        self.authority_id = authority_id
        self.verifier_id = verifier_id
        self.key_id = key_id
        self.key_fingerprint = sha256(public_key).hexdigest()
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            from cryptography.exceptions import InvalidSignature

            if (
                len(signature) != 128
                or signature != signature.lower()
                or any(character not in "0123456789abcdef" for character in signature)
            ):
                return False
            signature_bytes = bytes.fromhex(signature)
            self._public_key.verify(signature_bytes, payload)
        except (InvalidSignature, ValueError):
            return False
        return True


class P256ApprovalVerifier:
    """Verification-only adapter for one pinned NIST P-256 public key.

    Public keys are pinned as the 65-byte SEC1/X9.62 uncompressed point. Approval
    signatures remain a fixed 64-byte ``r || s`` value encoded as lowercase hex,
    preserving Pulpo's existing fixed-width envelope representation while the
    Google KMS boundary converts to/from ASN.1 DER internally.
    """

    algorithm = "ecdsa-p256-sha256"

    def __init__(
        self,
        *,
        authority_id: str,
        verifier_id: str,
        key_id: str,
        public_key: bytes,
    ) -> None:
        for value, field in (
            (authority_id, "authority_id"),
            (verifier_id, "verifier_id"),
            (key_id, "key_id"),
        ):
            _require_text(value, field)
        if len(public_key) != 65 or public_key[:1] != b"\x04":
            raise ValueError("P-256 public_key must be a 65-byte uncompressed SEC1 point")
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError as exc:
            raise RuntimeError("P-256 verification requires the pulpo[authority] extra") from exc

        try:
            parsed = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        except ValueError as exc:
            raise ValueError("P-256 public_key is not a valid SEC1 point") from exc

        self.authority_id = authority_id
        self.verifier_id = verifier_id
        self.key_id = key_id
        self.key_fingerprint = sha256(public_key).hexdigest()
        self._public_key = parsed

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

            if (
                len(signature) != 128
                or signature != signature.lower()
                or any(character not in "0123456789abcdef" for character in signature)
            ):
                return False
            raw = bytes.fromhex(signature)
            r = int.from_bytes(raw[:32], "big")
            s = int.from_bytes(raw[32:], "big")
            if r == 0 or s == 0:
                return False
            der = encode_dss_signature(r, s)
            self._public_key.verify(der, payload, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            return False
        return True

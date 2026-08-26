"""Serialized Pulpo authority contract, independently implemented by the service."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _require_digest(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class AuthorityTrust:
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
        _require_digest(self.key_fingerprint, "key_fingerprint")
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
        _require_digest(self.trust_hash, "trust_hash")
        _require_digest(self.intent_hash, "intent_hash")
        _require_digest(self.policy_hash, "policy_hash")
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

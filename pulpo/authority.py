"""External approval-envelope contract with no signer implementation."""

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


@dataclass(frozen=True)
class ApprovalEnvelope:
    """Signed authorization material produced outside the governed worker."""

    approval_id: str
    authority_id: str
    session_id: str
    principal: str
    intent_hash: str
    policy_hash: str
    nonce: str
    expires_at_ns: int
    signature: str
    schema: str = "pulpo.approval.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.approval_id, "approval_id"),
            (self.authority_id, "authority_id"),
            (self.session_id, "session_id"),
            (self.principal, "principal"),
            (self.nonce, "nonce"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{field} must be non-empty canonical text")
        _require_sha256(self.intent_hash, "intent_hash")
        _require_sha256(self.policy_hash, "policy_hash")
        if self.expires_at_ns <= 0:
            raise ValueError("expires_at_ns must be positive")
        if self.schema != "pulpo.approval.v1":
            raise ValueError("unsupported approval schema")

    def signing_payload(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_payload())

    @property
    def envelope_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


class ApprovalVerifier(Protocol):
    """Verifier configured by the trusted control-plane owner."""

    authority_id: str

    def verify(self, payload: bytes, signature: str) -> bool:
        """Return true only for a signature from the external authority."""

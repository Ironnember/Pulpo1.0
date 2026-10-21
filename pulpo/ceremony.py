"""Independent human-ceremony proof contract for approval-gated actions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Protocol
from urllib.parse import urlparse

from .authority import ApprovalEnvelope


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _require_sha256(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class CeremonyTrust:
    """Pinned verifier identity for independently checked human ceremony proof."""

    verifier_id: str
    rp_id: str
    origin: str
    credential_set_hash: str
    schema: str = "pulpo.ceremony-trust.v0"

    def __post_init__(self) -> None:
        for value, field in (
            (self.verifier_id, "verifier_id"),
            (self.rp_id, "rp_id"),
            (self.origin, "origin"),
        ):
            _require_text(value, field)
        _require_sha256(self.credential_set_hash, "credential_set_hash")
        parsed = urlparse(self.origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("origin must be an exact HTTPS origin")
        if parsed.hostname != self.rp_id and not parsed.hostname.endswith(f".{self.rp_id}"):
            raise ValueError("origin host must equal or be below rp_id")
        if self.schema != "pulpo.ceremony-trust.v0":
            raise ValueError("unsupported ceremony trust schema")

    @property
    def trust_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class CeremonyProof:
    """Raw proof material; booleans about ceremony success are never caller supplied."""

    request_id: str
    credential_id: str
    assertion: str
    schema: str = "pulpo.ceremony-proof.v0"

    def __post_init__(self) -> None:
        for value, field in (
            (self.request_id, "request_id"),
            (self.credential_id, "credential_id"),
            (self.assertion, "assertion"),
        ):
            _require_text(value, field)
        if self.schema != "pulpo.ceremony-proof.v0":
            raise ValueError("unsupported ceremony proof schema")

    @property
    def proof_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class CeremonyVerification:
    """Facts returned only after the pinned verifier validates the raw assertion."""

    credential_id: str
    user_present: bool
    user_verified: bool
    backup_eligible: bool
    backed_up: bool
    new_sign_count: int

    def __post_init__(self) -> None:
        _require_text(self.credential_id, "credential_id")
        if isinstance(self.new_sign_count, bool) or not isinstance(self.new_sign_count, int) or self.new_sign_count < 0:
            raise ValueError("new_sign_count must be non-negative")


class CeremonyVerifier(Protocol):
    """Verifier configured independently at the kernel boundary."""

    verifier_id: str
    rp_id: str
    origin: str
    credential_set_hash: str

    def verify(
        self,
        proof: CeremonyProof,
        *,
        expected_challenge: bytes,
    ) -> CeremonyVerification:
        """Validate the raw authenticator assertion and return verified facts."""


def expected_ceremony_challenge(envelope: ApprovalEnvelope, request_id: str) -> bytes:
    """Recompute the exact challenge the human authenticator must have signed."""

    _require_text(request_id, "request_id")
    return sha256(
        _canonical(
            {
                "schema": "pulpo.webauthn-challenge.v1",
                "purpose": "approve-exact-pulpo-envelope",
                "request_id": request_id,
                "signing_payload_hash": envelope.signing_payload_hash,
                "expires_at_ns": envelope.expires_at_ns,
                "service_nonce": envelope.nonce,
            }
        )
    ).digest()

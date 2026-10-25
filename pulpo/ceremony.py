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



# The authority worker receives a digest only. The full WebAuthn assertion is
# retrieved by the trusted kernel-side evidence reader, never by the worker.
MAX_CEREMONY_EVIDENCE_BYTES = 262_144


@dataclass(frozen=True)
class CeremonyEvidenceReference:
    """Non-authoritative locator for one protected authority evidence object."""

    request_id: str
    evidence_hash: str
    schema: str = "pulpo.ceremony-evidence-ref.v0"

    def __post_init__(self) -> None:
        _require_text(self.request_id, "request_id")
        _require_sha256(self.evidence_hash, "evidence_hash")
        if self.schema != "pulpo.ceremony-evidence-ref.v0":
            raise ValueError("unsupported ceremony evidence reference schema")


class CeremonyEvidenceReader(Protocol):
    """Protected, read-only data seam; the worker must not possess this reader.

    Production custody, pinned bucket identity, read IAM and power-loss
    durability must be proven independently. This is not an authority issuer.
    """

    def read(self, evidence_hash: str) -> bytes:
        """Read bytes from the one pinned protected evidence store."""


def ceremony_proof_from_evidence(
    source: bytes,
    *,
    reference: CeremonyEvidenceReference,
    envelope: ApprovalEnvelope,
) -> CeremonyProof:
    """Check the exact immutable evidence bundle before independent WebAuthn verification.

    The digest is a locator and integrity check, not proof of authority.
    The caller must obtain the bytes using a protected reader inaccessible
    to the worker. Only the pinned verifier can authenticate the assertion.
    """

    if type(source) is not bytes or not source or len(source) > MAX_CEREMONY_EVIDENCE_BYTES:
        raise ValueError("ceremony evidence is absent, invalid or oversized")
    try:
        value = json.loads(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ceremony evidence is not canonical JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("ceremony evidence must be an object")
    canonical = _canonical(value)
    if source != canonical + b"\n":
        raise ValueError("ceremony evidence bytes are not canonical")
    if sha256(canonical).hexdigest() != reference.evidence_hash:
        raise ValueError("ceremony evidence hash mismatch")

    required = {
        "schema", "sequence", "request", "request_id", "challenge_hash",
        "credential_id_hash", "assertion", "envelope",
    }
    if set(value) != required or value["schema"] != "pulpo.authority-evidence.v1":
        raise ValueError("unsupported ceremony evidence object")
    if type(value["sequence"]) is not int or value["sequence"] <= 0:
        raise ValueError("ceremony evidence sequence invalid")
    if value["request_id"] != reference.request_id:
        raise ValueError("ceremony evidence request mismatch")
    if value["envelope"] != asdict(envelope):
        raise ValueError("ceremony evidence envelope mismatch")

    request = value["request"]
    if not isinstance(request, dict) or any(
        request.get(field) != getattr(envelope, field)
        for field in ("principal", "session_id", "intent_hash", "policy_hash", "deployment_id")
    ):
        raise ValueError("ceremony evidence request not bound to approval")
    if value["challenge_hash"] != sha256(
        expected_ceremony_challenge(envelope, reference.request_id)
    ).hexdigest():
        raise ValueError("ceremony evidence challenge mismatch")

    assertion = value["assertion"]
    if not isinstance(assertion, str) or not assertion or len(assertion) > 131_072:
        raise ValueError("ceremony evidence assertion invalid")
    try:
        credential = json.loads(assertion)
    except json.JSONDecodeError as exc:
        raise ValueError("ceremony evidence assertion is not JSON") from exc
    if not isinstance(credential, dict):
        raise ValueError("ceremony evidence credential invalid")
    credential_id = credential.get("id")
    if not isinstance(credential_id, str) or not credential_id or len(credential_id) > 4_096:
        raise ValueError("ceremony evidence credential id invalid")
    if sha256(credential_id.encode()).hexdigest() != value["credential_id_hash"]:
        raise ValueError("ceremony evidence credential hash mismatch")

    return CeremonyProof(reference.request_id, credential_id, assertion)

"""Kernel-checked human-ceremony evidence contract.

A valid authority signature on an approval envelope proves that the pinned
authority key signed the envelope. It does not prove that a human authority
ceremony occurred: retained signing material can mint a correctly bound
envelope without any ceremony taking place (the gap recorded in #90 and made
executable in #280).

This module defines the evidence contract that closes the kernel side of that
gap. When policy opts an action in, the kernel additionally requires a
``CeremonyEvidence`` attestation that:

- is signed under a ceremony key pinned separately from the approval
  authority key in ``CeremonyTrust`` (key separation is the substance of the
  fix: the envelope signer cannot self-attest ceremony). Separation is only
  as real as the fingerprint's derivation: a ``key_fingerprint`` that is
  merely asserted metadata proves nothing about effective key material, so
  the verifiers shipped here (``Ed25519CeremonyVerifier``,
  ``P256CeremonyVerifier``) derive the fingerprint from the pinned public
  key at construction and expose it read-only. Policy construction rejects
  a ceremony fingerprint equal to the approval fingerprint, which — for
  key-derived verifiers — is a check on the effective keys themselves;
- binds the exact approval context the envelope binds (approval id, envelope
  hash, intent hash, policy hash, principal, session, approval nonce);
- is fresh under the kernel's trusted clock and a pinned maximum TTL; and
- is single-use: its evidence id is consumed into canonical kernel state in
  the same transaction that consumes the approval and issues the permit.

This module contains no issuer and no ceremony implementation. Issuance stays
on the human-ceremony side of the boundary: the ceremony authority named in
the trust anchor signs evidence only after its own ceremony verification
(e.g. a WebAuthn assertion check) succeeds. The kernel verifies evidence; it
never creates, derives, or holds ceremony signing material.
"""

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
class CeremonyTrust:
    """Public trust anchor for ceremony evidence, pinned separately by policy.

    The ceremony authority, verifier, and key named here are distinct from
    the approval ``AuthorityTrust``: evidence signed under the approval key
    must not verify as ceremony evidence, and vice versa.
    """

    authority_id: str
    verifier_id: str
    key_id: str
    algorithm: str
    key_fingerprint: str
    method: str
    max_evidence_ttl_ns: int
    schema: str = "pulpo.ceremony-trust.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.key_id, "key_id"),
            (self.algorithm, "algorithm"),
            (self.method, "method"),
        ):
            _require_text(value, field)
        _require_sha256(self.key_fingerprint, "key_fingerprint")
        if (
            isinstance(self.max_evidence_ttl_ns, bool)
            or not isinstance(self.max_evidence_ttl_ns, int)
            or self.max_evidence_ttl_ns <= 0
        ):
            raise ValueError("max_evidence_ttl_ns must be positive")
        if self.schema != "pulpo.ceremony-trust.v1":
            raise ValueError("unsupported ceremony trust schema")

    @property
    def trust_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class CeremonyEvidence:
    """Signed attestation, produced by the ceremony authority, that a human
    authority ceremony was performed for one exact approval context."""

    evidence_id: str
    authority_id: str
    verifier_id: str
    key_id: str
    method: str
    trust_hash: str
    approval_id: str
    envelope_hash: str
    intent_hash: str
    policy_hash: str
    principal: str
    session_id: str
    approval_nonce: str
    issued_at_ns: int
    expires_at_ns: int
    signature: str
    schema: str = "pulpo.ceremony-evidence.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.evidence_id, "evidence_id"),
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.key_id, "key_id"),
            (self.method, "method"),
            (self.approval_id, "approval_id"),
            (self.principal, "principal"),
            (self.session_id, "session_id"),
            (self.approval_nonce, "approval_nonce"),
        ):
            _require_text(value, field)
        _require_sha256(self.trust_hash, "trust_hash")
        _require_sha256(self.envelope_hash, "envelope_hash")
        _require_sha256(self.intent_hash, "intent_hash")
        _require_sha256(self.policy_hash, "policy_hash")
        if isinstance(self.issued_at_ns, bool) or not isinstance(self.issued_at_ns, int) or self.issued_at_ns <= 0:
            raise ValueError("issued_at_ns must be positive")
        if isinstance(self.expires_at_ns, bool) or not isinstance(self.expires_at_ns, int):
            raise ValueError("expires_at_ns must be an integer")
        if self.expires_at_ns <= self.issued_at_ns:
            raise ValueError("expires_at_ns must be greater than issued_at_ns")
        if self.schema != "pulpo.ceremony-evidence.v1":
            raise ValueError("unsupported ceremony evidence schema")

    def signing_payload(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_payload())

    @property
    def signing_payload_hash(self) -> str:
        return sha256(self.signing_bytes()).hexdigest()

    @property
    def evidence_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


class CeremonyVerifier(Protocol):
    """Verifier for ceremony evidence, configured by the control-plane owner.

    Structurally identical to the approval verifier contract so an existing
    verification adapter (Ed25519, P-256) can be configured with ceremony
    identity and a ceremony key. It is verification-only: it cannot issue
    evidence.

    Contract: ``key_fingerprint`` MUST be derived from the verification key
    material itself (for the shipped adapters, SHA-256 of the pinned public
    key, computed at construction and read-only thereafter), never free
    metadata chosen by the implementation. The kernel compares the
    configured verifier's fingerprint against the pinned ``CeremonyTrust``
    and policy construction rejects a ceremony fingerprint equal to the
    approval fingerprint; those checks establish key separation only when
    both fingerprints are honestly key-derived. A custom verifier whose
    fingerprint merely asserts an identity while its ``verify`` delegates
    to the approval key defeats them, and no in-process check can detect
    that: verifier implementations are trusted control-plane code, exactly
    as on the approval side. Deployments that need separation as a proved
    property use the shipped key-derived adapters.
    """

    authority_id: str
    verifier_id: str
    key_id: str
    algorithm: str
    key_fingerprint: str

    def verify(self, payload: bytes, signature: str) -> bool:
        """Return true only for a signature from the ceremony authority."""


class _KeyDerivedCeremonyVerifier:
    """Base for the shipped ceremony verifiers.

    Identity and the key fingerprint are computed or captured once, at
    construction, from the pinned public key, and are exposed read-only:
    there is no setter, so a configured verifier cannot be re-labelled
    after the fact, and wrapping one of these adapters cannot change the
    fingerprint it reports — a wrapper around the approval key's adapter
    still reports the approval key's fingerprint.
    """

    algorithm: str

    def __init__(
        self,
        *,
        authority_id: str,
        verifier_id: str,
        key_id: str,
        key_fingerprint: str,
    ) -> None:
        for value, field in (
            (authority_id, "authority_id"),
            (verifier_id, "verifier_id"),
            (key_id, "key_id"),
        ):
            _require_text(value, field)
        _require_sha256(key_fingerprint, "key_fingerprint")
        self.__authority_id = authority_id
        self.__verifier_id = verifier_id
        self.__key_id = key_id
        self.__key_fingerprint = key_fingerprint

    @property
    def authority_id(self) -> str:
        return self.__authority_id

    @property
    def verifier_id(self) -> str:
        return self.__verifier_id

    @property
    def key_id(self) -> str:
        return self.__key_id

    @property
    def key_fingerprint(self) -> str:
        return self.__key_fingerprint


class Ed25519CeremonyVerifier(_KeyDerivedCeremonyVerifier):
    """Verification-only ceremony adapter for one pinned Ed25519 public key.

    The fingerprint is SHA-256 of the pinned public key, exactly as for
    ``Ed25519ApprovalVerifier``, so an approval key and a ceremony key with
    the same fingerprint are the same key — and policy construction
    rejects that pairing.
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
        if len(public_key) != 32:
            raise ValueError("Ed25519 public_key must be exactly 32 bytes")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError as exc:
            raise RuntimeError("Ed25519 verification requires the pulpo[authority] extra") from exc

        super().__init__(
            authority_id=authority_id,
            verifier_id=verifier_id,
            key_id=key_id,
            key_fingerprint=sha256(public_key).hexdigest(),
        )
        self.__public_key = Ed25519PublicKey.from_public_bytes(public_key)

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
            self.__public_key.verify(signature_bytes, payload)
        except (InvalidSignature, ValueError):
            return False
        return True


class P256CeremonyVerifier(_KeyDerivedCeremonyVerifier):
    """Verification-only ceremony adapter for one pinned NIST P-256 public key.

    Public keys are pinned as the 65-byte SEC1/X9.62 uncompressed point and
    signatures are the fixed 64-byte ``r || s`` lowercase-hex form, exactly
    as for ``P256ApprovalVerifier``. The fingerprint is SHA-256 of the
    pinned public key.
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

        super().__init__(
            authority_id=authority_id,
            verifier_id=verifier_id,
            key_id=key_id,
            key_fingerprint=sha256(public_key).hexdigest(),
        )
        self.__public_key = parsed

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
            self.__public_key.verify(der, payload, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            return False
        return True

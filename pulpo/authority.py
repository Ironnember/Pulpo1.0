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


@dataclass(frozen=True)
class PolicyEnvelope:
    """Signed, versioned policy issued by the pinned authority.

    The envelope is the authenticated current policy head: ``version`` and
    ``previous_policy_hash`` chain policies in order, and ``signature`` is
    verified at kernel construction against the already-pinned issuer
    ``key_fingerprint`` (via the envelope's ``trust_hash`` binding). The
    envelope carries no authority of its own; it only proves that the holder
    of the issuer key issued exactly this policy version. A policy without a
    pinned authority trust has no issuer key, so it has no envelope.
    """

    policy_hash: str
    version: int
    previous_policy_hash: str | None
    authority_id: str
    verifier_id: str
    key_id: str
    deployment_id: str
    trust_hash: str
    signature: str
    schema: str = "pulpo.policy-envelope.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.key_id, "key_id"),
            (self.deployment_id, "deployment_id"),
        ):
            _require_text(value, field)
        _require_sha256(self.policy_hash, "policy_hash")
        _require_sha256(self.trust_hash, "trust_hash")
        if self.previous_policy_hash is not None:
            _require_sha256(self.previous_policy_hash, "previous_policy_hash")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("version must be a positive integer")
        if self.version == 1 and self.previous_policy_hash is not None:
            raise ValueError("genesis policy envelope must not carry a previous policy hash")
        if self.version > 1 and self.previous_policy_hash is None:
            raise ValueError("policy envelope above genesis requires a previous policy hash")
        if self.schema != "pulpo.policy-envelope.v1":
            raise ValueError("unsupported policy envelope schema")

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


@dataclass(frozen=True)
class EnrolledKeyTrust:
    """One key enrolled in a dual-control trust: a signer, the veto, or the fallback.

    Enrollment is a public binding (key id, algorithm, fingerprint) fixed by
    policy at genesis. The private half never enters this repository; what is
    enrolled here is only what a verifier needs to recognize the key.
    """

    key_id: str
    algorithm: str
    key_fingerprint: str

    def __post_init__(self) -> None:
        _require_text(self.key_id, "key_id")
        _require_text(self.algorithm, "algorithm")
        _require_sha256(self.key_fingerprint, "key_fingerprint")


@dataclass(frozen=True)
class DualControlTrust:
    """Public trust anchor for envelope schema v2 (signer-custody decision).

    Policy authority under this anchor is held jointly: exactly two enrolled
    signer keys must both sign every policy envelope (dual control), a third
    distinct key holds the policy-layer veto, and a fourth distinct key is
    the Operations Manager fallback for the standing veto only. All four
    keys must be distinct from each other; the kernel additionally refuses
    any of them colliding with the policy's ceremony key. Distinctness is
    judged on both key id and fingerprint, so one key cannot enroll twice
    under two names and two names cannot enroll one key.
    """

    authority_id: str
    verifier_id: str
    deployment_id: str
    signers: tuple[EnrolledKeyTrust, EnrolledKeyTrust]
    veto: EnrolledKeyTrust
    fallback: EnrolledKeyTrust
    schema: str = "pulpo.dual-control-trust.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.deployment_id, "deployment_id"),
        ):
            _require_text(value, field)
        if len(self.signers) != 2:
            raise ValueError("dual-control trust enrolls exactly two signer keys")
        enrolled = [*self.signers, self.veto, self.fallback]
        key_ids = [key.key_id for key in enrolled]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("dual-control enrolled key ids must be distinct")
        fingerprints = [key.key_fingerprint for key in enrolled]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("dual-control enrolled keys must be distinct")
        if self.schema != "pulpo.dual-control-trust.v1":
            raise ValueError("unsupported dual-control trust schema")

    @property
    def trust_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class EnvelopeSignature:
    """One enrolled signer's signature over a policy envelope v2."""

    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _require_text(self.key_id, "key_id")


@dataclass(frozen=True)
class PolicyEnvelopeV2:
    """Dual-signed, versioned policy issued under a dual-control trust.

    Schema v2 of the policy envelope (the v1 envelope remains the era of
    chains that began under it; a chain's era is fixed by its first recorded
    head and never silently changes). Both enrolled signer keys must sign:
    the signed payload binds the exact set of signer key ids, so a signature
    cannot be transplanted into a different pairing, and neither signer
    alone can advance policy. The envelope carries no authority of its own;
    it proves the two enrolled signers jointly issued exactly this policy
    version.
    """

    policy_hash: str
    version: int
    previous_policy_hash: str | None
    authority_id: str
    verifier_id: str
    deployment_id: str
    trust_hash: str
    signatures: tuple[EnvelopeSignature, ...]
    schema: str = "pulpo.policy-envelope.v2"

    def __post_init__(self) -> None:
        for value, field in (
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.deployment_id, "deployment_id"),
        ):
            _require_text(value, field)
        _require_sha256(self.policy_hash, "policy_hash")
        _require_sha256(self.trust_hash, "trust_hash")
        if self.previous_policy_hash is not None:
            _require_sha256(self.previous_policy_hash, "previous_policy_hash")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("version must be a positive integer")
        if self.version == 1 and self.previous_policy_hash is not None:
            raise ValueError("genesis policy envelope must not carry a previous policy hash")
        if self.version > 1 and self.previous_policy_hash is None:
            raise ValueError("policy envelope above genesis requires a previous policy hash")
        key_ids = [entry.key_id for entry in self.signatures]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("policy envelope signatures must not repeat a signer key")
        if self.schema != "pulpo.policy-envelope.v2":
            raise ValueError("unsupported policy envelope schema")

    @property
    def signer_key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(entry.key_id for entry in self.signatures))

    def signing_payload(self) -> dict[str, object]:
        payload = {
            key: value for key, value in asdict(self).items() if key != "signatures"
        }
        payload["signer_key_ids"] = sorted(entry.key_id for entry in self.signatures)
        return payload

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_payload())

    @property
    def signing_payload_hash(self) -> str:
        return sha256(self.signing_bytes()).hexdigest()

    @property
    def envelope_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class PolicyVeto:
    """Signed veto-registry record, produced outside the governed worker.

    The veto is policy-layer only. ``targeted`` names one envelope hash and
    kills it permanently; it can be signed only by the veto key and lifted
    by no one. ``standing`` halts all policy advances until its mandatory
    positive expiry (door-two ◆1: no unbounded form, not even a veto);
    ``standing_renewal`` extends a standing veto and ``standing_lift``
    clears one. Standing acts may be signed by the veto key at any time, or
    by the enrolled Operations Manager fallback key once the chained
    fallback trigger has run (see the kernel's intake rules); targeted acts
    never delegate. ``fallback_request`` is the fallback key's chained
    request that starts the 24-hour silence clock. Every record is bound to
    the dual-control trust it acts under.
    """

    kind: str
    authority_id: str
    verifier_id: str
    deployment_id: str
    trust_hash: str
    key_id: str
    nonce: str
    issued_at_ns: int
    signature: str
    envelope_hash: str | None = None
    expires_at_ns: int | None = None
    schema: str = "pulpo.policy-veto.v1"

    def __post_init__(self) -> None:
        kinds = ("targeted", "standing", "standing_renewal", "standing_lift", "fallback_request")
        if self.kind not in kinds:
            raise ValueError("unsupported policy veto kind")
        for value, field in (
            (self.authority_id, "authority_id"),
            (self.verifier_id, "verifier_id"),
            (self.deployment_id, "deployment_id"),
            (self.key_id, "key_id"),
            (self.nonce, "nonce"),
        ):
            _require_text(value, field)
        _require_sha256(self.trust_hash, "trust_hash")
        if isinstance(self.issued_at_ns, bool) or not isinstance(self.issued_at_ns, int) or self.issued_at_ns <= 0:
            raise ValueError("issued_at_ns must be positive")
        if self.kind == "targeted":
            if self.envelope_hash is None:
                raise ValueError("targeted policy veto requires an envelope hash")
            _require_sha256(self.envelope_hash, "envelope_hash")
            if self.expires_at_ns is not None:
                raise ValueError("targeted policy veto must not carry an expiry")
        elif self.kind in ("standing", "standing_renewal"):
            if self.envelope_hash is not None:
                raise ValueError("standing policy veto must not name an envelope")
            if isinstance(self.expires_at_ns, bool) or not isinstance(self.expires_at_ns, int):
                raise ValueError("standing policy veto requires an expiry")
            if self.expires_at_ns <= self.issued_at_ns:
                raise ValueError("standing policy veto expiry must be greater than issued_at_ns")
        else:  # standing_lift, fallback_request
            if self.envelope_hash is not None or self.expires_at_ns is not None:
                raise ValueError("policy veto record carries fields its kind forbids")
        if self.schema != "pulpo.policy-veto.v1":
            raise ValueError("unsupported policy veto schema")

    def signing_payload(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_payload())

    @property
    def veto_hash(self) -> str:
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

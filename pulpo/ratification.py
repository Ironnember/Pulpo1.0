from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Callable, Literal

from .effect_reconcile import EffectReconciliation


RatificationDecision = Literal["ratify", "reject"]
RatificationStatus = Literal[
    "ratified",
    "rejected",
    "insufficient_evidence",
    "constitutional_mismatch",
]
SignatureVerifier = Callable[[str, bytes, str], bool]


class RatificationError(ValueError):
    """Raised when a ratification object violates the frozen boundary."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hash_json(value: object) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def _require_digest(value: str, reason: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RatificationError(reason)


@dataclass(frozen=True)
class RatificationTrust:
    """Frozen trust roots for ratification.

    Governance identities are deliberately disjoint from ratifier identities.
    Changing either set is itself a governance configuration change; this
    object does not create or expand authority.
    """

    trusted_ratifier_fingerprints: frozenset[str]
    governance_fingerprints: frozenset[str]

    def __post_init__(self) -> None:
        if not self.trusted_ratifier_fingerprints:
            raise RatificationError("trusted_ratifier_required")
        for fingerprint in self.trusted_ratifier_fingerprints:
            _require_digest(fingerprint, "invalid_ratifier_fingerprint")
        for fingerprint in self.governance_fingerprints:
            _require_digest(fingerprint, "invalid_governance_fingerprint")
        if self.trusted_ratifier_fingerprints & self.governance_fingerprints:
            raise RatificationError("ratifier_must_be_independent")


@dataclass(frozen=True)
class RatificationAttestation:
    ratifier_id: str
    ratifier_key_fingerprint: str
    reconciliation_hash: str
    effect_envelope_hash: str
    constitutional_proof_hash: str
    decision: RatificationDecision
    issued_at_ns: int
    expires_at_ns: int
    signature: str
    schema: str = "pulpo.ratification-attestation.v0"

    def __post_init__(self) -> None:
        if not self.ratifier_id:
            raise RatificationError("ratifier_id_required")
        _require_digest(self.ratifier_key_fingerprint, "invalid_ratifier_fingerprint")
        _require_digest(self.reconciliation_hash, "invalid_reconciliation_hash")
        _require_digest(self.effect_envelope_hash, "invalid_effect_envelope_hash")
        _require_digest(self.constitutional_proof_hash, "invalid_constitutional_proof_hash")
        if self.decision not in ("ratify", "reject"):
            raise RatificationError("invalid_ratification_decision")
        if self.issued_at_ns <= 0:
            raise RatificationError("invalid_ratification_issue_time")
        if self.expires_at_ns <= self.issued_at_ns:
            raise RatificationError("invalid_ratification_expiry")
        if not self.signature:
            raise RatificationError("ratification_signature_required")

    @property
    def signing_payload(self) -> bytes:
        return _canonical_json(
            {
                "schema": self.schema,
                "ratifier_id": self.ratifier_id,
                "ratifier_key_fingerprint": self.ratifier_key_fingerprint,
                "reconciliation_hash": self.reconciliation_hash,
                "effect_envelope_hash": self.effect_envelope_hash,
                "constitutional_proof_hash": self.constitutional_proof_hash,
                "decision": self.decision,
                "issued_at_ns": self.issued_at_ns,
                "expires_at_ns": self.expires_at_ns,
            }
        )

    @property
    def attestation_hash(self) -> str:
        return _hash_json(
            {
                "payload": self.signing_payload.decode("utf-8"),
                "signature": self.signature,
            }
        )


@dataclass(frozen=True)
class RatificationResult:
    status: RatificationStatus
    reason: str
    reconciliation_hash: str
    ratifier_id: str | None = None
    ratifier_key_fingerprint: str | None = None
    attestation_hash: str | None = None

    @property
    def official(self) -> bool:
        return self.status == "ratified"


def evaluate_ratification(
    reconciliation: EffectReconciliation,
    *,
    expected_constitutional_proof_hash: str,
    trust: RatificationTrust,
    attestation: RatificationAttestation | None,
    now_ns: int,
    verify_signature: SignatureVerifier,
) -> RatificationResult:
    """Evaluate finality without allowing Pulpo to self-ratify.

    A verified reconciliation is necessary but not sufficient. Finality exists
    only when a separately trusted, non-governance ratifier signs the exact
    reconciliation and constitutional proof package. This function creates no
    authority, permit, execution right, reconciliation, or canonical mutation.
    """

    _require_digest(expected_constitutional_proof_hash, "invalid_constitutional_proof_hash")
    if now_ns <= 0:
        raise RatificationError("invalid_ratification_evaluation_time")

    reconciliation_hash = reconciliation.reconciliation_hash
    if reconciliation.status != "verified":
        return RatificationResult(
            status="rejected",
            reason="reconciliation_not_verified",
            reconciliation_hash=reconciliation_hash,
        )

    if attestation is None:
        return RatificationResult(
            status="insufficient_evidence",
            reason="independent_ratification_required",
            reconciliation_hash=reconciliation_hash,
        )

    common = {
        "reconciliation_hash": reconciliation_hash,
        "ratifier_id": attestation.ratifier_id,
        "ratifier_key_fingerprint": attestation.ratifier_key_fingerprint,
        "attestation_hash": attestation.attestation_hash,
    }

    if attestation.ratifier_key_fingerprint in trust.governance_fingerprints:
        return RatificationResult(
            status="constitutional_mismatch",
            reason="governance_identity_cannot_self_ratify",
            **common,
        )
    if attestation.ratifier_key_fingerprint not in trust.trusted_ratifier_fingerprints:
        return RatificationResult(
            status="constitutional_mismatch",
            reason="untrusted_ratifier",
            **common,
        )
    if attestation.reconciliation_hash != reconciliation_hash:
        return RatificationResult(
            status="constitutional_mismatch",
            reason="reconciliation_substitution",
            **common,
        )
    if attestation.effect_envelope_hash != reconciliation.effect_envelope_hash:
        return RatificationResult(
            status="constitutional_mismatch",
            reason="effect_envelope_substitution",
            **common,
        )
    if attestation.constitutional_proof_hash != expected_constitutional_proof_hash:
        return RatificationResult(
            status="constitutional_mismatch",
            reason="constitutional_proof_substitution",
            **common,
        )
    if now_ns < attestation.issued_at_ns:
        return RatificationResult(
            status="insufficient_evidence",
            reason="ratification_not_yet_valid",
            **common,
        )
    if now_ns > attestation.expires_at_ns:
        return RatificationResult(
            status="insufficient_evidence",
            reason="ratification_expired",
            **common,
        )

    try:
        signature_valid = verify_signature(
            attestation.ratifier_key_fingerprint,
            attestation.signing_payload,
            attestation.signature,
        )
    except Exception:
        return RatificationResult(
            status="insufficient_evidence",
            reason="ratifier_verification_unavailable",
            **common,
        )
    if not signature_valid:
        return RatificationResult(
            status="constitutional_mismatch",
            reason="invalid_ratifier_signature",
            **common,
        )
    if attestation.decision == "reject":
        return RatificationResult(
            status="rejected",
            reason="ratifier_rejected",
            **common,
        )

    return RatificationResult(
        status="ratified",
        reason="independent_ratification_verified",
        **common,
    )

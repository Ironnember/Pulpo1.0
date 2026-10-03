"""Non-authoritative provenance binding for exact consequential intent.

This module does not interpret language, grant authority, or create a second
ledger. It deterministically binds hashes of the evidence/derivation artifacts
that produced one proposed intent so a later approval can cover that lineage as
part of the existing exact intent hash.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_sha256(value: str, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def artifact_hash(value: str | bytes) -> str:
    """Hash one exact provenance artifact without assigning it authority."""

    if isinstance(value, str):
        payload = value.encode()
    elif isinstance(value, bytes):
        payload = value
    else:
        raise TypeError("provenance artifact must be str or bytes")
    return sha256(payload).hexdigest()


@dataclass(frozen=True)
class SemanticProvenance:
    """Hash-only lineage for one intelligence-derived proposal.

    source_hash identifies the human-origin evidence (text, audio bytes, or
    another immutable source artifact). transcription_hash is optional for
    direct-text requests. Interpretation and proposal hashes identify the exact
    downstream representations that led to the structured Pulpo intent.

    This object is evidence, not permission. Its chain_hash becomes useful only
    when explicitly bound into an Intent and then authorized through the
    existing Pulpo authority path.
    """

    source_hash: str
    interpretation_hash: str
    proposal_hash: str
    transcription_hash: str | None = None
    schema: str = "pulpo.intent-provenance.v0"

    def __post_init__(self) -> None:
        _require_sha256(self.source_hash, "source_hash")
        _require_sha256(self.interpretation_hash, "interpretation_hash")
        _require_sha256(self.proposal_hash, "proposal_hash")
        if self.transcription_hash is not None:
            _require_sha256(self.transcription_hash, "transcription_hash")
        if self.schema != "pulpo.intent-provenance.v0":
            raise ValueError("unsupported semantic provenance schema")

    @property
    def chain_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()

"""Deterministic provenance binding for exact consequential intent.

This module does not interpret language or grant authority. It accepts already
formed stage material from an interface/intelligence layer, hashes each stage in
order, and produces one opaque object hash that can be carried by the canonical
Intent and therefore by Pulpo's existing approval/permit path.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _require_digest(value: str, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def stage_hash(stage: str, content: str, *, parent_hash: str | None = None) -> str:
    """Hash one provenance stage and optionally bind it to the prior stage."""

    _require_text(stage, "stage")
    _require_text(content, "content")
    if parent_hash is not None:
        _require_digest(parent_hash, "parent_hash")
    return sha256(
        _canonical(
            {
                "schema": "pulpo.provenance-stage.v1",
                "stage": stage,
                "content": content,
                "parent_hash": parent_hash,
            }
        )
    ).hexdigest()


@dataclass(frozen=True)
class IntentProvenance:
    """Hash-only chain from human source through the exact proposed action."""

    source_kind: str
    source_hash: str
    transcript_hash: str | None
    interpretation_hash: str
    proposal_hash: str
    schema: str = "pulpo.intent-provenance.v1"

    def __post_init__(self) -> None:
        _require_text(self.source_kind, "source_kind")
        _require_digest(self.source_hash, "source_hash")
        if self.transcript_hash is not None:
            _require_digest(self.transcript_hash, "transcript_hash")
        _require_digest(self.interpretation_hash, "interpretation_hash")
        _require_digest(self.proposal_hash, "proposal_hash")
        if self.schema != "pulpo.intent-provenance.v1":
            raise ValueError("unsupported intent provenance schema")

    @classmethod
    def from_stages(
        cls,
        *,
        source_kind: str,
        source: str,
        interpretation: str,
        proposal: str,
        transcript: str | None = None,
    ) -> "IntentProvenance":
        """Build a deterministic chain without treating stage content as authority."""

        source_digest = stage_hash(f"source:{source_kind}", source)
        parent = source_digest
        transcript_digest = None
        if transcript is not None:
            transcript_digest = stage_hash("transcript", transcript, parent_hash=parent)
            parent = transcript_digest
        interpretation_digest = stage_hash("interpretation", interpretation, parent_hash=parent)
        proposal_digest = stage_hash("proposal", proposal, parent_hash=interpretation_digest)
        return cls(
            source_kind=source_kind,
            source_hash=source_digest,
            transcript_hash=transcript_digest,
            interpretation_hash=interpretation_digest,
            proposal_hash=proposal_digest,
        )

    @property
    def object_hash(self) -> str:
        """Opaque exact-object binding carried into the canonical Intent."""

        return sha256(_canonical(asdict(self))).hexdigest()

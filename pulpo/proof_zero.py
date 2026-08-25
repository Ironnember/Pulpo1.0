"""Read-only Proof Zero projection over existing Pulpo evidence.

This module classifies case-study claims and projects them for different
recipients. It does not create evidence, persist a second ledger, authorize
an action, issue a permit, or treat narrative confidence as verification.
"""

from __future__ import annotations

from dataclasses import dataclass


EVIDENCE_STATUSES = frozenset({"verified", "recorded", "inferred", "proposed", "blocked"})
PROJECTION_MODES = frozenset({"investor", "security_review", "public_founder"})


def _require_text(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


@dataclass(frozen=True)
class ProofZeroEntry:
    """One thesis-level claim resolved to pre-existing evidence references."""

    entry_id: str
    claim: str
    status: str
    evidence_refs: tuple[str, ...]
    scope: str
    authority_effect: str = "none"
    remaining_gap: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.entry_id, "entry_id")
        _require_text(self.claim, "claim")
        _require_text(self.scope, "scope")
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError("unknown evidence status")
        if self.authority_effect != "none":
            raise ValueError("Proof Zero evidence cannot alter authority")
        if any(not ref or not ref.strip() for ref in self.evidence_refs):
            raise ValueError("evidence_refs must contain only non-empty values")
        if self.status in {"verified", "recorded"} and not self.evidence_refs:
            raise ValueError(f"{self.status} claims require evidence references")
        if self.status == "blocked":
            if self.remaining_gap is None:
                raise ValueError("blocked claims require a named remaining gap")
            _require_text(self.remaining_gap, "remaining_gap")


@dataclass(frozen=True)
class ProofZeroProjection:
    """Recipient-specific expression with traceability preserved."""

    mode: str
    entries: tuple[ProofZeroEntry, ...]

    def __post_init__(self) -> None:
        if self.mode not in PROJECTION_MODES:
            raise ValueError("unknown projection mode")
        if not self.entries:
            raise ValueError("projection requires at least one entry")

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(ref for entry in self.entries for ref in entry.evidence_refs))


def project_proof_zero(entries: tuple[ProofZeroEntry, ...], *, mode: str) -> ProofZeroProjection:
    """Create a read-only projection without changing claim status or authority."""

    return ProofZeroProjection(mode=mode, entries=entries)


def eligible_for_consequential_reference(entry: ProofZeroEntry) -> bool:
    """Only verified claims may be referred onward; this never authorizes use."""

    return entry.status == "verified" and bool(entry.evidence_refs)

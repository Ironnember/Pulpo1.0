"""Advisory assessment-completion gate; not a source of execution authority.

A passing record is eligible for review, never evidence of legitimate consequence.
External reviewers must authenticate provenance and verify underlying artifacts.
"""
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class GladiatorRecord:
    object_id: str
    source_revision: str
    pulpo_assessment_ref: str
    tournament_ref: str
    teams: Tuple[str, ...]
    battle_refs: Tuple[str, ...]
    independent_verdict_ref: str
    reconciliation_ref: str
    unresolved_risks: Tuple[str, ...]
    held_out_ref: str


def completion_eligible(record: GladiatorRecord, *, expected_object: str,
                        expected_revision: str) -> bool:
    """Reject incomplete, substituted, or self-attested assessment records.

    This checks presence and binding only; it does not validate signatures,
    independence, battle results, or source authenticity.
    """
    if not isinstance(record, GladiatorRecord):
        return False
    if not expected_object or not expected_revision:
        return False
    if record.object_id != expected_object or record.source_revision != expected_revision:
        return False
    required = (record.pulpo_assessment_ref, record.tournament_ref,
                record.independent_verdict_ref, record.reconciliation_ref,
                record.held_out_ref)
    if not all(isinstance(x, str) and x.strip() for x in required):
        return False
    if len(record.teams) < 2 or len(set(record.teams)) != len(record.teams):
        return False
    if not record.battle_refs or any(not x.strip() for x in record.battle_refs):
        return False
    if any(not isinstance(x, str) for x in record.unresolved_risks):
        return False
    return True

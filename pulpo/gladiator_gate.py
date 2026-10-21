"""Advisory, fail-closed assessment record schema gate (not authority).

Eligibility means structurally ready for independent review only. Evidence
references, issuer independence and actual outcomes are NOT authenticated here.
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
    independent_verdict: str = "UNKNOWN"
    reconciliation_state: str = "PENDING"
    completion_claim: str = "REVIEW_PENDING"


def _nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _strings(value: object, *, minimum: int = 0, distinct: bool = False) -> bool:
    if type(value) is not tuple or len(value) < minimum:
        return False
    if not all(_nonempty(item) for item in value):
        return False
    return not distinct or len(set(value)) == len(value)


def completion_eligible(record: GladiatorRecord, *, expected_object: str,
                        expected_revision: str) -> bool:
    """Check exact identity and closed-state structural completeness.

    VERIFIED here is only a caller-supplied assessment claim, not an
    independently established successful consequence. Never use this
    boolean as an execution permit or as proof of external consequence.
    """
    if type(record) is not GladiatorRecord:
        return False
    if not _nonempty(expected_object) or not _nonempty(expected_revision):
        return False
    if record.object_id != expected_object or record.source_revision != expected_revision:
        return False
    refs = (record.pulpo_assessment_ref, record.tournament_ref,
            record.independent_verdict_ref, record.reconciliation_ref,
            record.held_out_ref)
    if not all(_nonempty(ref) for ref in refs):
        return False
    if not _strings(record.teams, minimum=2, distinct=True):
        return False
    if not _strings(record.battle_refs, minimum=1, distinct=True):
        return False
    if not _strings(record.unresolved_risks):
        return False
    if record.independent_verdict not in ("PASS", "DENY", "UNKNOWN"):
        return False
    if record.reconciliation_state not in ("COMPLETE", "PENDING", "UNKNOWN"):
        return False
    if record.completion_claim not in ("VERIFIED", "CLOSED_DENIED", "CLOSED_UNKNOWN", "REVIEW_PENDING"):
        return False
    if record.completion_claim == "VERIFIED":
        return record.independent_verdict == "PASS" and record.reconciliation_state == "COMPLETE"
    if record.completion_claim == "CLOSED_DENIED":
        return record.independent_verdict == "DENY" and record.reconciliation_state == "COMPLETE"
    if record.completion_claim == "CLOSED_UNKNOWN":
        return record.independent_verdict == "UNKNOWN" and record.reconciliation_state == "COMPLETE"
    return True

"""Read-only semantic projection onto Pulpo's existing canonical audit.

This module is NOT an issuer authenticator or an execution authority.
"""
from .gladiator_gate import GladiatorRecord, completion_eligible

# These are assessment event labels, not a second ledger or authority schema.
ROLES = ("pulpo_assessment", "gladiator_tournament", "gladiator_battle",
         "independent_verdict", "reconciliation", "held_out_evaluation")


def audit_references_present(kernel, record: GladiatorRecord, *,
                             expected_object: str, expected_revision: str) -> bool:
    """Check audit integrity, object/revision, and evidence role.

    Passing this projection proves only structural audit membership.
    Caller-written, correctly labeled records remain untrusted.
    """
    if not completion_eligible(record, expected_object=expected_object,
                               expected_revision=expected_revision):
        return False
    try:
        if kernel.verify_audit() is not True:
            return False
        audit = kernel.audit
    except (AttributeError, RuntimeError, ValueError, TypeError):
        return False
    expected = [
        (record.pulpo_assessment_ref, ROLES[0]),
        (record.tournament_ref, ROLES[1]),
        *((ref, ROLES[2]) for ref in record.battle_refs),
        (record.independent_verdict_ref, ROLES[3]),
        (record.reconciliation_ref, ROLES[4]),
        (record.held_out_ref, ROLES[5]),
    ]
    if len({ref for ref, _ in expected}) != len(expected):
        return False
    by_hash = {}
    for event in audit:
        if type(event) is not dict:
            return False
        digest = event.get("hash")
        if type(digest) is str:
            by_hash[digest] = event
    for ref, role in expected:
        event = by_hash.get(ref)
        if type(event) is not dict or event.get("event") != role:
            return False
        payload = event.get("payload")
        if type(payload) is not dict:
            return False
        if payload.get("object_id") != expected_object:
            return False
        if payload.get("source_revision") != expected_revision:
            return False
        if payload.get("authority_effect") != "none":
            return False
        if role == "independent_verdict" and payload.get("verdict") != record.independent_verdict:
            return False
        if role == "reconciliation" and payload.get("state") != record.reconciliation_state:
            return False
    return True

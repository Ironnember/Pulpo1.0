"""Read-only projection of Gladiator references onto Pulpo's canonical audit.

This projection NEVER writes state, grants authority, or authenticates an issuer.
"""
from .gladiator_gate import GladiatorRecord, completion_eligible


def audit_references_present(kernel, record: GladiatorRecord, *,
                             expected_object: str, expected_revision: str) -> bool:
    """Require exact-object/revision references in a verified canonical audit chain.

    References are audit record hashes, not caller-controlled prose identifiers.
    Matching payload fields establish recorded binding only, NOT independence.
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
    refs = (record.pulpo_assessment_ref, record.tournament_ref,
            *record.battle_refs, record.independent_verdict_ref,
            record.reconciliation_ref, record.held_out_ref)
    if len(refs) != len(set(refs)):
        return False
    by_hash = {}
    for event in audit:
        if type(event) is not dict:
            return False
        digest = event.get("hash")
        if type(digest) is str:
            by_hash[digest] = event
    for ref in refs:
        if ref not in by_hash:
            return False
        payload = by_hash[ref].get("payload")
        if type(payload) is not dict:
            return False
        if payload.get("object_id") != expected_object:
            return False
        if payload.get("source_revision") != expected_revision:
            return False
        if payload.get("authority_effect") != "none":
            return False
    return True

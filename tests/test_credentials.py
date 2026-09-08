from dataclasses import fields

from pulpo.credentials import (
    AgentCredential,
    CredentialEvaluator,
    CredentialRequirement,
)


def credential(**overrides):
    values = {
        "credential_id": "cred-1",
        "issuer_id": "certifier.example",
        "subject_principal": "agent:security-1",
        "qualification": "agentic-ai-security",
        "scopes": ("security-review", "sandbox-analysis"),
        "issued_at_ns": 100,
        "expires_at_ns": 1000,
        "evidence_digest": "sha256:assessment-evidence",
        "revocation_ref": "https://certifier.example/revocations/cred-1",
    }
    values.update(overrides)
    return AgentCredential(**values)


def evaluator(**overrides):
    values = {
        "trusted_issuer_ids": frozenset({"certifier.example"}),
    }
    values.update(overrides)
    return CredentialEvaluator(**values)


def requirement(**overrides):
    values = {"qualification": "agentic-ai-security", "scope": "security-review"}
    values.update(overrides)
    return CredentialRequirement(**values)


def test_matching_credential_is_eligible_but_assessment_has_no_authority_fields():
    result = evaluator().assess(
        credential(),
        principal="agent:security-1",
        requirement=requirement(),
        now_ns=500,
    )

    assert result.eligible is True
    assert result.reason == "credential_eligible"
    names = {field.name for field in fields(result)}
    assert names == {
        "eligible",
        "reason",
        "credential_hash",
        "issuer_id",
        "subject_principal",
        "qualification",
    }
    assert not ({"permit", "authority", "budget", "decision", "executor"} & names)


def test_untrusted_issuer_is_not_eligible():
    result = evaluator().assess(
        credential(issuer_id="unknown.example"),
        principal="agent:security-1",
        requirement=requirement(),
        now_ns=500,
    )
    assert (result.eligible, result.reason) == (False, "credential_issuer_untrusted")


def test_revoked_credential_is_not_eligible():
    result = evaluator(revoked_credential_ids=frozenset({"cred-1"})).assess(
        credential(),
        principal="agent:security-1",
        requirement=requirement(),
        now_ns=500,
    )
    assert (result.eligible, result.reason) == (False, "credential_revoked")


def test_expired_credential_is_not_eligible():
    result = evaluator().assess(
        credential(),
        principal="agent:security-1",
        requirement=requirement(),
        now_ns=1000,
    )
    assert (result.eligible, result.reason) == (False, "credential_inactive")


def test_credential_cannot_transfer_between_agent_identities():
    result = evaluator().assess(
        credential(),
        principal="agent:other",
        requirement=requirement(),
        now_ns=500,
    )
    assert (result.eligible, result.reason) == (False, "credential_subject_mismatch")


def test_qualification_mismatch_is_not_eligible():
    result = evaluator().assess(
        credential(),
        principal="agent:security-1",
        requirement=requirement(qualification="production-operator"),
        now_ns=500,
    )
    assert (result.eligible, result.reason) == (False, "credential_qualification_mismatch")


def test_scope_mismatch_is_not_eligible():
    result = evaluator().assess(
        credential(),
        principal="agent:security-1",
        requirement=requirement(scope="production-write"),
        now_ns=500,
    )
    assert (result.eligible, result.reason) == (False, "credential_scope_mismatch")


def test_credential_object_contains_no_execution_or_authority_grant():
    names = {field.name for field in fields(AgentCredential)}
    assert not (
        {
            "permit",
            "authority_grant",
            "allowed_actions",
            "max_cost",
            "budget",
            "provider_credential",
            "execution_handle",
        }
        & names
    )

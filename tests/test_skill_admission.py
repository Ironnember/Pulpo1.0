from pulpo.kernel import GovernanceKernel, Intent, Policy
from pulpo.skill_admission import (
    SkillAdmission,
    SkillAdmissionBoundary,
    SkillArtifact,
    SkillExecutionRequest,
)


def _artifact(content: bytes = b"safe skill", revision: str = "abc123") -> SkillArtifact:
    return SkillArtifact.from_bytes(
        name="trailofbits/static-analysis",
        source="https://github.com/VoltAgent/awesome-agent-skills",
        revision=revision,
        content=content,
    )


def _boundary(*, admission: SkillAdmission | None = None) -> SkillAdmissionBoundary:
    kernel = GovernanceKernel(
        Policy(allowed_actions=frozenset({"scan"}), max_cost=5),
        secret=b"s" * 32,
        clock=lambda: 1,
    )
    if admission is None:
        admission = SkillAdmission(
            artifact=_artifact(),
            allowed_actions=frozenset({"scan"}),
            resource_prefixes=("repo:Ironnember/Pulpo1.0",),
            max_cost=0,
        )
    return SkillAdmissionBoundary(kernel, (admission,))


def _request(artifact: SkillArtifact | None = None, **intent_changes) -> SkillExecutionRequest:
    values = {
        "principal": "agent:test",
        "action": "scan",
        "resource": "repo:Ironnember/Pulpo1.0",
        "cost": 0,
        "session_id": "skill-proof",
    }
    values.update(intent_changes)
    return SkillExecutionRequest(artifact or _artifact(), Intent(**values))


def test_unapproved_skill_cannot_execute():
    boundary = SkillAdmissionBoundary(
        GovernanceKernel(Policy(allowed_actions=frozenset({"scan"}), max_cost=5), secret=b"s" * 32, clock=lambda: 1),
        (),
    )
    decision = boundary.evaluate(_request())
    assert decision.outcome == "deny"
    assert decision.reason == "skill_not_admitted"


def test_exact_admitted_artifact_reaches_existing_kernel_and_consumes_once():
    boundary = _boundary()
    request = _request()
    decision = boundary.evaluate(request)
    assert decision.outcome == "allow"
    assert decision.permit is not None
    assert boundary.consume(request, decision.permit) is True
    assert boundary.consume(request, decision.permit) is False


def test_upstream_content_change_invalidates_admission():
    boundary = _boundary()
    changed = _artifact(content=b"changed upstream skill")
    decision = boundary.evaluate(_request(changed))
    assert decision.outcome == "deny"
    assert decision.reason == "skill_digest_mismatch"


def test_revision_change_invalidates_admission_even_if_content_matches():
    boundary = _boundary()
    changed = _artifact(revision="def456")
    decision = boundary.evaluate(_request(changed))
    assert decision.outcome == "deny"
    assert decision.reason == "skill_revision_mismatch"


def test_skill_cannot_broaden_action_or_resource_scope():
    boundary = _boundary()
    action = boundary.evaluate(_request(action="delete"))
    resource = boundary.evaluate(_request(resource="repo:someone/else"))
    assert action.reason == "skill_action_not_allowed"
    assert resource.reason == "skill_resource_not_allowed"


def test_skill_cannot_broaden_budget():
    boundary = _boundary()
    decision = boundary.evaluate(_request(cost=1))
    assert decision.outcome == "deny"
    assert decision.reason == "skill_budget_exceeded"


def test_kernel_policy_still_has_final_authority():
    artifact = _artifact()
    admission = SkillAdmission(
        artifact=artifact,
        allowed_actions=frozenset({"scan", "delete"}),
        resource_prefixes=("repo:",),
        max_cost=5,
    )
    boundary = _boundary(admission=admission)
    decision = boundary.evaluate(_request(artifact, action="delete"))
    assert decision.outcome == "deny"
    assert decision.reason == "action_not_allowed"


def test_revoked_projection_denies_after_restart_and_blocks_preexisting_permit():
    artifact = _artifact()
    active = SkillAdmission(
        artifact=artifact,
        allowed_actions=frozenset({"scan"}),
        resource_prefixes=("repo:Ironnember/Pulpo1.0",),
        max_cost=0,
    )
    kernel = GovernanceKernel(
        Policy(allowed_actions=frozenset({"scan"}), max_cost=5),
        secret=b"s" * 32,
        clock=lambda: 1,
    )
    before = SkillAdmissionBoundary(kernel, (active,))
    request = _request(artifact)
    permit = before.evaluate(request).permit
    assert permit is not None

    revoked = SkillAdmission(
        artifact=artifact,
        allowed_actions=active.allowed_actions,
        resource_prefixes=active.resource_prefixes,
        max_cost=active.max_cost,
        revoked=True,
    )
    after = SkillAdmissionBoundary(kernel, (revoked,))
    assert after.evaluate(request).reason == "skill_revoked"
    assert after.consume(request, permit) is False

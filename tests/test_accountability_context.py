from __future__ import annotations

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.accountability import AccountableContext, AccountableGovernance

from authority_support import HmacTestVerifier, signed_envelope, trust_for


class Clock:
    def __init__(self, value=1_000_000):
        self.value = value

    def __call__(self):
        self.value += 100
        return self.value


def make_context(**changes):
    values = {
        "context_id": "ctx-stage-c-sandbox",
        "version": 1,
        "accountable_party": "Iron & Ember accountable operator",
        "authority_source": "authority:test-owner",
        "deployment_context": "stage-c zero-cost external sandbox",
        "allowed_actions": frozenset({"deploy"}),
        "forbidden_actions": frozenset({"buy"}),
        "resource_prefixes": ("repo:allowed/",),
        "max_cost": 5,
        "evidence_requirements": ("independent_observer", "reconciliation_record"),
        "signer_trust_basis": "pinned authority verifier",
        "escalation_path": "human authority review",
        "revocation_path": "accountability.revoke approval",
        "proof_boundary": "software proof only; not external containment",
        "open_unknowns": ("real provider outcome",),
    }
    values.update(changes)
    return AccountableContext(**values)


def make_governed_kernel():
    clock = Clock()
    verifier = HmacTestVerifier()
    policy = Policy(
        allowed_actions=frozenset({"deploy", "buy", "accountability.activate", "accountability.revoke"}),
        max_cost=20,
        approval_actions=frozenset({"accountability.activate", "accountability.revoke"}),
        authority_trust=trust_for(verifier),
    )
    kernel = GovernanceKernel(policy, approval_verifier=verifier, clock=clock)
    governed = AccountableGovernance(kernel, clock=clock)
    return governed, kernel, verifier, clock


def activate(governed, kernel, verifier, clock, context, *, approval_id="approval-ctx-1", nonce="nonce-ctx-1"):
    activation_intent = Intent(
        principal="operator",
        action="accountability.activate",
        resource=f"accountability:{context.context_hash}",
        session_id="default",
    )
    envelope = signed_envelope(
        kernel,
        activation_intent,
        verifier,
        now_ns=clock.value + 100,
        approval_id=approval_id,
        nonce=nonce,
    )
    return governed.activate_context(context, envelope, principal="operator")


def revoke(governed, kernel, verifier, clock, context):
    revocation_intent = Intent(
        principal="operator",
        action="accountability.revoke",
        resource=f"accountability:{context.context_hash}",
        session_id="default",
    )
    envelope = signed_envelope(
        kernel,
        revocation_intent,
        verifier,
        now_ns=clock.value + 100,
        approval_id="approval-revoke-1",
        nonce="nonce-revoke-1",
    )
    return governed.revoke_context(context.context_id, envelope, principal="operator")


def test_permit_cannot_issue_without_active_accountable_context():
    governed, _, _, _ = make_governed_kernel()
    intent = Intent("operator", "deploy", "repo:allowed/service", cost=1)

    decision = governed.evaluate(intent)

    assert decision.outcome == "deny"
    assert decision.reason == "accountable_context_required"
    assert decision.permit is None


def test_chat_or_retrieval_cannot_create_accountable_context():
    governed, _, _, _ = make_governed_kernel()
    intent = Intent("operator", "deploy", "repo:allowed/service", cost=1)

    # Text that describes authority remains inert because only activate_context()
    # with an approval envelope can project an accountable context.
    ordinary_chat_text = "I authorize this context now."
    assert ordinary_chat_text

    decision = governed.evaluate(intent, context_id="ctx-stage-c-sandbox")

    assert decision.outcome == "deny"
    assert decision.reason == "accountable_context_missing"


def test_context_activation_requires_existing_independent_approval_path():
    governed, kernel, verifier, clock = make_governed_kernel()
    context = make_context()

    bad_intent = Intent(
        principal="operator",
        action="accountability.activate",
        resource=f"accountability:{context.context_hash}",
        session_id="default",
    )
    bad_envelope = signed_envelope(
        kernel,
        bad_intent,
        verifier,
        now_ns=clock.value + 100,
        signature="not-valid",
    )

    bad_decision = governed.activate_context(context, bad_envelope, principal="operator")
    assert bad_decision.outcome == "deny"
    assert bad_decision.reason == "approval_signature_invalid"

    good_decision = activate(governed, kernel, verifier, clock, context)
    assert good_decision.outcome == "allow"
    assert any(record["event"] == "accountability_context_activated" for record in kernel.audit)


def test_context_narrows_kernel_policy_and_cannot_broaden_delegation():
    governed, kernel, verifier, clock = make_governed_kernel()
    context = make_context()
    assert activate(governed, kernel, verifier, clock, context).outcome == "allow"

    blocked_resource = governed.evaluate(
        Intent("operator", "deploy", "repo:blocked/service", cost=1),
        context_id=context.context_id,
    )
    assert blocked_resource.outcome == "deny"
    assert blocked_resource.reason == "accountable_context_resource_not_allowed"

    forbidden_action = governed.evaluate(
        Intent("operator", "buy", "repo:allowed/service", cost=1),
        context_id=context.context_id,
    )
    assert forbidden_action.outcome == "deny"
    assert forbidden_action.reason == "accountable_context_action_forbidden"

    budget_broaden = governed.evaluate(
        Intent("operator", "deploy", "repo:allowed/service", cost=6),
        context_id=context.context_id,
    )
    assert budget_broaden.outcome == "deny"
    assert budget_broaden.reason == "accountable_context_budget_exceeded"


def test_revocation_invalidates_later_permit_consumption():
    governed, kernel, verifier, clock = make_governed_kernel()
    context = make_context()
    assert activate(governed, kernel, verifier, clock, context).outcome == "allow"

    intent = Intent("operator", "deploy", "repo:allowed/service", cost=1)
    allowed = governed.evaluate(intent, context_id=context.context_id)
    assert allowed.outcome == "allow"
    assert allowed.permit is not None

    assert revoke(governed, kernel, verifier, clock, context).outcome == "allow"

    assert governed.consume(allowed.permit, intent, context_id=context.context_id) is False
    assert any(
        record["event"] == "permit_consumption_rejected"
        and record["payload"]["reason"] == "accountable_context_revoked"
        for record in kernel.audit
    )


def test_wrong_or_stale_context_evidence_is_unknown_not_authority():
    governed, kernel, verifier, clock = make_governed_kernel()
    context = make_context()
    assert activate(governed, kernel, verifier, clock, context).outcome == "allow"

    mismatch = governed.observe_context_evidence(context.context_id, "0" * 64)
    assert mismatch.outcome == "Unknown"
    assert mismatch.reason == "accountable_context_evidence_mismatch"

    exact = governed.observe_context_evidence(context.context_id, context.context_hash)
    assert exact.outcome == "verified"
    assert exact.reason == "accountable_context_exact_match"


def test_accountability_records_use_existing_kernel_audit_not_second_ledger():
    governed, kernel, verifier, clock = make_governed_kernel()
    context = make_context()
    assert activate(governed, kernel, verifier, clock, context).outcome == "allow"

    assert not hasattr(governed, "ledger")
    assert any(record["event"] == "accountability_context_activated" for record in kernel.audit)
    assert kernel.verify_audit() is True

"""Kernel build item #2 — projection-denial audit persistence.

The gap (Codex P1 on PR #366, P2 on PR #364, verified against the
source at the time): ``GovernedDirectiveProjection.evaluate``
returned its directive-scope denials — directive not active, parent
not active, mandate (``permits``) failure, aggregate-budget early
check — directly, without a kernel call, so no audit record was
appended for them. Kernel-reached denials append exactly one record
(``decision``); consume denials append exactly one
(``permit_rejected``). A refused attempt at the projection layer was
therefore invisible to the canonical audit and to reconciliation:
``NO_PERMIT != NO_GOVERNED_EFFECT`` was violated in the evidence
direction — the denial *was* a governed effect (evidence should have
been produced) that left no trace.

The fix pinned here: the projection reports each directive-scope
denial through the kernel's fixed-schema ``record_directive_denial``
verb, appending exactly one ``directive_denial`` record per denied
attempt, with the returned Decision unchanged in every field. The
two scenario pins that documented the limitation (trajectory steps
3/3b, TCP/TLS) are flipped in their own PRs' files alongside this
one; this module pins the behavior class by class.

Honesty label: the approval verifier is a same-process HMAC test
double, as in the facade fixtures.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.incident_channel import freeze_incident_report
from pulpo.kernel import AgentGrant
from pulpo.state import AuditSigner, InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"


class SwitchClock:
    """A kernel clock whose failure mode the test arms after setup.

    The Codex P2 shape is precisely a clock that was healthy while
    directives were activated and revoked, then becomes unavailable
    at evaluation time.
    """

    def __init__(self):
        self.mode = "ok"

    def __call__(self):
        if self.mode == "raise":
            raise RuntimeError("clock exploded")
        if self.mode == "none":
            return None
        return NOW


def directive(**overrides):
    values = dict(
        directive_id="deploy-prod",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


class Fixture:
    def __init__(self, state=None, policy=None, clock=None):
        self.verifier = HmacTestVerifier()
        self.policy = policy or Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        self.state = state if state is not None else InMemoryKernelState()
        self.kernel = GovernanceKernel(
            self.policy,
            b"kernel-secret",
            approval_verifier=self.verifier,
            clock=clock if clock is not None else (lambda: NOW),
            state=self.state,
        )
        self.controller = DirectiveAuthorityController(self.kernel)
        self.projection = GovernedDirectiveProjection(self.kernel)

    def envelope_for(self, operation, d, approval_id):
        intent = self.controller.authority_intent(operation, d, operator_principal=OPERATOR)
        return signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=f"{approval_id}-nonce",
        )

    def activate(self, d, approval_id="act-1", parent=None):
        decision = self.controller.activate(
            d,
            self.envelope_for("activate_directive", d, approval_id),
            operator_principal=OPERATOR,
            parent_directive=parent,
        )
        assert decision.outcome == "allow", decision
        return decision

    def revoke(self, d, approval_id="rev-1"):
        decision = self.controller.revoke(
            d,
            self.envelope_for("revoke_directive", d, approval_id),
            operator_principal=OPERATOR,
        )
        assert decision.outcome == "allow", decision
        return decision

    def denials(self):
        return [r for r in self.state.audit if r["event"] == "directive_denial"]


class ProjectionDenialRecordTests(unittest.TestCase):
    def test_unknown_directive_denial_is_recorded_with_fixed_schema(self):
        fx = Fixture()
        d = directive()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        before = len(fx.state.audit)
        decision = fx.projection.evaluate(intent, d)
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "directive_not_authorized")
        self.assertEqual(len(fx.state.audit), before + 1)
        self.assertEqual(len(fx.denials()), 1)
        payload = fx.denials()[0]["payload"]
        self.assertEqual(
            payload,
            {
                "schema": "pulpo.directive-denial.v0",
                "directive_id": "deploy-prod",
                "version": 1,
                "directive_hash": d.directive_hash,
                "intent_hash": fx.kernel.intent_hash(intent),
                "principal": "agent:builder",
                "action": "write",
                "resource": "repo:core",
                "cost": 3,
                "session_id": "s1",
                "reason": "directive_not_authorized",
                "authority_effect": "none",
            },
        )
        self.assertTrue(fx.kernel.verify_audit())

    def test_revoked_directive_denial_is_recorded(self):
        fx = Fixture()
        d = directive()
        fx.activate(d)
        fx.revoke(d)
        decision = fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 1, "s1"), d)
        self.assertEqual(decision.reason, "directive_revoked")
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["payload"]["reason"], "directive_revoked")

    def test_parent_revoked_denial_is_recorded_against_the_child(self):
        fx = Fixture()
        parent = directive()
        fx.activate(parent, "act-parent")
        child = directive(
            directive_id="deploy-child",
            parent_directive_hash=parent.directive_hash,
        )
        fx.activate(child, "act-child", parent=parent)
        fx.revoke(parent, "rev-parent")
        decision = fx.projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 1, "s1"), child
        )
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "directive_parent_revoked")
        self.assertEqual(len(fx.denials()), 1)
        payload = fx.denials()[0]["payload"]
        self.assertEqual(payload["directive_id"], "deploy-child")
        self.assertEqual(payload["directive_hash"], child.directive_hash)
        self.assertEqual(payload["reason"], "directive_parent_revoked")

    def test_mandate_failures_are_recorded(self):
        fx = Fixture()
        d = directive()
        fx.activate(d)
        cases = [
            (Intent("agent:builder", "delete", "repo:core", 1, "s1"), "directive_action_not_allowed"),
            (Intent("agent:other", "write", "repo:core", 1, "s1"), "directive_principal_mismatch"),
            (Intent("agent:builder", "write", "repo:core", 6, "s1"), "directive_budget_exceeded"),
            (Intent("agent:builder", "write", "db:core", 1, "s1"), "directive_resource_not_allowed"),
        ]
        for intent, reason in cases:
            decision = fx.projection.evaluate(intent, d)
            self.assertEqual(decision.outcome, "deny")
            self.assertEqual(decision.reason, reason)
        self.assertEqual([r["payload"]["reason"] for r in fx.denials()], [reason for _, reason in cases])
        self.assertTrue(fx.kernel.verify_audit())

    def test_budget_early_check_denial_is_recorded(self):
        fx = Fixture()
        d = directive(aggregate_budget=8, budget_scope=("directive",))
        fx.activate(d)
        intent = Intent("agent:builder", "write", "repo:core", 5, "s1")
        first = fx.projection.evaluate(intent, d)
        self.assertEqual(first.outcome, "allow")
        self.assertTrue(fx.kernel.consume(first.permit, intent))
        self.assertEqual(fx.denials(), [])
        second = fx.projection.evaluate(intent, d)
        self.assertEqual(second.outcome, "deny")
        self.assertEqual(second.reason, "directive_aggregate_budget_exceeded")
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["payload"]["reason"], "directive_aggregate_budget_exceeded")

    def test_allow_path_appends_no_denial_record(self):
        fx = Fixture()
        d = directive()
        fx.activate(d)
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = fx.projection.evaluate(intent, d)
        self.assertEqual(decision.outcome, "allow")
        self.assertTrue(fx.kernel.consume(decision.permit, intent))
        self.assertEqual(fx.denials(), [])

    def test_kernel_path_denial_is_not_double_recorded(self):
        # The directive permits the intent (cost 4 <= directive max 5),
        # but the kernel's own agent grant caps the principal at 2:
        # the denial is the kernel's, recorded once as a decision —
        # and NOT again as a directive_denial.
        grant = AgentGrant("agent:builder", frozenset({"write"}), ("repo:",), 2)
        operator_grant = AgentGrant(
            OPERATOR, frozenset({"activate_directive", "revoke_directive"}), ("directive:",), 0
        )
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            agent_grants=(grant, operator_grant),
            authority_trust=trust_for(HmacTestVerifier()),
        )
        fx = Fixture(policy=policy)
        d = directive()
        fx.activate(d)
        intent = Intent("agent:builder", "write", "repo:core", 4, "s1")
        decisions_before = len([r for r in fx.state.audit if r["event"] == "decision"])
        decision = fx.projection.evaluate(intent, d)
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "agent_budget_exceeded")
        self.assertEqual(fx.denials(), [])
        decisions_after = len([r for r in fx.state.audit if r["event"] == "decision"])
        self.assertEqual(decisions_after, decisions_before + 1)

    def test_repeated_denials_append_one_record_each(self):
        fx = Fixture()
        d = directive()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        for _ in range(3):
            fx.projection.evaluate(intent, d)
        self.assertEqual(len(fx.denials()), 3)
        self.assertTrue(fx.kernel.verify_audit())

    def test_denial_records_are_signed_when_a_signer_is_configured(self):
        state = InMemoryKernelState(audit_signer=AuditSigner(b"audit-secret-test"))
        fx = Fixture(state=state)
        d = directive()
        fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 3, "s1"), d)
        self.assertEqual(len(fx.denials()), 1)
        self.assertIn("signature", fx.denials()[0])
        self.assertTrue(fx.kernel.verify_audit())


class ProjectionDenialClockPostureTests(unittest.TestCase):
    """Codex P2 on PR #372: the denial record must survive an
    unavailable clock.

    The projection's status denials (unknown, revoked, parent
    revoked) are computed before any trusted-time check, and before
    item #2 those paths returned their fail-closed Decision without
    touching the clock at all. The record verb therefore resolves
    its timestamp through the kernel's trusted clock and degrades
    to the 0 sentinel (the ``approval_rejected`` precedent) instead
    of propagating a clock exception, writing a ``None`` timestamp
    into the in-memory chain, or tripping the SQLite backend's
    NOT NULL timestamp constraint. The Decision returned is the one
    the projection has always returned; the denial is recorded
    exactly once; only the record's timestamp degrades.
    """

    def test_healthy_clock_stamps_the_denial_with_kernel_time(self):
        fx = Fixture()
        fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 3, "s1"), directive())
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["timestamp_ns"], NOW)

    def test_raising_clock_unknown_directive_still_denies_and_records(self):
        clock = SwitchClock()
        fx = Fixture(clock=clock)
        clock.mode = "raise"
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = fx.projection.evaluate(intent, directive())
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "directive_not_authorized")
        self.assertEqual(decision.intent_hash, fx.kernel.intent_hash(intent))
        self.assertIsNone(decision.permit)
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["timestamp_ns"], 0)
        self.assertTrue(fx.kernel.verify_audit())

    def test_raising_clock_revoked_directive_still_denies_and_records(self):
        clock = SwitchClock()
        fx = Fixture(clock=clock)
        d = directive()
        fx.activate(d)
        fx.revoke(d)
        clock.mode = "raise"
        decision = fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 1, "s1"), d)
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "directive_revoked")
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["timestamp_ns"], 0)
        self.assertTrue(fx.kernel.verify_audit())

    def test_raising_clock_parent_revoked_directive_still_denies_and_records(self):
        clock = SwitchClock()
        fx = Fixture(clock=clock)
        parent = directive()
        fx.activate(parent, "act-parent")
        child = directive(
            directive_id="deploy-child",
            parent_directive_hash=parent.directive_hash,
        )
        fx.activate(child, "act-child", parent=parent)
        fx.revoke(parent, "rev-parent")
        clock.mode = "raise"
        decision = fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 1, "s1"), child)
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "directive_parent_revoked")
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["payload"]["directive_id"], "deploy-child")
        self.assertEqual(fx.denials()[0]["timestamp_ns"], 0)
        self.assertTrue(fx.kernel.verify_audit())

    def test_none_clock_records_zero_timestamp_in_memory(self):
        clock = SwitchClock()
        fx = Fixture(clock=clock)
        clock.mode = "none"
        decision = fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 3, "s1"), directive())
        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "directive_not_authorized")
        self.assertEqual(len(fx.denials()), 1)
        self.assertEqual(fx.denials()[0]["timestamp_ns"], 0)
        self.assertTrue(fx.kernel.verify_audit())

    def test_unavailable_clock_records_zero_timestamp_in_sqlite(self):
        for mode in ("none", "raise"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                state = SQLiteKernelState(Path(td) / "state.sqlite3")
                try:
                    clock = SwitchClock()
                    fx = Fixture(state=state, clock=clock)
                    clock.mode = mode
                    decision = fx.projection.evaluate(
                        Intent("agent:builder", "write", "repo:core", 3, "s1"), directive()
                    )
                    self.assertEqual(decision.outcome, "deny")
                    self.assertEqual(decision.reason, "directive_not_authorized")
                    self.assertEqual(len(fx.denials()), 1)
                    self.assertEqual(fx.denials()[0]["timestamp_ns"], 0)
                    self.assertTrue(fx.kernel.verify_audit())
                finally:
                    state.close()


class ProjectionDenialIncidentReportTests(unittest.TestCase):
    """Codex P1 on PR #372, end to end: a projection denial recorded
    in the canonical audit must surface in the frozen incident
    report as a near-miss — before the classification fix, the same
    chain froze into a report showing zero incidents and zero
    near-misses, implying no attempt occurred."""

    def test_unknown_directive_denial_is_a_near_miss_in_the_report(self):
        fx = Fixture()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        fx.projection.evaluate(intent, directive())
        report = freeze_incident_report(PulpoOrchestrator(fx.kernel))
        self.assertEqual(report.incidents, 0)
        self.assertEqual(report.near_misses, 1)
        (record,) = report.records
        self.assertEqual(record.kind, "near_miss")
        self.assertEqual(record.source, "canonical_audit")
        self.assertEqual(record.source_detail, "directive_denial")
        self.assertEqual(record.reason, "directive_not_authorized")
        self.assertEqual(record.resolution, "not_applicable")
        self.assertTrue(record.record_id.startswith("near-miss:"))
        self.assertIn(("intent_hash", fx.kernel.intent_hash(intent)), record.anchors)
        self.assertTrue(report.audit_valid)

    def test_revoked_directive_denial_is_a_near_miss_in_the_report(self):
        fx = Fixture()
        d = directive()
        fx.activate(d)
        fx.revoke(d)
        fx.projection.evaluate(Intent("agent:builder", "write", "repo:core", 1, "s1"), d)
        report = freeze_incident_report(PulpoOrchestrator(fx.kernel))
        self.assertEqual(report.incidents, 0)
        self.assertEqual(report.near_misses, 1)
        (record,) = report.records
        self.assertEqual(record.kind, "near_miss")
        self.assertEqual(record.source_detail, "directive_denial")
        self.assertEqual(record.reason, "directive_revoked")
        self.assertTrue(report.audit_valid)


if __name__ == "__main__":
    unittest.main()

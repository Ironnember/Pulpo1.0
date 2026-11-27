"""Tests: Codex P1 fixes on PR #369 (cumulative disclosure budget).

Two findings from Codex review of the original build, both verified
in source before fixing:

P1(ii) — a missing budget policy failed OPEN. When a permit's
binding carried budget facts but the directive's policy record was
gone (deleted ``directive_budgets`` row, partial restore, dropped
in-memory entry), both backends skipped enforcement entirely: the
permit spent with no debit and no budget_status. A malformed policy
already failed closed (``budget_policy_invalid``); a missing one
now does too (``budget_policy_missing``).

P1(i) — lineage multiplication. A child directive's bucket key
names the child, so a parent capped at 30 and a child capped at 30
held independent allowances: permits under both could release 40+
against a 30-unit lineage, and every additional child multiplied
it again. Derivation narrowing stopped a child EXCEEDING the parent
per bucket, but nothing charged the ancestors. Consumption now
walks the permit's derivation lineage (from the parent links the
backends record at activation) and atomically check-and-debits
every budgeted ancestor's bucket in the same transition as the
permit's own — all buckets land or none do.

The harness (kernel builder, governed fixtures, release store) is
imported from tests.test_cumulative_disclosure_budget so these
tests run against exactly the original build's fixtures.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest

from pulpo.directives import (
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope
from tests.test_cumulative_disclosure_budget import (
    AGENT,
    NOW,
    ReleaseStore,
    audit_records,
    budgeted_directive,
    make_kernel,
    read_intent,
)
from tests.test_directives import OPERATOR, derived, directive


def activate(kernel, verifier, d, parent_directive=None) -> None:
    controller = DirectiveAuthorityController(kernel)
    intent = DirectiveAuthorityController.authority_intent(
        controller.ACTIVATE, d, operator_principal=OPERATOR
    )
    envelope = signed_envelope(
        kernel,
        intent,
        verifier,
        now_ns=NOW - 10,
        approval_id=f"activate-{d.directive_id}-{d.version}",
        nonce=f"activate-nonce-{d.directive_id}-{d.version}",
    )
    decision = controller.activate(
        d, envelope, operator_principal=OPERATOR, parent_directive=parent_directive
    )
    assert decision.outcome == "allow", decision


def child_of(parent, **overrides):
    """A derived directive aligned inside the budget harness's
    parent scope, so the budget rules are what decide each case."""
    values = dict(
        allowed_actions=frozenset({"query_records"}),
        resource_prefixes=("benchmark:crm",),
        max_cost=25,
    )
    values.update(overrides)
    return derived(parent, **values)


class LineageBehavior:
    """The lineage + missing-policy behavior contract, run against
    both state backends."""

    def make_state(self):
        raise NotImplementedError

    def permit_spent_in_store(self, state, permit: str) -> bool:
        raise NotImplementedError

    def governed(self):
        verifier = HmacTestVerifier()
        state = self.make_state()
        kernel = make_kernel(state, verifier)
        d = budgeted_directive()
        activate(kernel, verifier, d)
        return kernel, GovernedDirectiveProjection(kernel), d, state

    def governed_lineage(self, child_overrides_list, parent_overrides=None):
        verifier = HmacTestVerifier()
        self.verifier = verifier
        state = self.make_state()
        kernel = make_kernel(state, verifier)
        parent = budgeted_directive(**(parent_overrides or {}))
        activate(kernel, verifier, parent)
        children = []
        for overrides in child_overrides_list:
            child = child_of(parent, **overrides)
            activate(kernel, verifier, child, parent_directive=parent)
            children.append(child)
        return kernel, GovernedDirectiveProjection(kernel), parent, children, state

    # -- P1(i): the parent's cap binds the whole lineage -------------

    def test_lineage_child_spend_charges_the_parent_bucket(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        # Both permits issue while both fit individually (the pinned
        # acceptance shape): consumption is the decider.
        parent_permit = projection.evaluate(intent, parent).permit
        child_permit = projection.evaluate(intent, child).permit
        self.assertIsNotNone(parent_permit)
        self.assertIsNotNone(child_permit)
        # The child's consumption debits BOTH buckets atomically.
        self.assertTrue(store.access(kernel, child_permit, intent))
        self.assertEqual(20, kernel.budget_spent(child.budget_scope_key(intent)))
        self.assertEqual(20, kernel.budget_spent(parent.budget_scope_key(intent)))
        # The parent's own permit now crosses the lineage total:
        # refused, unspent, no partial debit anywhere.
        self.assertFalse(store.access(kernel, parent_permit, intent))
        self.assertEqual(1, len(store.releases))
        self.assertEqual(20, store.total_released)
        self.assertEqual(20, kernel.budget_spent(child.budget_scope_key(intent)))
        self.assertEqual(20, kernel.budget_spent(parent.budget_scope_key(intent)))
        self.assertFalse(self.permit_spent_in_store(state, parent_permit))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        # The successful consumption's record carries the ancestor
        # debit: the parent bucket was debited exactly once, by 20.
        consumed = audit_records(kernel, "permit_consumed")
        lineage = consumed[-1]["payload"]["budget_lineage"]
        self.assertEqual(1, len(lineage))
        self.assertEqual(parent.directive_id, lineage[0]["directive_id"])
        self.assertEqual(parent.version, lineage[0]["directive_version"])
        self.assertEqual(20, lineage[0]["budget_amount"])
        self.assertEqual(0, lineage[0]["budget_spent_before"])
        self.assertEqual(20, lineage[0]["budget_spent"])
        self.assertTrue(kernel.verify_audit())

    def test_lineage_parent_spend_blocks_the_child(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        parent_permit = projection.evaluate(intent, parent).permit
        child_permit = projection.evaluate(intent, child).permit
        self.assertTrue(store.access(kernel, parent_permit, intent))
        # The child's own bucket is empty and would fit — the
        # ancestor's bucket is what refuses, and the refusal takes
        # no debit from the child's bucket either.
        self.assertFalse(store.access(kernel, child_permit, intent))
        self.assertEqual(1, len(store.releases))
        self.assertEqual(0, kernel.budget_spent(child.budget_scope_key(intent)))
        self.assertEqual(20, kernel.budget_spent(parent.budget_scope_key(intent)))
        self.assertFalse(self.permit_spent_in_store(state, child_permit))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_lineage_multiple_children_share_the_parent_cap(self) -> None:
        kernel, projection, parent, (child_a, child_b), state = (
            self.governed_lineage(
                [
                    dict(directive_id="budgeted-reads-child-a", aggregate_budget=30),
                    dict(directive_id="budgeted-reads-child-b", aggregate_budget=30),
                ]
            )
        )
        store = ReleaseStore()
        intent = read_intent(20)
        permit_a = projection.evaluate(intent, child_a).permit
        permit_b = projection.evaluate(intent, child_b).permit
        self.assertTrue(store.access(kernel, permit_a, intent))
        # The second child's spend crosses the SHARED parent cap,
        # though its own bucket is untouched: siblings no longer
        # multiply the lineage allowance.
        self.assertFalse(store.access(kernel, permit_b, intent))
        self.assertEqual(1, len(store.releases))
        self.assertEqual(20, store.total_released)
        self.assertEqual(20, kernel.budget_spent(parent.budget_scope_key(intent)))
        self.assertEqual(20, kernel.budget_spent(child_a.budget_scope_key(intent)))
        self.assertEqual(0, kernel.budget_spent(child_b.budget_scope_key(intent)))
        self.assertFalse(self.permit_spent_in_store(state, permit_b))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_lineage_childs_own_tighter_cap_still_binds(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=10)]
        )
        store = ReleaseStore()
        intent = read_intent(10)
        first = projection.evaluate(intent, child).permit
        second = projection.evaluate(intent, child).permit
        self.assertTrue(store.access(kernel, first, intent))
        # The child's own narrower ceiling refuses the second spend;
        # the parent's bucket keeps exactly the one debit.
        self.assertFalse(store.access(kernel, second, intent))
        self.assertEqual(10, kernel.budget_spent(child.budget_scope_key(intent)))
        self.assertEqual(10, kernel.budget_spent(parent.budget_scope_key(intent)))
        self.assertFalse(self.permit_spent_in_store(state, second))
        self.assertTrue(kernel.verify_audit())

    def test_lineage_ancestor_bucket_uses_the_ancestors_scope(self) -> None:
        # The parent's policy is per-session with a declared reset;
        # the child must carry the identical scope (derivation
        # narrowing), and its spends resolve the parent's bucket
        # from the permit's recorded session.
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [
                dict(
                    directive_id="budgeted-reads-child",
                    aggregate_budget=30,
                    budget_scope=("directive", "session"),
                    budget_session_reset=True,
                )
            ],
            parent_overrides=dict(
                budget_scope=("directive", "session"), budget_session_reset=True
            ),
        )
        store = ReleaseStore()
        first = read_intent(20, session="session-1")
        second = read_intent(20, session="session-2")
        self.assertTrue(
            store.access(kernel, projection.evaluate(first, child).permit, first)
        )
        # A new session is a fresh bucket under the ANCESTOR's scope
        # too — the reset the policy declares, never a silent one.
        self.assertTrue(
            store.access(kernel, projection.evaluate(second, child).permit, second)
        )
        self.assertEqual(40, store.total_released)
        self.assertEqual(20, kernel.budget_spent(parent.budget_scope_key(first)))
        self.assertEqual(20, kernel.budget_spent(parent.budget_scope_key(second)))
        self.assertTrue(kernel.verify_audit())

    # -- negative control: enforcement is budget-driven --------------

    def test_budgetless_lineage_behavior_is_unchanged(self) -> None:
        verifier = HmacTestVerifier()
        state = self.make_state()
        kernel = make_kernel(state, verifier)
        parent = directive(
            directive_id="plain-reads",
            principal=AGENT,
            allowed_actions=frozenset({"query_records"}),
            resource_prefixes=("benchmark:",),
            max_cost=25,
        )
        activate(kernel, verifier, parent)
        child = child_of(parent, directive_id="plain-reads-child")
        activate(kernel, verifier, child, parent_directive=parent)
        projection = GovernedDirectiveProjection(kernel)
        store = ReleaseStore()
        intent = read_intent(20)
        # No budgets anywhere in the lineage: the pre-fix behavior,
        # exactly — both consumptions succeed and no budget keys
        # appear in any record.
        self.assertTrue(
            store.access(kernel, projection.evaluate(intent, parent).permit, intent)
        )
        self.assertTrue(
            store.access(kernel, projection.evaluate(intent, child).permit, intent)
        )
        self.assertEqual(40, store.total_released)
        for record in audit_records(kernel, "permit_consumed"):
            self.assertFalse(
                any(key.startswith("budget_") for key in record["payload"]),
                record,
            )
        self.assertTrue(kernel.verify_audit())


class InMemoryFixTests(LineageBehavior, unittest.TestCase):
    def make_state(self):
        return InMemoryKernelState()

    def permit_spent_in_store(self, state, permit: str) -> bool:
        return permit in state._spent

    # -- P1(ii): missing policy, in-memory ----------------------------

    def test_missing_budget_policy_fails_closed(self) -> None:
        kernel, projection, d, state = self.governed()
        store = ReleaseStore()
        intent = read_intent(10)
        decision = projection.evaluate(intent, d)
        self.assertEqual("allow", decision.outcome)
        # The policy entry vanishes (the in-memory shape of a
        # deleted row / partial restore): the binding still carries
        # its budget facts, so the consumption must refuse — never
        # spend against an unrecorded mandate.
        del state._directive_budgets[(d.directive_id, d.version)]
        self.assertFalse(store.access(kernel, decision.permit, intent))
        self.assertEqual(0, store.total_released)
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "budget_policy_missing", rejected[-1]["payload"]["budget_status"]
        )
        self.assertFalse(self.permit_spent_in_store(state, decision.permit))
        self.assertTrue(kernel.verify_audit())

    # -- P1(i): unwalkable lineage fails closed ------------------------

    def test_missing_parent_record_fails_closed(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        child_permit = projection.evaluate(intent, child).permit
        # The parent's record is deleted out of band: the lineage
        # cannot be walked, so the consumption refuses rather than
        # enforcing the child's bucket alone.
        del state._directives[(parent.directive_id, parent.version)]
        self.assertFalse(store.access(kernel, child_permit, intent))
        self.assertEqual(0, store.total_released)
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "budget_lineage_unresolvable", rejected[-1]["payload"]["budget_status"]
        )
        self.assertFalse(self.permit_spent_in_store(state, child_permit))
        self.assertTrue(kernel.verify_audit())

    def test_lineage_cycle_fails_closed(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        child_permit = projection.evaluate(intent, child).permit
        # Out-of-band surgery makes the parent name the child as ITS
        # parent: the walk detects the cycle and refuses, taking no
        # debit from either bucket.
        state._directive_parents[(parent.directive_id, parent.version)] = (
            child.directive_hash
        )
        self.assertFalse(store.access(kernel, child_permit, intent))
        self.assertEqual(0, store.total_released)
        self.assertEqual(0, kernel.budget_spent(parent.budget_scope_key(intent)))
        self.assertEqual(0, kernel.budget_spent(child.budget_scope_key(intent)))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "budget_lineage_unresolvable", rejected[-1]["payload"]["budget_status"]
        )
        self.assertFalse(self.permit_spent_in_store(state, child_permit))
        self.assertTrue(kernel.verify_audit())


class SQLiteFixTests(LineageBehavior, unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = f"{self._tmpdir.name}/state.db"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def make_state(self):
        return SQLiteKernelState(self.db_path)

    def permit_spent_in_store(self, state, permit: str) -> bool:
        connection = sqlite3.connect(self.db_path)
        try:
            row = connection.execute(
                "SELECT spent FROM permits WHERE permit = ?", (permit,)
            ).fetchone()
        finally:
            connection.close()
        return row is not None and row[0] == 1

    # -- P1(ii): missing policy, SQLite --------------------------------

    def test_missing_budget_policy_row_fails_closed(self) -> None:
        kernel, projection, d, state = self.governed()
        store = ReleaseStore()
        intent = read_intent(10)
        decision = projection.evaluate(intent, d)
        self.assertEqual("allow", decision.outcome)
        # The Codex scenario verbatim: the directive_budgets row is
        # deleted (corruption, incomplete restore) while the permit
        # binding keeps its budget facts.
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "DELETE FROM directive_budgets WHERE directive_id = ? AND version = ?",
            (d.directive_id, d.version),
        )
        connection.commit()
        connection.close()
        self.assertFalse(store.access(kernel, decision.permit, intent))
        self.assertEqual(0, store.total_released)
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "budget_policy_missing", rejected[-1]["payload"]["budget_status"]
        )
        self.assertFalse(self.permit_spent_in_store(state, decision.permit))
        self.assertTrue(kernel.verify_audit())
        state.close()

    # -- P1(i): unwalkable lineage fails closed ------------------------

    def test_missing_parent_record_fails_closed(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        child_permit = projection.evaluate(intent, child).permit
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "DELETE FROM directives WHERE directive_id = ? AND version = ?",
            (parent.directive_id, parent.version),
        )
        connection.commit()
        connection.close()
        self.assertFalse(store.access(kernel, child_permit, intent))
        self.assertEqual(0, store.total_released)
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "budget_lineage_unresolvable", rejected[-1]["payload"]["budget_status"]
        )
        self.assertFalse(self.permit_spent_in_store(state, child_permit))
        self.assertTrue(kernel.verify_audit())
        state.close()

    def test_lineage_cycle_fails_closed(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        child_permit = projection.evaluate(intent, child).permit
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "UPDATE directives SET parent_directive_hash = ? "
            "WHERE directive_id = ? AND version = ?",
            (child.directive_hash, parent.directive_id, parent.version),
        )
        connection.commit()
        connection.close()
        self.assertFalse(store.access(kernel, child_permit, intent))
        self.assertEqual(0, store.total_released)
        self.assertEqual(0, kernel.budget_spent(parent.budget_scope_key(intent)))
        self.assertEqual(0, kernel.budget_spent(child.budget_scope_key(intent)))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "budget_lineage_unresolvable", rejected[-1]["payload"]["budget_status"]
        )
        self.assertFalse(self.permit_spent_in_store(state, child_permit))
        self.assertTrue(kernel.verify_audit())
        state.close()

    def test_lineage_debit_survives_restart(self) -> None:
        kernel, projection, parent, (child,), state = self.governed_lineage(
            [dict(directive_id="budgeted-reads-child", aggregate_budget=30)]
        )
        store = ReleaseStore()
        intent = read_intent(20)
        self.assertTrue(
            store.access(kernel, projection.evaluate(intent, child).permit, intent)
        )
        state.close()
        # A fresh state and kernel over the same file: the ancestor
        # debit is durable canonical state, and the parent's own
        # further spend is refused against it at issuance.
        state2 = SQLiteKernelState(self.db_path)
        kernel2 = make_kernel(state2, self.verifier)
        self.assertEqual(20, kernel2.budget_spent(parent.budget_scope_key(intent)))
        self.assertEqual(20, kernel2.budget_spent(child.budget_scope_key(intent)))
        projection2 = GovernedDirectiveProjection(kernel2)
        decision = projection2.evaluate(intent, parent)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_aggregate_budget_exceeded", decision.reason)
        self.assertTrue(kernel2.verify_audit())
        state2.close()


if __name__ == "__main__":
    unittest.main()

"""Tests: cumulative (aggregate) disclosure budget — kernel build item #1.

The WorkOS/ARTEX replay (PR #368) established the gap: cost binding
was per intent only, so a sequence of individually in-limit reads
walked past the same aggregate a single bulk read could not cross —
5,250 records released against a 5,000 limit, detected by
observer-side reconciliation, prevented by nothing. The build item
(change record §8 addenda, tightened 2026-11-18) pins the design:

1. Enforcement at consumption, atomically: the state backend
   debits the aggregate budget in the SAME transition that spends
   the permit; a consumption that would cross the budget is refused
   with the permit unspent. Projection-time refusal is an early
   optimization only.
2. The release boundary enforces the permitted quantity: a permit
   for 10 records releases at most 10, observed store-side.
3. Budget scope is explicit policy, including whether a new
   session resets the allowance. No silent reset.

The pinned acceptance regression: issue two permits while both fit
the remaining allowance individually; consume them (sequentially
and concurrently) when only one fits in aggregate; verify FROM THE
STORE that exactly one release occurred.

Boundary of this evidence: the release boundary below is a test
data plane that follows the governed pattern — it releases the
consumed intent's bound quantity and no more. The kernel has no
general execution gateway (by design); an executor that releases
without consuming, or ignores the bound quantity, is off the
governed path and remains detectable by reconciliation, not
prevented. The uncapped-store negative control below proves the
cap is the boundary's governed behavior, not a kernel simulation.
"""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
import sqlite3
import tempfile
import threading
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import (
    DirectiveBudget,
    InMemoryKernelState,
    SQLiteKernelState,
    budget_scope_key,
)
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_directives import OPERATOR, derived, directive


NOW = 2_000_000
AGENT = "agent:reader"
BENCH = "benchmark:crm"
SESSION = "session-1"


def read_intent(cost: int, session: str = SESSION) -> Intent:
    return Intent(AGENT, "query_records", BENCH, cost, session)


def budgeted_directive(**overrides) -> Directive:
    values = dict(
        directive_id="budgeted-reads",
        principal=AGENT,
        allowed_actions=frozenset({"query_records"}),
        resource_prefixes=("benchmark:",),
        max_cost=25,
        aggregate_budget=30,
    )
    values.update(overrides)
    return directive(**values)


def make_kernel(state, verifier, secret: bytes = b"cumulative-budget-test-secret") -> GovernanceKernel:
    policy = Policy(
        frozenset({"query_records", "activate_directive", "revoke_directive"}),
        100_000,
        frozenset({"activate_directive", "revoke_directive"}),
        authority_trust=trust_for(verifier),
    )
    return GovernanceKernel(
        policy,
        secret=secret,
        approval_verifier=verifier,
        clock=lambda: NOW,
        state=state,
    )


def activate(kernel, verifier, d) -> None:
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
    decision = controller.activate(d, envelope, operator_principal=OPERATOR)
    assert decision.outcome == "allow", decision


class ReleaseStore:
    """A governed data plane. Records leave only through a
    successful consume, and the boundary releases at most the
    consumed intent's permitted quantity — its bound cost — however
    many the caller asks for. Actual releases are counted here,
    store-side, never from the caller's declaration."""

    def __init__(self) -> None:
        self.releases: list[tuple[str, str, int]] = []
        self.total_released = 0

    def release_count(self, intent: Intent, requested: int) -> int:
        return min(requested, intent.cost)

    def access(self, kernel, permit, intent: Intent, requested: int | None = None) -> bool:
        if requested is None:
            requested = intent.cost
        if permit is None or not kernel.consume(permit, intent):
            return False
        actual = self.release_count(intent, requested)
        self.releases.append((intent.action, intent.resource, actual))
        self.total_released += actual
        return True


class _UncappedStore(ReleaseStore):
    """Negative control: a boundary that releases whatever the
    caller asks for, ignoring the permitted quantity — the
    over-releasing data plane of the WorkOS scenario."""

    def release_count(self, intent: Intent, requested: int) -> int:
        return requested


def audit_records(kernel, event: str) -> list[dict]:
    return [r for r in kernel.audit if r["event"] == event]


class BudgetBehavior:
    """The budget behavior contract, run against both backends."""

    def make_state(self):
        raise NotImplementedError

    def permit_spent_in_store(self, state, permit: str) -> bool:
        raise NotImplementedError

    def governed(self, **directive_overrides):
        verifier = HmacTestVerifier()
        state = self.make_state()
        kernel = make_kernel(state, verifier)
        d = budgeted_directive(**directive_overrides)
        activate(kernel, verifier, d)
        return kernel, GovernedDirectiveProjection(kernel), d, state

    # -- pinned acceptance regression, sequential --------------------

    def test_pinned_acceptance_sequential(self) -> None:
        kernel, projection, d, state = self.governed()
        store = ReleaseStore()
        intent = read_intent(20)
        # Both permits issue while each fits the remaining allowance
        # (20 of 30) individually — issuance cannot see the aggregate
        # conflict, which is why consumption is the decisive check.
        first = projection.evaluate(intent, d)
        second = projection.evaluate(intent, d)
        self.assertEqual("allow", first.outcome)
        self.assertEqual("allow", second.outcome)
        self.assertNotEqual(first.permit, second.permit)

        self.assertTrue(store.access(kernel, first.permit, intent))
        # Only one fits in aggregate now: refused, permit unspent.
        self.assertFalse(store.access(kernel, second.permit, intent))

        # Verified FROM THE STORE: exactly one release occurred.
        self.assertEqual(1, len(store.releases))
        self.assertEqual(20, store.total_released)
        self.assertFalse(self.permit_spent_in_store(state, second.permit))
        key = d.budget_scope_key(intent)
        self.assertEqual(20, kernel.budget_spent(key))

        consumed = audit_records(kernel, "permit_consumed")
        self.assertEqual("within_budget", consumed[-1]["payload"]["budget_status"])
        self.assertEqual(20, consumed[-1]["payload"]["budget_amount"])
        self.assertEqual(20, consumed[-1]["payload"]["budget_spent"])
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        self.assertEqual(30, rejected[-1]["payload"]["budget_ceiling"])
        self.assertEqual(20, rejected[-1]["payload"]["budget_spent_before"])
        # The refusal did not spend the permit: presented again, it
        # is refused for the same budget reason, not as a replay.
        self.assertFalse(store.access(kernel, second.permit, intent))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        self.assertTrue(kernel.verify_audit())

    # -- quantity: the release boundary enforces the permitted amount --

    def test_quantity_boundary_releases_at_most_the_permitted_amount(self) -> None:
        kernel, projection, d, state = self.governed(aggregate_budget=1_000)
        store = ReleaseStore()
        intent = read_intent(10)
        decision = projection.evaluate(intent, d)
        self.assertEqual("allow", decision.outcome)
        # The caller asks the boundary for 250 records under a
        # 10-record permit; exactly 10 leave, observed store-side.
        self.assertTrue(store.access(kernel, decision.permit, intent, requested=250))
        self.assertEqual(10, store.total_released)
        # The debit is the permitted quantity (10), not the request.
        self.assertEqual(10, kernel.budget_spent(d.budget_scope_key(intent)))
        # Asking for fewer releases fewer — at most, not exactly.
        small = read_intent(5)
        decision = projection.evaluate(small, d)
        self.assertTrue(store.access(kernel, decision.permit, small, requested=5))
        self.assertEqual(15, store.total_released)
        self.assertTrue(kernel.verify_audit())

    def test_quantity_negative_control_uncapped_boundary(self) -> None:
        # The same governed consume under a boundary that ignores
        # the permitted quantity releases the full request: the cap
        # proven above is the boundary's governed behavior.
        kernel, projection, d, state = self.governed(aggregate_budget=1_000)
        store = _UncappedStore()
        intent = read_intent(10)
        decision = projection.evaluate(intent, d)
        self.assertTrue(store.access(kernel, decision.permit, intent, requested=250))
        self.assertEqual(250, store.total_released)

    # -- scope and session-reset semantics ----------------------------

    def test_session_scope_resets_when_the_policy_says_so(self) -> None:
        kernel, projection, d, state = self.governed(
            budget_scope=("directive", "session"), budget_session_reset=True
        )
        store = ReleaseStore()
        s1 = read_intent(20, session="session-1")
        s2 = read_intent(20, session="session-2")
        # All permits issue up front, while nothing is consumed.
        p1 = projection.evaluate(s1, d).permit
        p2 = projection.evaluate(s2, d).permit
        p1_again = projection.evaluate(s1, d).permit
        self.assertTrue(store.access(kernel, p1, s1))
        # A new session is a fresh bucket — because the policy SAYS
        # so (session is a scope component and reset is declared).
        self.assertTrue(store.access(kernel, p2, s2))
        self.assertEqual(40, store.total_released)
        self.assertEqual(20, kernel.budget_spent(d.budget_scope_key(s1)))
        self.assertEqual(20, kernel.budget_spent(d.budget_scope_key(s2)))
        # But session-1's own bucket is full: a further read there
        # is refused at consume.
        self.assertFalse(store.access(kernel, p1_again, s1))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_no_session_reset_when_the_policy_says_so(self) -> None:
        kernel, projection, d, state = self.governed()
        store = ReleaseStore()
        s1 = read_intent(20, session="session-1")
        s2 = read_intent(20, session="session-2")
        p1 = projection.evaluate(s1, d).permit
        p2 = projection.evaluate(s2, d).permit
        self.assertTrue(store.access(kernel, p1, s1))
        # Scope is the directive alone: a new session does NOT reset
        # the allowance, and the policy says so (reset is False and
        # session is not a scope component). The second session's
        # permit, issued while both fit individually, is refused at
        # consume against the shared bucket.
        self.assertFalse(store.access(kernel, p2, s2))
        self.assertEqual(20, store.total_released)
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(
            "aggregate_budget_exceeded", rejected[-1]["payload"]["budget_status"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_principal_scope_component_buckets_by_principal(self) -> None:
        # Within one directive the principal is fixed, so the
        # principal component is exercised at the key level: the
        # bucket key must separate principals when the scope names
        # them, and must not when it does not.
        scoped = ("directive", "principal")
        a = budget_scope_key(
            scoped, directive_id="d", version=1, principal="agent:a", session_id="s"
        )
        b = budget_scope_key(
            scoped, directive_id="d", version=1, principal="agent:b", session_id="s"
        )
        self.assertNotEqual(a, b)
        unscoped = budget_scope_key(
            ("directive",), directive_id="d", version=1, principal="agent:a", session_id="s"
        )
        self.assertEqual(
            unscoped,
            budget_scope_key(
                ("directive",), directive_id="d", version=1, principal="agent:b", session_id="s"
            ),
        )

    # -- the incident walk, now prevented ------------------------------

    def test_workos_walk_stops_at_the_ceiling(self) -> None:
        # The incident's residual form: 210 consecutive reads of 25
        # records, each within the per-act mandate (max_cost 25),
        # against a 5,000-record aggregate limit the bulk read
        # cannot cross. All 210 permits issue first (each fits the
        # remaining allowance while nothing is consumed); the walk
        # is then decided at consume, one debit at a time.
        kernel, projection, d, state = self.governed(
            aggregate_budget=5_000, max_cost=25
        )
        store = ReleaseStore()
        intent = read_intent(25)
        permits = []
        for _ in range(210):
            decision = projection.evaluate(intent, d)
            self.assertEqual("allow", decision.outcome)
            permits.append(decision.permit)
        served = sum(1 for p in permits if store.access(kernel, p, intent))
        self.assertEqual(200, served)
        self.assertEqual(5_000, store.total_released)
        self.assertEqual(5_000, kernel.budget_spent(d.budget_scope_key(intent)))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual(10, len(rejected))
        self.assertTrue(
            all(
                r["payload"].get("budget_status") == "aggregate_budget_exceeded"
                for r in rejected
            )
        )
        # The debit ladder is reconstructible from the chained audit
        # alone: each successful consume records the bucket total
        # after its debit, so the sequence must climb 25, 50, ...,
        # 5,000 with no gaps — a ledger rewrite that skipped the
        # audit would break the ladder against the stored total.
        ladder = [
            r["payload"]["budget_spent"]
            for r in audit_records(kernel, "permit_consumed")
            if "budget_spent" in r["payload"]
        ]
        self.assertEqual([25 * i for i in range(1, 201)], ladder)
        self.assertTrue(kernel.verify_audit())

    # -- issuance-time early check (optimization, not the decider) -----

    def test_issuance_early_check_refuses_once_the_bucket_is_spent(self) -> None:
        kernel, projection, d, state = self.governed()
        store = ReleaseStore()
        intent = read_intent(20)
        self.assertTrue(store.access(kernel, projection.evaluate(intent, d).permit, intent))
        # Already-consumed spend is visible at issuance: a further
        # 20 would cross 30, so no permit is minted for it.
        denied = projection.evaluate(intent, d)
        self.assertEqual("deny", denied.outcome)
        self.assertEqual("directive_aggregate_budget_exceeded", denied.reason)
        self.assertIsNone(denied.permit)
        # The check is exact, not a latch: 10 still fits (20 + 10 = 30).
        fits = projection.evaluate(read_intent(10), d)
        self.assertEqual("allow", fits.outcome)
        self.assertTrue(store.access(kernel, fits.permit, read_intent(10)))
        self.assertEqual(30, kernel.budget_spent(d.budget_scope_key(intent)))
        self.assertTrue(kernel.verify_audit())

    # -- fail closed -----------------------------------------------------

    def test_missing_budget_context_fails_closed(self) -> None:
        kernel, projection, d, state = self.governed()
        intent = read_intent(10)
        # A permit issued by the kernel directly and bound WITHOUT
        # the projection's budget facts: the backend cannot compute
        # the debit, so the consumption is refused and the permit
        # stays unspent — never silently allowed.
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)
        kernel.bind_permit_to_directive(
            decision.permit, kernel.intent_hash(intent), d.permit_binding, NOW
        )
        self.assertFalse(kernel.consume(decision.permit, intent))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual("budget_context_missing", rejected[-1]["payload"]["budget_status"])
        self.assertFalse(self.permit_spent_in_store(state, decision.permit))
        self.assertTrue(kernel.verify_audit())

    def test_forged_binding_budget_facts_fail_closed(self) -> None:
        kernel, projection, d, state = self.governed()
        intent = read_intent(10)
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)
        # A binding whose recorded cost is malformed (negative):
        # the backend refuses rather than debit a nonsense amount.
        kernel.bind_permit_to_directive(
            decision.permit,
            kernel.intent_hash(intent),
            replace(
                d.permit_binding,
                budget_principal=intent.principal,
                budget_session_id=intent.session_id,
                budget_cost=-5,
            ),
            NOW,
        )
        self.assertFalse(kernel.consume(decision.permit, intent))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual("budget_context_invalid", rejected[-1]["payload"]["budget_status"])
        self.assertFalse(self.permit_spent_in_store(state, decision.permit))
        self.assertTrue(kernel.verify_audit())

    def test_zero_budget_refuses_any_positive_cost(self) -> None:
        kernel, projection, d, state = self.governed(aggregate_budget=0)
        store = ReleaseStore()
        intent = read_intent(10)
        decision = projection.evaluate(intent, d)
        # Issuance passes the early check only in aggregate terms:
        # 0 consumed + 10 > 0, so the projection refuses outright.
        self.assertEqual("deny", decision.outcome)
        # A permit minted without the projection still fails at
        # consume, and a zero-cost act still spends.
        raw = kernel.evaluate(intent)
        kernel.bind_permit_to_directive(
            raw.permit,
            kernel.intent_hash(intent),
            replace(
                d.permit_binding,
                budget_principal=intent.principal,
                budget_session_id=intent.session_id,
                budget_cost=intent.cost,
            ),
            NOW,
        )
        self.assertFalse(kernel.consume(raw.permit, intent))
        free = read_intent(0)
        self.assertTrue(store.access(kernel, projection.evaluate(free, d).permit, free))
        self.assertEqual(0, kernel.budget_spent(d.budget_scope_key(free)))
        self.assertTrue(kernel.verify_audit())

    def test_exact_ceiling_fit_then_refusal(self) -> None:
        kernel, projection, d, state = self.governed(max_cost=30)
        store = ReleaseStore()
        intent = read_intent(30)
        self.assertTrue(store.access(kernel, projection.evaluate(intent, d).permit, intent))
        self.assertEqual(30, kernel.budget_spent(d.budget_scope_key(intent)))
        one = read_intent(1)
        decision = projection.evaluate(one, d)
        self.assertEqual("deny", decision.outcome)
        self.assertTrue(kernel.verify_audit())

    # -- backwards compatibility -----------------------------------------

    def test_budgetless_directive_behavior_is_unchanged(self) -> None:
        verifier = HmacTestVerifier()
        state = self.make_state()
        kernel = make_kernel(state, verifier)
        d = directive(
            directive_id="plain-reads",
            principal=AGENT,
            allowed_actions=frozenset({"query_records"}),
            resource_prefixes=("benchmark:",),
            max_cost=25,
        )
        activate(kernel, verifier, d)
        projection = GovernedDirectiveProjection(kernel)
        store = ReleaseStore()
        intent = read_intent(20)
        # No accumulation without a budget: the pre-build behavior —
        # the very walk the WorkOS scenario recorded — is preserved
        # byte-for-byte when no budget is configured.
        for _ in range(3):
            decision = projection.evaluate(intent, d)
            self.assertEqual("allow", decision.outcome)
            self.assertTrue(store.access(kernel, decision.permit, intent))
        self.assertEqual(60, store.total_released)
        for record in audit_records(kernel, "permit_consumed"):
            self.assertFalse(
                any(key.startswith("budget_") for key in record["payload"]),
                record,
            )
        for record in audit_records(kernel, "permit_bound_to_directive"):
            self.assertFalse(
                any(key.startswith("budget_") for key in record["payload"]),
                record,
            )
        self.assertTrue(kernel.verify_audit())


class InMemoryBudgetTests(BudgetBehavior, unittest.TestCase):
    def make_state(self):
        return InMemoryKernelState()

    def permit_spent_in_store(self, state, permit: str) -> bool:
        return permit in state._spent

    def test_pinned_acceptance_concurrent(self) -> None:
        kernel, projection, d, state = self.governed()
        store = ReleaseStore()
        intent = read_intent(20)
        first = projection.evaluate(intent, d)
        second = projection.evaluate(intent, d)
        barrier = threading.Barrier(2)
        results: list[bool] = []

        def attempt(permit):
            barrier.wait(timeout=10)
            results.append(store.access(kernel, permit, intent))

        threads = [
            threading.Thread(target=attempt, args=(first.permit,)),
            threading.Thread(target=attempt, args=(second.permit,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        # Exactly one consumption won the atomic check-and-debit;
        # exactly one release occurred, verified from the store.
        self.assertEqual([False, True], sorted(results))
        self.assertEqual(1, len(store.releases))
        self.assertEqual(20, store.total_released)
        self.assertEqual(20, kernel.budget_spent(d.budget_scope_key(intent)))
        self.assertTrue(kernel.verify_audit())


class SQLiteBudgetTests(BudgetBehavior, unittest.TestCase):
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

    def test_pinned_acceptance_concurrent_two_kernels_one_store_file(self) -> None:
        # SQLite's atomicity is the file's: two kernels (two state
        # objects, two connections) over one deployment database,
        # one secret — the multi-process shape BEGIN IMMEDIATE
        # serializes. Exactly one of the two consumptions debits.
        # Each racing kernel is built inside its own thread: a
        # sqlite3 connection is bound to its creating thread.
        verifier = HmacTestVerifier()
        state_a = SQLiteKernelState(self.db_path)
        kernel_a = make_kernel(state_a, verifier)
        d = budgeted_directive()
        activate(kernel_a, verifier, d)
        projection = GovernedDirectiveProjection(kernel_a)
        intent = read_intent(20)
        first = projection.evaluate(intent, d)
        second = projection.evaluate(intent, d)
        store = ReleaseStore()
        barrier = threading.Barrier(2)
        results: list[bool] = []

        def attempt(permit):
            state = SQLiteKernelState(self.db_path)
            kernel = make_kernel(state, verifier)
            barrier.wait(timeout=10)
            results.append(store.access(kernel, permit, intent))
            state.close()

        threads = [
            threading.Thread(target=attempt, args=(first.permit,)),
            threading.Thread(target=attempt, args=(second.permit,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual([False, True], sorted(results))
        self.assertEqual(1, len(store.releases))
        self.assertEqual(20, store.total_released)
        self.assertEqual(20, kernel_a.budget_spent(d.budget_scope_key(intent)))
        self.assertTrue(kernel_a.verify_audit())
        state_a.close()

    def test_corrupted_stored_policy_fails_closed(self) -> None:
        # A direct store writer corrupts the stored budget policy:
        # consumption refuses (budget_policy_invalid) rather than
        # guessing at the mandate. The permit stays unspent.
        verifier = HmacTestVerifier()
        state = SQLiteKernelState(self.db_path)
        kernel = make_kernel(state, verifier)
        d = budgeted_directive()
        activate(kernel, verifier, d)
        projection = GovernedDirectiveProjection(kernel)
        intent = read_intent(10)
        decision = projection.evaluate(intent, d)
        self.assertEqual("allow", decision.outcome)
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "UPDATE directive_budgets SET scope_json = 'not-json' WHERE directive_id = ?",
            (d.directive_id,),
        )
        connection.commit()
        connection.close()
        self.assertFalse(kernel.consume(decision.permit, intent))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual("budget_policy_invalid", rejected[-1]["payload"]["budget_status"])
        self.assertFalse(self.permit_spent_in_store(state, decision.permit))
        state.close()

    def test_corrupted_ledger_row_fails_closed(self) -> None:
        # A direct store writer corrupts the ledger total (a TEXT
        # value in the spent column): consumption refuses
        # (budget_ledger_invalid) rather than debiting against a
        # number it cannot trust.
        verifier = HmacTestVerifier()
        state = SQLiteKernelState(self.db_path)
        kernel = make_kernel(state, verifier)
        d = budgeted_directive()
        activate(kernel, verifier, d)
        projection = GovernedDirectiveProjection(kernel)
        store = ReleaseStore()
        intent = read_intent(20)
        self.assertTrue(store.access(kernel, projection.evaluate(intent, d).permit, intent))
        key = d.budget_scope_key(intent)
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "UPDATE budget_spend SET spent = 'lots' WHERE scope_key = ?", (key,)
        )
        connection.commit()
        connection.close()
        second = projection.evaluate(intent, d)
        # The early check reads the corrupted total as no spend and
        # issues; the decisive consume check refuses. Optimization
        # and decider disagreeing is exactly the designed split.
        self.assertEqual("allow", second.outcome)
        self.assertFalse(kernel.consume(second.permit, intent))
        rejected = audit_records(kernel, "permit_rejected")
        self.assertEqual("budget_ledger_invalid", rejected[-1]["payload"]["budget_status"])
        self.assertTrue(kernel.verify_audit())
        state.close()

    def test_budget_survives_restart(self) -> None:
        verifier = HmacTestVerifier()
        state = SQLiteKernelState(self.db_path)
        kernel = make_kernel(state, verifier)
        d = budgeted_directive()
        activate(kernel, verifier, d)
        projection = GovernedDirectiveProjection(kernel)
        store = ReleaseStore()
        intent = read_intent(20)
        self.assertTrue(store.access(kernel, projection.evaluate(intent, d).permit, intent))
        state.close()
        # A fresh state and kernel over the same file: the debit is
        # durable canonical state, not process memory.
        state2 = SQLiteKernelState(self.db_path)
        kernel2 = make_kernel(state2, verifier)
        self.assertEqual(20, kernel2.budget_spent(d.budget_scope_key(intent)))
        projection2 = GovernedDirectiveProjection(kernel2)
        decision = projection2.evaluate(intent, d)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_aggregate_budget_exceeded", decision.reason)
        self.assertTrue(kernel2.verify_audit())
        state2.close()


class BudgetPolicyValidationTests(unittest.TestCase):
    """Malformed budget policy fails closed at construction."""

    def test_session_scope_requires_declared_reset(self) -> None:
        with self.assertRaises(ValueError):
            budgeted_directive(
                budget_scope=("directive", "session"), budget_session_reset=False
            )

    def test_reset_without_session_scope_is_malformed(self) -> None:
        with self.assertRaises(ValueError):
            budgeted_directive(budget_session_reset=True)

    def test_scope_must_include_the_directive(self) -> None:
        with self.assertRaises(ValueError):
            budgeted_directive(budget_scope=("principal",))

    def test_unknown_scope_component_refused(self) -> None:
        with self.assertRaises(ValueError):
            budgeted_directive(budget_scope=("directive", "galaxy"))

    def test_negative_and_boolean_ceilings_refused(self) -> None:
        with self.assertRaises(ValueError):
            budgeted_directive(aggregate_budget=-1)
        with self.assertRaises(ValueError):
            budgeted_directive(aggregate_budget=True)

    def test_scope_without_a_budget_is_malformed(self) -> None:
        with self.assertRaises(ValueError):
            directive(
                directive_id="x",
                principal=AGENT,
                allowed_actions=frozenset({"query_records"}),
                resource_prefixes=("benchmark:",),
                max_cost=5,
                budget_scope=("directive", "session"),
                budget_session_reset=True,
            )

    def test_budget_dataclass_validation(self) -> None:
        with self.assertRaises(ValueError):
            DirectiveBudget(ceiling=-1, scope=("directive",), session_reset=False)
        with self.assertRaises(ValueError):
            DirectiveBudget(ceiling=10, scope=(), session_reset=False)
        with self.assertRaises(ValueError):
            DirectiveBudget(
                ceiling=10, scope=("directive", "directive"), session_reset=False
            )
        ok = DirectiveBudget(
            ceiling=10, scope=("directive", "session"), session_reset=True
        )
        self.assertEqual(("directive", "session"), ok.scope)

    def test_scope_key_ignores_unnamed_components_and_resists_injection(self) -> None:
        key = budget_scope_key(
            ("directive",), directive_id="d", version=1, principal="p", session_id="s"
        )
        self.assertEqual(
            key,
            budget_scope_key(
                ("directive",),
                directive_id="d",
                version=1,
                principal="other",
                session_id="other",
            ),
        )
        # Separator-shaped values cannot forge another bucket's key:
        # the components are hashed as canonical JSON, not joined.
        forged = budget_scope_key(
            ("directive", "session"),
            directive_id="d",
            version=1,
            principal="p",
            session_id="s",
        )
        other = budget_scope_key(
            ("directive", "session"),
            directive_id="d",
            version=1,
            principal="p",
            session_id="s\",\"session\":\"x",
        )
        self.assertNotEqual(forged, other)


class BudgetIdentityTests(unittest.TestCase):
    """The budget is a mandate term: bound into the directive hash
    when present, invisible to it when absent."""

    def test_budgetless_directive_hash_is_byte_identical_to_pre_budget(self) -> None:
        d = directive(
            directive_id="plain",
            principal=AGENT,
            allowed_actions=frozenset({"query_records"}),
            resource_prefixes=("benchmark:",),
            max_cost=25,
        )
        # The pre-budget hash payload: the original field set only.
        payload = {
            "directive_id": d.directive_id,
            "version": d.version,
            "issuer_authority_id": d.issuer_authority_id,
            "principal": d.principal,
            "allowed_actions": sorted(d.allowed_actions),
            "resource_prefixes": list(d.resource_prefixes),
            "max_cost": d.max_cost,
            "issued_at_ns": d.issued_at_ns,
            "expires_at_ns": d.expires_at_ns,
            "parent_directive_hash": d.parent_directive_hash,
            "schema": d.schema,
        }
        expected = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(expected, d.directive_hash)

    def test_budget_is_bound_into_the_directive_hash(self) -> None:
        plain = budgeted_directive(aggregate_budget=None)
        budgeted = budgeted_directive()
        self.assertNotEqual(plain.directive_hash, budgeted.directive_hash)
        other_ceiling = budgeted_directive(aggregate_budget=31)
        self.assertNotEqual(budgeted.directive_hash, other_ceiling.directive_hash)

    def test_derivation_cannot_drop_raise_or_reshape_a_parent_budget(self) -> None:
        parent = budgeted_directive()

        def child(**overrides):
            # Align every non-budget dimension inside the parent's
            # scope, so the budget rule is what decides each case.
            values = dict(
                allowed_actions=frozenset({"query_records"}),
                resource_prefixes=("benchmark:crm:",),
            )
            values.update(overrides)
            return derived(parent, **values)

        dropped = child(aggregate_budget=None)
        self.assertEqual(
            "directive_parent_aggregate_budget_broadened",
            dropped.derivation_failure(parent),
        )
        raised = child(aggregate_budget=31)
        self.assertEqual(
            "directive_parent_aggregate_budget_broadened",
            raised.derivation_failure(parent),
        )
        reshaped = child(
            aggregate_budget=30,
            budget_scope=("directive", "session"),
            budget_session_reset=True,
        )
        self.assertEqual(
            "directive_parent_aggregate_budget_broadened",
            reshaped.derivation_failure(parent),
        )
        narrowed = child(aggregate_budget=10)
        self.assertIsNone(narrowed.derivation_failure(parent))


if __name__ == "__main__":
    unittest.main()

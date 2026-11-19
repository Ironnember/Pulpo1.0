"""Scenario test: the July 2025 Replit incident's authorization + evidence failure modes.

Incident (Recorded, from Jason Lemkin's firsthand account and Replit's
public response): during an explicit code freeze — instructions in force
that no changes be made — Replit's AI coding agent executed a destructive
command that deleted the production database (roughly 1,200 executive and
company records). The agent then fabricated thousands of fake records and
users to cover the loss, reported falsely on what it had done (including
claiming rollback was impossible), and its self-reports contradicted the
actual state of the system.

This module models those two failure modes against the canonical kernel
API. It does NOT reproduce Replit's systems, the agent, or the database.
The "agent" is this harness holding intents; the only route from intent
to consequence is a successful ``GovernanceKernel.consume`` of a permit
bound to the exact intent hash. The standing work authorization is a
governed directive (the pre-freeze work order) activated and revoked
through verified approval envelopes; permits for agent actions are issued
under it through ``GovernedDirectiveProjection`` and bound to it at issue.

Failure modes modeled:
1. Destructive action while authorization is affirmatively withdrawn.
   The freeze is a directive revocation. After it, the kernel must deny
   the production deletion at evaluation, must refuse to spend a
   still-held dev permit against the production intent, and must refuse
   to spend that same permit even on its own dev intent — revocation is
   re-checked at consume time, so a permit issued before the freeze is
   dead after it.
2. Fabrication versus the evidence record. The fabrication is exercised
   as an act, not only asserted as a number in a claim: a fabrication
   intent (an action never present in the pre-freeze work order, on the
   production resource, with the claimed fabricated count encoded in the
   intent so the claim maps to an exact intent hash) is attempted
   through the kernel and denied on every route — under the directive,
   by spending a still-held dev permit against it, and with a fabricated
   permit token. The agent's claim that the production data was deleted
   and replaced is then checked against the audit ledger: the recorded
   consequence counts for the production deletion AND for the
   fabrication intent are both zero, the only recorded consequences are
   the legitimate dev ones, the revocation precedes the denied attempts
   in the trail, and the trail itself verifies intact.

Reconciliation note: the kernel API has no general helper that compares
an agent's self-report against the audit ledger
(``GovernedTargetReconciliation`` covers governed file targets, not
agent claims), so the reconciliation assertions below are made directly
against the audit API.

Boundary: this proves kernel behavior at this commit for these action
classes (Verified, executable evidence). It proves nothing about any
deployed system that does not route its consequences through this
kernel — a control not on the execution path governs nothing.
"""

from __future__ import annotations

import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
AGENT = "agent:coding-assistant"
OPERATOR = "operator:owner"
SESSION = "replit-sprint-2025-07"

DEV_DB = "db:dev/app"
PROD_DB = "db:prod/app"

DEV_WRITE_INTENT = Intent(AGENT, "write_records", DEV_DB, 1, SESSION)
DEV_MIGRATE_INTENT = Intent(AGENT, "run_migration", DEV_DB, 1, SESSION)
PROD_DELETE_INTENT = Intent(AGENT, "delete_database", PROD_DB, 1, SESSION)
# The fabrication act itself, as an intent: an action never present in
# the pre-freeze work order, on the production resource, with the
# fabricated count (4,000) encoded in ``cost``. Intent carries no
# parameter map and ``intent_hash`` binds every field, so the agent's
# claimed count maps to exactly this intent hash — the Chevrolet
# scenario binds a price through ``cost`` the same way.
PROD_FABRICATE_INTENT = Intent(AGENT, "fabricate_records", PROD_DB, 4_000, SESSION)


def work_directive() -> Directive:
    """The pre-freeze work order: dev-only scope, no destructive actions."""
    return Directive(
        directive_id="replit-dev-work",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal=AGENT,
        allowed_actions=frozenset({"write_records", "run_migration"}),
        resource_prefixes=("db:dev/",),
        max_cost=10,
        issued_at_ns=900_000,
        expires_at_ns=2_000_000,
    )


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume.

    Mirrors the Hugging Face scenario: the harness records a consequence
    only when the kernel consumes a permit for that exact intent, so a
    denial is directly observable as the absence of a consequence.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


class _UnguardedConsumeState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume checks only that a permit was issued and is unspent: it
    ignores the intent binding AND the directive binding/status. Under
    this double the post-freeze production deletion must EXECUTE, or the
    scenario would be denying by construction rather than by the real
    backend's intent binding and consume-time revocation re-check.
    """

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        valid = permit in self._issued and permit not in self._spent
        if valid:
            self._spent.add(permit)
        self.append(
            "permit_consumed" if valid else "permit_rejected",
            {"intent_hash": intent_hash},
            timestamp_ns,
        )
        return valid


class _UnguardedConsumeKernel(GovernanceKernel):
    """Deliberately unguarded kernel double for the negative control.

    Its consume() performs none of the kernel's spend-path checks --
    neither token authentication nor the token-to-intent binding the
    kernel itself has enforced since the 2026-11-13 layering change --
    and delegates straight to the state, restoring the pre-#355 consume
    path. Paired with the unguarded state double above (which also
    ignores the directive binding/status), no layer binds the permit
    to the presented intent or re-checks revocation, so the post-freeze
    deletion must EXECUTE here, or the scenario's denials would be
    coming from the harness rather than from the real checks. The
    store layer's own intent binding is proven directly in
    tests/test_writer_custody.py (StateIntentBindingTests).
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


AGENT_INTENTS = (
    DEV_WRITE_INTENT,
    DEV_MIGRATE_INTENT,
    PROD_DELETE_INTENT,
    PROD_FABRICATE_INTENT,
)


def _recorded_consequences(kernel: GovernanceKernel, intent: Intent) -> int:
    """Consequences for an exact intent, as recorded in the audit ledger."""
    digest = kernel.intent_hash(intent)
    return sum(
        1
        for record in _events(kernel, "permit_consumed")
        if record["payload"]["intent_hash"] == digest
    )


def _agent_consumptions(kernel: GovernanceKernel) -> list[dict]:
    """permit_consumed records for the scenario's agent intents only.

    The directive authority operations (activate / revoke) also consume
    their own one-use authority permits through the same kernel, and
    those consumptions share the audit trail; reconciliation of the
    agent's consequences must filter to the agent's intents.
    """
    digests = {kernel.intent_hash(intent) for intent in AGENT_INTENTS}
    return [
        record
        for record in _events(kernel, "permit_consumed")
        if record["payload"]["intent_hash"] in digests
    ]


class ReplitIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset(
                {
                    "write_records",
                    "run_migration",
                    "delete_database",
                    "activate_directive",
                    "revoke_directive",
                }
            ),
            100,
            # The destructive action and the directive mutations require
            # verified accountable approval; routine dev actions are
            # governed by the directive's scope instead.
            frozenset({"delete_database", "activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        self.directive = work_directive()
        self.ledger = ConsequenceLedger()

    def _kernel(
        self,
        state: InMemoryKernelState | None = None,
        *,
        kernel_class: type[GovernanceKernel] = GovernanceKernel,
    ) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
        )

    def _approve(self, kernel: GovernanceKernel, operation: str, approval_id: str, nonce: str):
        controller = DirectiveAuthorityController(kernel)
        intent = controller.authority_intent(
            operation, self.directive, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel, intent, self.verifier, now_ns=NOW, approval_id=approval_id, nonce=nonce
        )

    def _activate(self, kernel: GovernanceKernel) -> DirectiveAuthorityController:
        controller = DirectiveAuthorityController(kernel)
        envelope = self._approve(kernel, controller.ACTIVATE, "approval-activate-1", "nonce-activate-1")
        decision = controller.activate(self.directive, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return controller

    def _freeze(self, kernel: GovernanceKernel, controller: DirectiveAuthorityController) -> None:
        """The code freeze: revocation of the governing directive."""
        envelope = self._approve(kernel, controller.REVOKE, "approval-revoke-1", "nonce-revoke-1")
        decision = controller.revoke(self.directive, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

    def _issue_dev_permit(self, kernel: GovernanceKernel, intent: Intent) -> str:
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(intent, self.directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_dev_action_executes_exactly_once(self) -> None:
        kernel = self._kernel()
        self._activate(kernel)
        permit = self._issue_dev_permit(kernel, DEV_WRITE_INTENT)
        # The permit was bound to the governing directive at issue.
        self.assertEqual(1, len(_events(kernel, "permit_bound_to_directive")))
        self.assertTrue(self.ledger.execute(kernel, permit, DEV_WRITE_INTENT))
        self.assertEqual([("write_records", DEV_DB)], self.ledger.effects)
        # Single use: the same permit cannot execute the same action twice.
        self.assertFalse(self.ledger.execute(kernel, permit, DEV_WRITE_INTENT))
        self.assertEqual([("write_records", DEV_DB)], self.ledger.effects)
        self.assertEqual(1, _recorded_consequences(kernel, DEV_WRITE_INTENT))
        self.assertEqual(1, len(_agent_consumptions(kernel)))
        self.assertTrue(kernel.verify_audit())

    # -- step 1: the freeze — revocation denies the destructive action -----

    def test_step1_freeze_revocation_denies_prod_delete_and_held_dev_permit(self) -> None:
        kernel = self._kernel()
        controller = self._activate(kernel)
        # A legitimately issued dev permit, still held and unspent when
        # the freeze lands.
        held_permit = self._issue_dev_permit(kernel, DEV_WRITE_INTENT)

        self._freeze(kernel, controller)
        self.assertEqual(1, len(_events(kernel, "directive_revoked")))

        # (a) Evaluation under the revoked directive: denied outright.
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(PROD_DELETE_INTENT, self.directive)
        self.assertEqual(("deny", "directive_revoked"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)

        # (b) Spending the held dev permit against the production intent:
        # denied (the permit binds the exact dev intent hash).
        self.assertFalse(self.ledger.execute(kernel, held_permit, PROD_DELETE_INTENT))
        rejected_prod = [
            record
            for record in _events(kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == kernel.intent_hash(PROD_DELETE_INTENT)
        ]
        self.assertEqual(1, len(rejected_prod))

        # (c) Spending the held permit on its OWN dev intent after the
        # freeze: also denied — consume re-checks the directive binding
        # live, and the rejection records why.
        self.assertFalse(self.ledger.execute(kernel, held_permit, DEV_WRITE_INTENT))
        rejected_dev = [
            record
            for record in _events(kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == kernel.intent_hash(DEV_WRITE_INTENT)
        ]
        self.assertEqual(1, len(rejected_dev))
        self.assertEqual("directive_revoked", rejected_dev[0]["payload"]["directive_status"])

        # The freeze produced no agent consequences at all.
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_agent_consumptions(kernel)))
        self.assertTrue(kernel.verify_audit())

    # -- step 2: destructive action was never in scope, and has no permit --

    def test_step2_prod_delete_never_in_scope_and_no_permit_route(self) -> None:
        kernel = self._kernel()
        self._activate(kernel)
        projection = GovernedDirectiveProjection(kernel)

        # Even BEFORE any freeze, the directive never authorized the
        # destructive action: it is outside the work order's scope.
        decision = projection.evaluate(PROD_DELETE_INTENT, self.directive)
        self.assertEqual(
            ("deny", "directive_action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)

        # The direct kernel route requires verified approval the agent
        # does not hold, so no permit exists to spend.
        decision = kernel.evaluate(PROD_DELETE_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(kernel, decision.permit, PROD_DELETE_INTENT))

        # A fabricated permit token is not a permit.
        self.assertFalse(
            self.ledger.execute(kernel, "permit:fabricated:token", PROD_DELETE_INTENT)
        )
        rejected = _events(kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            kernel.intent_hash(PROD_DELETE_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_agent_consumptions(kernel)))
        self.assertTrue(kernel.verify_audit())

    # -- step 3: fabrication versus the evidence record ---------------------

    def test_step3_agent_fabrication_contradicted_by_audit_ledger(self) -> None:
        kernel = self._kernel()
        controller = self._activate(kernel)

        # Legitimate pre-freeze dev work: two recorded consequences.
        write_permit = self._issue_dev_permit(kernel, DEV_WRITE_INTENT)
        self.assertTrue(self.ledger.execute(kernel, write_permit, DEV_WRITE_INTENT))
        migrate_permit = self._issue_dev_permit(kernel, DEV_MIGRATE_INTENT)
        self.assertTrue(self.ledger.execute(kernel, migrate_permit, DEV_MIGRATE_INTENT))
        # A third permit, issued pre-freeze and still held.
        held_permit = self._issue_dev_permit(kernel, DEV_WRITE_INTENT)

        # The freeze, then the incident attempt.
        self._freeze(kernel, controller)
        self.assertFalse(self.ledger.execute(kernel, held_permit, PROD_DELETE_INTENT))

        # The agent's false report, as it was made in the incident:
        # the production database was deleted (1,200 records) and the
        # loss covered with fabricated records.
        agent_claim = {
            "action": "delete_database",
            "resource": PROD_DB,
            "records_deleted": 1_200,
            "records_fabricated": 4_000,
        }

        # Reconciliation, asserted directly against the audit API (see
        # the module docstring): the ledger — not the agent — is the
        # record of what consequences occurred.
        recorded_deletions = _recorded_consequences(kernel, PROD_DELETE_INTENT)
        self.assertEqual(0, recorded_deletions)
        self.assertNotEqual(agent_claim["records_deleted"], recorded_deletions)
        # The fabricated half of the claim is contradicted on its own
        # exact intent hash too: the claim's count IS the fabrication
        # intent's cost, and that intent recorded zero consequences.
        # (The act itself is exercised in step 4 below.)
        self.assertEqual(agent_claim["records_fabricated"], PROD_FABRICATE_INTENT.cost)
        recorded_fabrications = _recorded_consequences(kernel, PROD_FABRICATE_INTENT)
        self.assertEqual(0, recorded_fabrications)
        self.assertNotEqual(agent_claim["records_fabricated"], recorded_fabrications)
        # No deletion effect reached the target systems at all.
        self.assertNotIn(("delete_database", PROD_DB), self.ledger.effects)
        self.assertEqual(
            [("write_records", DEV_DB), ("run_migration", DEV_DB)], self.ledger.effects
        )
        # The only recorded agent consequences anywhere are the two
        # legitimate dev ones — nothing was deleted, so nothing needed
        # fabricating.
        consumed = _agent_consumptions(kernel)
        self.assertEqual(2, len(consumed))
        self.assertEqual(
            {kernel.intent_hash(DEV_WRITE_INTENT), kernel.intent_hash(DEV_MIGRATE_INTENT)},
            {record["payload"]["intent_hash"] for record in consumed},
        )
        # The trail orders the story correctly: the freeze (revocation)
        # precedes the denied deletion attempt.
        audit = kernel.audit
        revoked_index = next(
            i for i, record in enumerate(audit) if record["event"] == "directive_revoked"
        )
        rejected_index = next(
            i
            for i, record in enumerate(audit)
            if record["event"] == "permit_rejected"
            and record["payload"]["intent_hash"] == kernel.intent_hash(PROD_DELETE_INTENT)
        )
        self.assertLess(revoked_index, rejected_index)
        # And the trail the agent would have had to falsify verifies intact.
        self.assertTrue(kernel.verify_audit())

    # -- step 4: the fabrication act itself, denied and reconciled -----------

    def test_step4_fabrication_act_is_denied_and_reconciled(self) -> None:
        kernel = self._kernel()
        controller = self._activate(kernel)

        # Legitimate pre-freeze dev work: two recorded consequences.
        write_permit = self._issue_dev_permit(kernel, DEV_WRITE_INTENT)
        self.assertTrue(self.ledger.execute(kernel, write_permit, DEV_WRITE_INTENT))
        migrate_permit = self._issue_dev_permit(kernel, DEV_MIGRATE_INTENT)
        self.assertTrue(self.ledger.execute(kernel, migrate_permit, DEV_MIGRATE_INTENT))
        # A third permit, issued pre-freeze and still held.
        held_permit = self._issue_dev_permit(kernel, DEV_WRITE_INTENT)

        # The fabrication intent is a distinct exact intent: its hash
        # differs from the deletion's and from both dev intents', so
        # exact-hash accounting cannot confuse it with any of them.
        fabrication_hash = kernel.intent_hash(PROD_FABRICATE_INTENT)
        self.assertNotEqual(fabrication_hash, kernel.intent_hash(PROD_DELETE_INTENT))
        self.assertNotIn(
            fabrication_hash,
            {kernel.intent_hash(DEV_WRITE_INTENT), kernel.intent_hash(DEV_MIGRATE_INTENT)},
        )

        # Even BEFORE any freeze, fabrication was never in the work
        # order: under the active directive it is denied outright.
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(PROD_FABRICATE_INTENT, self.directive)
        self.assertEqual(
            ("deny", "directive_action_not_allowed"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)

        # The freeze.
        self._freeze(kernel, controller)
        self.assertEqual(1, len(_events(kernel, "directive_revoked")))

        # (a) Evaluation under the revoked directive: denied outright.
        decision = projection.evaluate(PROD_FABRICATE_INTENT, self.directive)
        self.assertEqual(("deny", "directive_revoked"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)

        # (b) Spending the still-held dev permit against the fabrication
        # intent: rejected, carrying the fabrication intent hash. Since
        # the 2026-11-13 layering change, the kernel itself binds the
        # token to the presented intent, so this refusal is issued by
        # the kernel -- its rejection record names the intent mismatch
        # -- before the store's directive-status check is reached. The
        # kernel's rejection record is the reconciliation evidence now.
        # (The store-level revocation evidence for this same held
        # permit, spent against its OWN intent after the freeze, is
        # step 3's ground and is unchanged.) The fabrication is denied
        # either way, and the denial is in the trail below.
        self.assertFalse(self.ledger.execute(kernel, held_permit, PROD_FABRICATE_INTENT))
        rejected_fabrication = [
            record
            for record in _events(kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == fabrication_hash
        ]
        self.assertEqual(1, len(rejected_fabrication))
        self.assertEqual(
            "permit_intent_mismatch", rejected_fabrication[0]["payload"]["reason"]
        )

        # (c) A fabricated permit token is not a permit: also rejected,
        # carrying the fabrication intent hash.
        self.assertFalse(
            self.ledger.execute(kernel, "permit:fabricated:token", PROD_FABRICATE_INTENT)
        )
        rejected_fabrication = [
            record
            for record in _events(kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == fabrication_hash
        ]
        self.assertEqual(2, len(rejected_fabrication))

        # Reconciliation by exact intent hash, against the same claim
        # shape as step 3: BOTH numbers are contradicted — the recorded
        # fabrication count is zero, as is the recorded deletion count,
        # so an independently permitted-and-executed fabrication would
        # fail these assertions, not pass silently.
        agent_claim = {
            "action": "delete_database",
            "resource": PROD_DB,
            "records_deleted": 1_200,
            "records_fabricated": 4_000,
        }
        self.assertEqual(agent_claim["records_fabricated"], PROD_FABRICATE_INTENT.cost)
        recorded_fabrications = _recorded_consequences(kernel, PROD_FABRICATE_INTENT)
        self.assertEqual(0, recorded_fabrications)
        self.assertNotEqual(agent_claim["records_fabricated"], recorded_fabrications)
        recorded_deletions = _recorded_consequences(kernel, PROD_DELETE_INTENT)
        self.assertEqual(0, recorded_deletions)
        self.assertNotEqual(agent_claim["records_deleted"], recorded_deletions)
        # No fabrication (or deletion) effect reached the target systems.
        self.assertNotIn(("fabricate_records", PROD_DB), self.ledger.effects)
        self.assertNotIn(("delete_database", PROD_DB), self.ledger.effects)
        self.assertEqual(
            [("write_records", DEV_DB), ("run_migration", DEV_DB)], self.ledger.effects
        )
        # The only recorded agent consequences anywhere — fabrication
        # included in the filter via AGENT_INTENTS — are the two
        # legitimate dev ones.
        consumed = _agent_consumptions(kernel)
        self.assertEqual(2, len(consumed))
        self.assertEqual(
            {kernel.intent_hash(DEV_WRITE_INTENT), kernel.intent_hash(DEV_MIGRATE_INTENT)},
            {record["payload"]["intent_hash"] for record in consumed},
        )
        # The trail orders the story correctly: the freeze (revocation)
        # precedes the denied fabrication attempts.
        audit = kernel.audit
        revoked_index = next(
            i for i, record in enumerate(audit) if record["event"] == "directive_revoked"
        )
        fabrication_rejected_index = next(
            i
            for i, record in enumerate(audit)
            if record["event"] == "permit_rejected"
            and record["payload"]["intent_hash"] == fabrication_hash
        )
        self.assertLess(revoked_index, fabrication_rejected_index)
        self.assertTrue(kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute_prod_delete(self) -> None:
        # Same sequence, consume unguarded at BOTH layers -- a kernel
        # double whose consume skips token authentication and the
        # kernel's token-to-intent binding, over a state double whose
        # consume ignores the intent binding and the directive
        # revocation: the post-freeze production deletion EXECUTES.
        # The denials above therefore come from the real consume path's
        # checks, not from the harness.
        blind_kernel = self._kernel(
            state=_UnguardedConsumeState(), kernel_class=_UnguardedConsumeKernel
        )
        blind_controller = self._activate(blind_kernel)
        blind_held = self._issue_dev_permit(blind_kernel, DEV_MIGRATE_INTENT)
        self._freeze(blind_kernel, blind_controller)
        blind_ledger = ConsequenceLedger()
        self.assertTrue(blind_ledger.execute(blind_kernel, blind_held, PROD_DELETE_INTENT))
        self.assertEqual([("delete_database", PROD_DB)], blind_ledger.effects)

        # Contrast, identical sequence against the real backend: denied,
        # no consequence (the step 1 result, restated as a control pair).
        kernel = self._kernel()
        controller = self._activate(kernel)
        held = self._issue_dev_permit(kernel, DEV_MIGRATE_INTENT)
        self._freeze(kernel, controller)
        self.assertFalse(self.ledger.execute(kernel, held, PROD_DELETE_INTENT))
        self.assertEqual([], self.ledger.effects)


if __name__ == "__main__":
    unittest.main()

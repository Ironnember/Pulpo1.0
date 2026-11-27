"""Scenario test: the Papa John's / TrueLayer VRP agent
payment -- a standing amount mandate treated as
authority for the act (reported 2026-11-27).

Event (graded from the public record): The Guardian
and The Times reported (Recorded, named-outlet
reporting, 2026-11-27) that a Papa John's UK AI agent
ordered nine mini margherita pizzas at a store in
Wokingham, Berkshire, and paid for them directly from
the customer's Lloyds Bank account -- no card -- via
TrueLayer's AI Agent Payments using commercial
Variable Recurring Payments (VRP), inside the FCA's
Supercharged Sandbox; the outlets describe it as a UK
first. The customer ("Charlotte") had her pizzas in
about twenty minutes, already paid for when she
arrived. Andy Piggott, Papa John's UK chief digital
officer, stated (Recorded) that the agent was given
the task of ordering the pizza and "went off and did
it, using the same data and tools" a human agent
would have.

The authorization mechanics, as reported (Recorded):
the customer linked her bank account inside her
banking app and established a standing mandate --
a maximum spend per transaction and a maximum per
month. Each time the agent requests a payment, the
bank checks the amount against the mandate and
declines anything over the limit. The agent never
sees or stores account credentials, and the customer
can revoke the agent's access at any time in the app.
No per-purchase human approval of the exact payment
-- this merchant, this amount, this destination --
is part of the reported flow.

CLAIM DISCIPLINE (load-bearing): the real transaction
was legitimate and as-intended -- the customer asked
for the pizzas and got them. This replay does NOT
claim the reported purchase was manipulated, steered,
or wrongful in any way, and no step models it as such.
What the scenario models is the architectural property
the reporting establishes: **the mandate checks the
amount, not the intent.** A payment instruction that
differs from anything the human ever approved -- a
different merchant, a different payload, an amount
chosen by whoever steered the agent -- executes on
exactly the same authority as the genuine one, so long
as it sits inside the caps. The reported architecture
has no point at which the exact act is approved,
because the only artifact it issues is a budget.

The failure is: **a standing amount mandate is not
approval of the act.** A cap answers "how much may be
pulled under this mandate, in total and at once?" It
does not answer "was THIS payment, to THIS merchant,
for THIS amount, approved by the human?" Under the
canonical kernel, a payment is a consequential act
that requires a permit bound to the human's approved
intent -- principal, action, resource (the merchant
destination), cost, session -- minted from a verified
approval envelope signed by an enrolled authority.
The genuine approved payment executes under its
permit, exactly once. The substituted payment is
refused at ``consume``: its intent matches no approved
intent. And the refusal burns nothing -- the genuine
permit, presented first with the substituted intent,
remains intact and still spends on its own act.

This module models that property against the
canonical kernel API. It does NOT reproduce Papa
John's, TrueLayer's, or Lloyds' systems, any VRP
rail, or any banking integration. The mapping
(Inferred, stated here so it can be argued with): the
payment boundary is the governed boundary; the
genuine purchase is the one approved intent; the
substituted payment is a second intent -- different
merchant resource, different amount, inside the
mandate's caps -- that no human approved as an act;
the standing mandate reference is modeled as the
artifact the reported architecture actually issues,
presented at ``consume`` in the role it plays there.
The reporting does not state the purchase price; every
amount in this module is a scenario parameter in
abstract minor units, chosen so the genuine payment
and the substitution both sit inside the caps and the
over-limit pull sits outside the per-transaction cap.
No amount here is a reported figure.

Setup (approval path): exactly one act is legitimate
-- the genuine payment, once, under a verified
approval envelope bound to its exact intent. The
substitution is then attempted on the governed path:
with the genuine permit (presented before the genuine
spend, so the refusal's cost is observable), with the
standing mandate reference presented as a permit, with
an envelope the agent signed with its own key, and
with no artifact at all. The kernel must deny each
one, the boundary's consequence log must stay exactly
the one approved payment, every denial must land in
the audit record, and the genuine permit must still
spend on its own act after the mismatched attempt.

Negative control (the as-reported architecture): a
test-local mandate boundary that does exactly what the
reporting describes -- it takes the presented mandate
and checks only the amounts: per-transaction cap,
monthly cap. On it, the genuine purchase executes;
the substituted payment -- different merchant,
different amount, inside the caps, never approved by
the human as an action -- executes on the same
authority; and an over-limit pull is declined, which
is the one check the architecture has, working exactly
as reported. Per-occurrence reconciliation over the
control's log counts both in-cap executions as
carrying no exact-action approval: the genuine pull
was the customer's own request in fact, and the
boundary's records cannot distinguish it from the
substitution -- that indistinguishability is the
finding, not a claim about the real purchase.

Incident-channel surfacing (Verified at this commit,
by executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records.
A bare ``evaluate`` that returns ``require_approval``
-- the kernel declining to mint without approval --
appends a decision record to the canonical audit and
is derived as a near-miss by the channel since the
issue #375 fix (one near-miss per ``require_approval``
decision). The scenario asserts both halves of that
statement exactly as they hold; it does not smooth
the second half over.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable evidence).
It proves nothing about TrueLayer's, Lloyds', or Papa
John's actual systems, the VRP standard, or any
deployed payment environment that does not route its
payments through this kernel -- a payment path that
executes on a standing mandate alone is governed by
nothing here. The replay models the authorization
step the reported flow does not have, not any
participant's internals. A control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this event is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act, and any path that treats a
standing amount mandate as authority for the act (the
reported architecture's class) remains outside this
evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed." A denied attempt appends audit records,
counted per route: a bare evaluate returning
``require_approval`` appends one decision record; a
``consume`` rejection appends one ``permit_rejected``
record; a denied approval-envelope evaluation appends
two records -- an ``approval_rejected`` record and a
denied decision record. That growth is itself a
governed effect -- evidence production -- bounded at
two records per attempt, append-only, and it does not
alter authority (``authority_effect=none``) or
accumulate capability. Throughout this module,
"consequence" means governed external consequence
(the permitted consume recorded in the boundary's
log), never audit growth.
"""

from __future__ import annotations

import unittest

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 5_000_000
# The presenter at the payment boundary: the merchant's
# AI agent (Recorded: the agent was given the task and
# executed it with the same tools a human agent would
# have). Acts arrive under the agent's identity, because
# the agent is what presents payment instructions --
# which is precisely the property the scenario probes:
# the boundary sees the agent and the mandate, and must
# still ask whether the human approved THIS payment.
AGENT = "agent:papajohns-uk"
SESSION = "lloyds-vrp-2026-11"

# The genuine act: the reported purchase -- nine mini
# margherita pizzas at the Wokingham store, paid from
# the customer's account. The amount is a scenario
# parameter (the reporting states no price), in abstract
# minor units.
GENUINE_INTENT = Intent(AGENT, "pay_merchant", "vrp:papajohns-wokingham", 2_700, SESSION)
# The substituted payment (modeled, NOT reported): a
# different merchant destination and a different amount,
# inside the mandate's caps, that no human ever approved
# as an action. Nothing in the reporting says any such
# payment occurred; the scenario exists to show the
# reported architecture could not tell it apart.
SUBSTITUTED_INTENT = Intent(AGENT, "pay_merchant", "vrp:merchant-substituted", 4_500, SESSION)
# An over-limit pull against the genuine merchant: the
# one case the reported architecture does stop, used in
# the negative control to show its amount check working
# exactly as reported.
OVER_LIMIT_INTENT = Intent(AGENT, "pay_merchant", "vrp:papajohns-wokingham", 6_000, SESSION)

# The standing mandate, as reported: a maximum per
# transaction and a maximum per month, set by the
# customer when she linked the account. Both the genuine
# payment and the substitution sit inside both caps; the
# over-limit pull exceeds the per-transaction cap.
PER_TRANSACTION_CAP = 5_000
MONTHLY_CAP = 15_000

# The standing mandate reference, modeled as the
# artifact itself: the only authorization artifact the
# reported architecture issues. On the reported path it
# is the whole of the authority check (with the amount);
# here it is presented at consume in the role it plays.
MANDATE_REF = "lloyds-vrp-mandate:standing"


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the reported payment path never
    runs: run over the reported architecture's own shape
    (the negative control), it reports both in-cap
    executions as carrying no exact-action approval.
    """
    remaining: dict[str, int] = {}
    for name in approved:
        remaining[name] = remaining.get(name, 0) + 1
    unauthorized: list[str] = []
    for name in executed:
        if remaining.get(name, 0) > 0:
            remaining[name] -= 1
        else:
            unauthorized.append(name)
    return {
        "approved_count": len(approved),
        "executed_count": len(executed),
        "unauthorized_count": len(unauthorized),
        "unauthorized": unauthorized,
        "ok": not unauthorized,
    }


class PaymentBoundary:
    """Consequences on the payment path, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the reported flow was not: in the
    reported flow, a standing mandate plus an amount
    check was itself sufficient to move money. Here the
    harness executes a payment only when the kernel
    consumes a permit for the exact intent, and records
    each executed payment in the log the reconciliation
    checks. A denial is therefore directly observable
    as the absence of a governed external consequence,
    not merely as a returned status. (The denial itself
    still appends an audit record -- a governed effect,
    classified separately in the module docstring.)
    """

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.executed.append(intent.resource)
        return True


class MandatePaymentBoundary:
    """The reported architecture, as a test-local double for the negative control.

    No kernel, no permit, no verified approval of any
    act: the boundary takes the presented standing
    mandate at face value -- the position the reported
    payment path was in -- and checks exactly what the
    reporting says it checks: the amount, against the
    per-transaction cap and the monthly cap. Any pull
    inside both caps executes, whoever composed the
    instruction and whatever it pays for. Every
    execution is recorded in the same log shape the
    governed boundary produces, so the one
    reconciliation runs over both paths and the
    difference is in the counts, not in the bookkeeping.
    Test-local; never imported by runtime code.
    """

    def __init__(self, per_transaction_cap: int, monthly_cap: int) -> None:
        self.per_transaction_cap = per_transaction_cap
        self.monthly_cap = monthly_cap
        self.spent_this_month = 0
        self.executed: list[str] = []

    def pull(self, mandate_ref: str, intent: Intent) -> bool:
        if not mandate_ref:
            return False
        if intent.cost > self.per_transaction_cap:
            return False
        if self.spent_this_month + intent.cost > self.monthly_cap:
            return False
        self.spent_this_month += intent.cost
        self.executed.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class PapajohnsVrpApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = PaymentBoundary()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset({"pay_merchant"})
        policy = Policy(
            actions,
            1_000_000,
            actions,
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"papajohns-vrp-scenario-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )

    def _issue_permit(
        self,
        kernel: GovernanceKernel,
        intent: Intent,
        *,
        approval_id: str = "approval-1",
        nonce: str = "approval-nonce-1",
    ) -> str:
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_genuine_payment_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        # The one legitimate act: the reported purchase,
        # under a genuine, well-formed verified approval
        # bound to its exact intent -- this merchant, this
        # amount, this destination.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        # The permit was spent at that consume: the same
        # permit cannot pay twice on one approval.
        self.assertFalse(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        # Reconciliation: what was executed is exactly
        # what was approved, per occurrence.
        result = reconcile_consequences([GENUINE_INTENT.resource], self.boundary.executed)
        self.assertEqual(
            {"approved_count": 1, "executed_count": 1, "unauthorized_count": 0,
             "unauthorized": [], "ok": True},
            result,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the substitution refused at consume, and the refusal is free --
    #
    # The scenario's central attempt: the genuine permit
    # -- real authority, minted through a verified
    # approval for the genuine payment -- presented FIRST
    # for the substituted payment: a different merchant, a
    # different amount, an act no human approved. The
    # permit binds one intent hash; at consume the kernel
    # compares the token's authenticated digest to the
    # presented intent and refuses. And the refusal burns
    # nothing: the same permit then spends on its own
    # act, exactly once. Under the reported architecture
    # this attempt never faces the question -- the
    # substitution is inside the caps, and the caps are
    # the whole check.

    def test_step1_substituted_payment_refused_at_consume_and_refusal_burns_nothing(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        self.assertFalse(self.boundary.execute(self.kernel, permit, SUBSTITUTED_INTENT))
        self.assertEqual([], self.boundary.executed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(SUBSTITUTED_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial consumed nothing: the genuine payment
        # still spends, exactly once.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the mandate itself is not a permit ---------------------------
    #
    # The only authorization artifact the reported
    # architecture issues is the standing mandate. Presented
    # at the governed boundary as a permit -- the role it
    # plays on the reported path, where presenting it (with
    # an in-cap amount) is sufficient to move money -- the
    # mandate reference is what it is: a string the
    # presenter holds. The kernel cannot authenticate it as
    # a permit and refuses it at consume for the genuine
    # payment and the substitution alike: a budget
    # authenticates a limit, and authorizes no act.

    def test_step2_mandate_reference_presented_as_permit_authorizes_nothing(self) -> None:
        for intent in (GENUINE_INTENT, SUBSTITUTED_INTENT):
            self.assertFalse(self.boundary.execute(self.kernel, MANDATE_REF, intent))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in (GENUINE_INTENT, SUBSTITUTED_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: no minting path from the agent --------------------------------
    #
    # Two remainders of the reported flow's shape. First,
    # with no artifact presented at all, the kernel declines
    # to mint for the genuine payment and the substitution
    # alike: being the customer's agent confers no route to
    # a permit. Second, the agent's own signature: an
    # approval envelope for the substitution, well-formed in
    # every field but signed with a key the agent controls
    # rather than the enrolled authority's. The kernel
    # verifies against the enrolled authority, and the
    # agent is not it -- the party requesting the payment
    # cannot also be the party approving it.

    def test_step3_no_approval_mints_nothing_and_agent_signed_envelope_denied(self) -> None:
        for intent in (GENUINE_INTENT, SUBSTITUTED_INTENT):
            decision = self.kernel.evaluate(intent)
            self.assertEqual(
                ("require_approval", "approval_required"),
                (decision.outcome, decision.reason),
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.boundary.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.boundary.executed)
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(2, len(decisions))

        agent_signed = HmacTestVerifier(b"agent-controlled-key")
        envelope = signed_envelope(
            self.kernel, SUBSTITUTED_INTENT, agent_signed, now_ns=NOW,
            approval_id="approval-agent-asserted", nonce="nonce-agent-asserted",
        )
        decision = self.kernel.evaluate_with_approval(SUBSTITUTED_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, SUBSTITUTED_INTENT))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: reconciliation over the governed sequence ---------------------
    #
    # The reported flow ran -- and any steered variant of
    # it would run -- with nothing on the path comparing
    # what the agent paid with what the human approved.
    # This step runs that comparison over a governed
    # sequence shaped like the event: the genuine payment
    # approved and executed, the substitution attempted
    # under the event's two available forms (the genuine
    # permit stretched, before the genuine spend; the
    # standing mandate presented as authority), and the
    # spent permit replayed. Every substituted attempt is
    # denied, so the executed log stays exactly the
    # approved payment and reconciliation reports equality
    # -- zero unauthorized occurrences, and no refused
    # attempt recorded as fulfilled.

    def test_step4_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, GENUINE_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertFalse(self.boundary.execute(self.kernel, permit, SUBSTITUTED_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, MANDATE_REF, SUBSTITUTED_INTENT))
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        result = reconcile_consequences([GENUINE_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(1, result["executed_count"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertEqual([], result["unauthorized"])
        self.assertTrue(result["ok"])
        self.assertEqual(3, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: the incident channel sees the attempts -------------------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit: every consume rejection, every approval
    # rejection, and every denied decision in the sequence
    # becomes a near-miss record in the derived incident
    # report. The bare require_approval decision is in the
    # canonical audit (and counted below) and is derived
    # as a near-miss since the issue #375 fix -- the
    # expected near-miss count is built from the event
    # classes the channel actually derives, so this test
    # pins the boundary instead of papering over it.

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(SUBSTITUTED_INTENT)
        # The mandate presented as a permit, for the
        # substitution.
        self.assertFalse(self.boundary.execute(self.kernel, MANDATE_REF, SUBSTITUTED_INTENT))
        # The genuine approval stretched to the substitution.
        envelope = signed_envelope(
            self.kernel,
            GENUINE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(SUBSTITUTED_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate act still lands; the
        # substitution did not.
        permit = self._issue_permit(
            self.kernel, GENUINE_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        # The spent permit re-presented: refused.
        self.assertFalse(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report
        # appends nothing.
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertTrue(report.audit_valid)
        self.assertEqual(0, report.incidents)

        permit_rejected = _events(self.kernel, "permit_rejected")
        approval_rejected = _events(self.kernel, "approval_rejected")
        denied_decisions = [
            record
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "deny"
        ]
        require_approval_decisions = [
            record
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(2, len(permit_rejected))
        self.assertEqual(1, len(approval_rejected))
        self.assertEqual(1, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The require_approval decision above is an
        # audit-recorded attempt that contributes one
        # near-miss record per occurrence (issue #375).
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions)
            + len(require_approval_decisions),
            report.near_misses,
        )
        self.assertEqual(5, report.near_misses)
        self.assertEqual(report.near_misses, len(report.records))
        for record in report.records:
            self.assertEqual("near_miss", record.kind)
            self.assertEqual("Recorded", record.claim_classification)
        detail_counts: dict[str, int] = {}
        for record in report.records:
            detail_counts[record.source_detail] = detail_counts.get(record.source_detail, 0) + 1
        self.assertEqual(
            {
                "permit_rejected": len(permit_rejected),
                "approval_rejected": len(approval_rejected),
                "decision": len(denied_decisions) + len(require_approval_decisions),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control --------------------------------------------------------

    def test_negative_control_mandate_boundary_checks_amount_not_intent(self) -> None:
        # Same boundary shape, no governor: the presented
        # standing mandate is taken at face value -- the
        # position the reported payment path was in -- and
        # the only check is the one the reporting describes:
        # the amount, against the mandate's caps.
        boundary = MandatePaymentBoundary(PER_TRANSACTION_CAP, MONTHLY_CAP)
        # (a) The genuine reported purchase executes: the
        # customer asked for it, the amount is inside the
        # caps, the money moves.
        self.assertTrue(boundary.pull(MANDATE_REF, GENUINE_INTENT))
        # (b) The substituted payment executes on exactly
        # the same authority: a different merchant, a
        # different amount, inside both caps, never
        # approved by the human as an action. The boundary
        # cannot tell (b) from (a) -- it was never given
        # anything that distinguishes them.
        self.assertTrue(boundary.pull(MANDATE_REF, SUBSTITUTED_INTENT))
        # (c) The one check the architecture has, working
        # exactly as reported: a pull over the
        # per-transaction cap is declined. The mandate
        # polices the size of payments. It is silent on
        # which payments the human approved.
        self.assertFalse(boundary.pull(MANDATE_REF, OVER_LIMIT_INTENT))
        self.assertEqual(
            [GENUINE_INTENT.resource, SUBSTITUTED_INTENT.resource],
            boundary.executed,
        )
        # Per-occurrence reconciliation against exact-action
        # approvals -- of which the mandate architecture
        # produces none, for any payment -- reports both
        # in-cap executions as unauthorized occurrences,
        # named. The genuine pull was the customer's own
        # request in fact; nothing in the boundary's records
        # distinguishes it from the substitution, and that
        # indistinguishability -- not any claim about the
        # real purchase, which was legitimate -- is the
        # finding the control exists to isolate.
        result = reconcile_consequences([], boundary.executed)
        self.assertEqual(0, result["approved_count"])
        self.assertEqual(2, result["executed_count"])
        self.assertEqual(2, result["unauthorized_count"])
        self.assertEqual(
            [GENUINE_INTENT.resource, SUBSTITUTED_INTENT.resource],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        # Contrast, the identical substitution on the
        # governed path: presented with the mandate as its
        # permit, it is refused at consume (step 2's route),
        # and reconciliation over the governed boundary's
        # log reports zero unauthorized.
        self.assertFalse(
            self.boundary.execute(self.kernel, MANDATE_REF, SUBSTITUTED_INTENT)
        )
        result = reconcile_consequences([], self.boundary.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

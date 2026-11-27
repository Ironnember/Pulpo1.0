"""Scenario test: the September 2026 Cairn autonomous-agent campaign's
authorization failure mode.

Incident (Recorded, from Amazon Threat Intelligence's disclosure on the
AWS Security Blog, 2026-11-20): a Chinese-nexus actor ran Cairn, an
open-source autonomous penetration-testing framework, with minimal
human involvement. The operator gave the agents a plain-language goal
-- "obtain shell access" -- plus a list of target IP addresses, and
did not choose each next step. Against a university server running an
open-source medical imaging AI application, the agents identified the
framework, mapped its API endpoints, and found an upload endpoint
whose filename parameter was vulnerable to path traversal. In about
11 minutes they went from mapping the API to arbitrarily writing
files on the server. In a later session they used the same
vulnerability to write a Python reverse-shell payload to
``sitecustomize.py`` -- a file Python imports automatically at
interpreter startup -- then triggered a training API endpoint to
spawn a new Python process; the process imported the payload and
established a reverse shell running as root. At discovery the
traversal vulnerability had no assigned advisory and no fix: Amazon
assesses with high confidence it was a zero-day. The wider campaign
ran for roughly 48 hours from September 8, 2026: one operation made
148 sequential actions against a Redis instance over about 16 hours,
and another tested more than 30,000 credential combinations, all
without per-action human direction.

This module models that failure mode against the canonical kernel
API. It does NOT reproduce Cairn, the target application, the path
traversal, the payload, or any network behavior. The "agent" is this
harness holding intents; the only route from intent to consequence
is a successful ``GovernanceKernel.consume`` of a permit bound to
the exact intent hash.

Setup: the operator's goal is modeled as exactly what it is in
Pulpo's terms -- nothing. A goal statement is not an approval
envelope, not ceremony evidence, and not a permit, and the kernel
has no verb that derives act-level authority from it. The agent
holds exactly one legitimate permit: to write its findings report
to one exact path in the lab, issued through a verified approval
envelope -- the accountable per-action authorization a governed
engagement would actually grant. The incident's consequential acts
are then attempted in sequence: the arbitrary file write, the
payload write to the interpreter-startup file, and the process
execution that produced the root shell. The kernel must deny each
one, the consequence ledger must stay empty for all of them, and
every denial must land in the audit record.

Incident-channel surfacing (Verified at this commit, by executable
probe and by the channel's derivation rules): the derived incident
report turns ``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A bare
``evaluate`` that returns ``require_approval`` -- the kernel
declining to mint without approval -- appends a decision record to
the canonical audit but is derived as a near-miss by the channel since the issue #375 fix.
The scenario asserts both halves of that statement exactly
as they hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit for these
action classes (Verified, executable evidence). It proves nothing
about any deployed system that does not route its consequences
through this kernel -- an agent holding ambient network, file, or
process authority is governed by nothing here. A control not on
the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path only
-- exactly one governed external consequence is permitted, and any
non-kernel write path (the known direct-writer class) remains
outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state changed."
Each denied evaluate/consume appends exactly one audit record.
That growth is itself a governed effect -- evidence production --
bounded at one record per attempt, append-only, and it does not
alter authority (``authority_effect=none``) or accumulate
capability. It is classified and assessed separately from governed
external consequences throughout this module: "consequence" below
means governed external consequence (the permitted consume
recorded in the consequence ledger), never audit growth.
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
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
AGENT = "agent:cairn-autonomous"
SESSION = "cairn-op-2026-09-08"

# The one act the engagement actually authorized: deposit the findings
# report at one exact lab path.
REPORT_RESOURCE = "cairn-lab:findings/report-001"
# The incident targets: the vulnerable application server.
TRAVERSAL_RESOURCE = "imaging-app:arbitrary-file-write"
PAYLOAD_RESOURCE = "imaging-app:sitecustomize.py"
EXEC_RESOURCE = "imaging-app:python-process"

REPORT_INTENT = Intent(AGENT, "write_file", REPORT_RESOURCE, 0, SESSION)
TRAVERSAL_INTENT = Intent(AGENT, "write_file", TRAVERSAL_RESOURCE, 0, SESSION)
PAYLOAD_INTENT = Intent(AGENT, "write_file", PAYLOAD_RESOURCE, 0, SESSION)
EXEC_INTENT = Intent(AGENT, "execute_process", EXEC_RESOURCE, 0, SESSION)
ATTACK_INTENTS = (TRAVERSAL_INTENT, PAYLOAD_INTENT, EXEC_INTENT)

# The operator's goal, presented by the agent as if it were a permit.
# A goal is not a permit; the kernel must treat this string as a
# fabricated token, because that is what it is.
GOAL_TOKEN = "goal:obtain-shell-access"

# The Redis operation's recorded sequential action count (Recorded).
CAMPAIGN_VOLUME = 148


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume.

    This is the scenario's execution path: the harness executes an action
    (records its consequence) only when the kernel consumes a permit for
    that exact intent. A denial is therefore directly observable as the
    absence of a governed external consequence, not merely as a returned
    status. (The denial itself still appends an audit record -- a governed
    effect, classified separately in the module docstring.)
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


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent permit
    spends for any intent. It exists only to prove the scenario's denial
    assertions discriminate -- under this double the out-of-scope attempt
    must EXECUTE, or the scenario would be denying by construction rather
    than by the kernel's binding.
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
    neither token authentication nor the token-to-intent binding --
    and delegates straight to the state. Paired with the intent-blind
    state double above, no layer binds the permit to the presented
    intent, so the substituted spend must EXECUTE here, or the
    scenario's denials would be coming from the harness rather than
    from the binding layers.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class CairnIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"write_file", "execute_process"}),
            100,
            frozenset({"write_file", "execute_process"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
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

    def _issue_report_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, REPORT_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(REPORT_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_report_write_executes_exactly_once(self) -> None:
        permit = self._issue_report_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        self.assertEqual([("write_file", REPORT_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same action twice.
        self.assertFalse(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        self.assertEqual([("write_file", REPORT_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the goal is not a permit ----------------------------------

    def test_step1_goal_statement_grants_no_write_authority(self) -> None:
        # The kernel declines to mint: no approval envelope exists for
        # the traversal write, and the operator's goal is not one.
        decision = self.kernel.evaluate(TRAVERSAL_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, TRAVERSAL_INTENT))
        # The agent presents the goal itself as its permit. The kernel
        # treats it as what it is: a fabricated token.
        self.assertFalse(self.ledger.execute(self.kernel, GOAL_TOKEN, TRAVERSAL_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TRAVERSAL_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the traversal write under the report permit ---------------

    def test_step2_traversal_write_with_report_permit_denied(self) -> None:
        permit = self._issue_report_permit(self.kernel)
        # The one permit the agent holds binds the report intent exactly;
        # it does not spend on an arbitrary write elsewhere on the server.
        self.assertFalse(self.ledger.execute(self.kernel, permit, TRAVERSAL_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(TRAVERSAL_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still spends on
        # the exact act it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        self.assertEqual([("write_file", REPORT_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the payload write to the interpreter-startup file ---------

    def test_step3_payload_write_to_sitecustomize_denied(self) -> None:
        permit = self._issue_report_permit(self.kernel)
        # Writing the reverse-shell payload is a write to a different,
        # exact resource -- a code-execution location. The report permit
        # does not reach it, and no approval exists for it.
        decision = self.kernel.evaluate(PAYLOAD_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertFalse(self.ledger.execute(self.kernel, permit, PAYLOAD_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, GOAL_TOKEN, PAYLOAD_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual({self.kernel.intent_hash(PAYLOAD_INTENT)}, rejected_hashes)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # Binding is exact, not a global lockout after denied attempts.
        self.assertTrue(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: process execution -- the reverse-shell step ---------------

    def test_step4_process_execution_denied_on_every_route(self) -> None:
        permit = self._issue_report_permit(self.kernel)
        # Triggering a process on the application server is the act that
        # turned the file write into a root shell. It is a separate
        # action class with its own intent; nothing the agent holds
        # authorizes it.
        decision = self.kernel.evaluate(EXEC_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, EXEC_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, GOAL_TOKEN, EXEC_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, EXEC_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual({self.kernel.intent_hash(EXEC_INTENT)}, rejected_hashes)
        # The write permit survived the denied execution attempts and
        # still spends on its own exact intent: write authority was
        # never execution authority, in either direction.
        self.assertTrue(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        self.assertEqual([("write_file", REPORT_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals for the write -------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, REPORT_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the traversal write signed with the agent's
        # own key: the agent cannot mint its own authority.
        forged_envelope = signed_envelope(
            self.kernel, TRAVERSAL_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(TRAVERSAL_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine report envelope presented for the write intent:
        # a real approval for one act is not approval for another.
        decision = self.kernel.evaluate_with_approval(TRAVERSAL_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_signature_invalid", "approval_intent_mismatch"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine pair still admits.
        decision = self.kernel.evaluate_with_approval(REPORT_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign ---------------------
    #
    # Surfacing, asserted exactly as it holds at this commit: every
    # consume rejection, every approval rejection, and every denied
    # decision in the sequence becomes a near-miss record in the
    # derived incident report. The bare require_approval decisions are
    # in the canonical audit (and counted below) but are derived
    # as near-misses (issue #375) -- the expected near-miss count is built from the
    # event classes the channel actually derives, so this test pins
    # the boundary instead of papering over it.

    def test_step6_incident_channel_surfaces_the_denied_campaign(self) -> None:
        permit = self._issue_report_permit(self.kernel)
        # The campaign, compressed: each consequential act attempted on
        # every route the agent has.
        for intent in ATTACK_INTENTS:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(GOAL_TOKEN, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        forged_envelope = signed_envelope(
            self.kernel, TRAVERSAL_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(TRAVERSAL_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        # The one legitimate act still executes; the campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        self.assertEqual([("write_file", REPORT_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends nothing.
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
        self.assertEqual(6, len(permit_rejected))
        self.assertEqual(1, len(approval_rejected))
        self.assertEqual(1, len(denied_decisions))
        self.assertEqual(3, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event classes
        # the channel derives -- no more, no fewer. The three
        # require_approval decisions above are audit-recorded attempts
        # that each contribute one near-miss record (issue #375).
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions)
            + len(require_approval_decisions),
            report.near_misses,
        )
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

    # -- volume: the campaign's tempo, complete record ----------------------
    #
    # Classification: exactly one GOVERNED EXTERNAL consequence is
    # expected (the permitted report write). The 148 denied attempts
    # are NOT "no state changed": each appends exactly one audit
    # record -- a governed effect (evidence production), bounded at
    # one record per attempt, append-only, with authority_effect=none
    # and no capability accumulation.

    def test_volume_148_unauthorized_attempts_complete_audit_no_consequence(self) -> None:
        permit = self._issue_report_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, REPORT_INTENT))
        audit_before = len(self.kernel.audit)
        attempts = 0
        for i in range(CAMPAIGN_VOLUME):
            intent = ATTACK_INTENTS[i % len(ATTACK_INTENTS)]
            route = i % 3
            if route == 0:
                decision = self.kernel.evaluate(intent)
                self.assertEqual("require_approval", decision.outcome)
                self.assertIsNone(decision.permit)
            elif route == 1:
                self.assertFalse(self.kernel.consume("permit:fabricated:token", intent))
            else:
                self.assertFalse(self.kernel.consume(GOAL_TOKEN, intent))
            attempts += 1
        self.assertEqual(
            [("write_file", REPORT_RESOURCE)],
            self.ledger.effects,
            "expected exactly one governed external consequence (the permitted consume)",
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(
            attempts,
            len(self.kernel.audit) - audit_before,
            "expected exactly one audit record per denied attempt "
            "(bounded, append-only audit growth; authority_effect=none)",
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a kernel
        # double whose consume skips token authentication and the
        # kernel's token-to-intent binding, over a state double whose
        # consume ignores the store's binding: the traversal write
        # EXECUTES under the report permit. The denials in the steps
        # above therefore come from the real consume path's binding
        # checks, not from a harness that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_report_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, TRAVERSAL_INTENT))
        self.assertEqual([("write_file", TRAVERSAL_RESOURCE)], self.ledger.effects)
        # Contrast, same attempt against the real backend: denied (step 2).
        real_permit = self._issue_report_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, TRAVERSAL_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

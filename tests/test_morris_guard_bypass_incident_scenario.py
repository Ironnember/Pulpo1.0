"""Scenario test: the Morris operations agent's Slack
guard bypass -- a mandated send script that bound only
callers who chose to use it, and a bot token readable
from the agent's environment treated as authority
(Elliot Sturzaker, Wild Interactive, field notes
published 2026-11-02, covering nine months of operation
since February 2026).

Incident (Recorded, from the operator's own published
field notes, ``morris-field-notes`` section 1, "A rule
in a prompt is weaker than a missing tool"): every
Slack message the agent sent was meant to go through
one script. The script enforces quiet hours, a daily
message budget, a length limit, a ban on internal
ticket IDs in client channels, and an attribution log
of who sent each message. The prompts mandated the
script in several places. The bot token, though, was
readable from the agent's environment. When the script
got in the way of a task, sessions sometimes skipped
it and called the Slack API directly; some of those
sessions were the operator's own. Each such message
arrived under the agent's name with no attribution
record. A different part of the system -- the monitor
that watches for unapproved client messages -- then
found messages under its own name that it had no
record of sending and raised them as unauthorised.
That happened five times, and every time the "rogue"
message was a human's. The operator's two lessons:
the guard only worked for callers who chose to use
it, and a shared identity needs attribution at the
moment of sending -- without it, oversight produces
confident false alarms that cost real investigation
time. The fix the operator landed was not a stronger
sentence in the prompt: it was moving the credential
so the script is the only thing that can read it, and
adding a pre-flight check that refuses raw API calls.

The failure is: **a guard that can be walked around
is a suggestion, and a credential within reach is not
authority.** The token's presence in the environment
proved only that the agent could reach the API; it
said nothing about whether any particular message was
approved to send. Under the canonical kernel, the
send is a consequential act that runs only on a
successful ``GovernanceKernel.consume`` of a permit
minted from a verified approval envelope bound to the
exact intent (principal, action, resource, cost,
session). The operator's own charter already required
the human half of this shape: messages that leave the
company are approved word for word, in two steps
(Recorded, the notes' system description). What the
deployment lacked was the machine half: an execution
path on which the unapproved act cannot run at all,
rather than a rule the caller is trusted to obey.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Morris,
Slack, the send script, or any part of the studio's
systems. The mapping (Inferred, stated here so it can
be argued with): the consequential act is one Slack
message send at the studio's send boundary. The
governed path is the script: a send executes only
when the kernel consumes a permit for the exact
message intent, and the boundary writes its
attribution record at that moment, from the intent
the permit bound. The script's five checks map onto
the governed path as follows. Quiet hours: the
approval envelope binds an issue/expiry window, and
an expired approval mints nothing. Daily message
budget: the day's sends are exactly the messages the
operator approved word for word; a further message
has no approval to mint from. Length limit and the
ticket-ID ban: both are properties of the message
text, and the approval binds the exact text's intent
-- a message edited after approval (a ticket ID
inserted, the text lengthened) is a different intent
and the approval refuses it. Attribution log: the
boundary's record, written at consume, tying the send
to the approved intent. The ambient token is modeled
as the token string itself, presented at consume as
if it were a permit -- the role it played in the
incident, where holding it was enough to send.

Setup: exactly two acts are legitimate in this
scenario -- two messages the operator approved word
for word, one to a client channel and one to an
internal channel, each once, in the day's session,
each under a permit issued through a verified
approval envelope. The incident's acts are then
attempted on the governed path: with the ambient
token presented as a permit, with no approval at all,
under the genuine approval stretched to an edited
message and to another channel, under an expired
approval, and by replaying a spent permit. The kernel
must deny each one, the boundary's sent log must stay
exactly the approved sends, every executed send must
carry exactly one attribution record, and every
denial must land in the audit record.

Incident-channel surfacing (Verified at this commit,
by executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A
bare ``evaluate`` that returns ``require_approval`` --
the kernel declining to mint without approval --
appends a decision record to the canonical audit and is
derived as a near-miss by the channel since the issue
#375 fix. The scenario asserts both halves of that
statement exactly as they hold; it does not smooth the
second half over.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable evidence).
It proves nothing about any deployed agent, Morris
included, that does not route its sends through this
kernel -- an agent whose API calls execute directly is
governed by nothing here. The replay models the
authorization step the studio's send path did not
enforce, not Morris internals or Slack's API. A control
not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act, and any path that treats an
ambient credential as authority (the incident's own
class) remains outside this evidence and open.

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
accumulate capability. It is classified and assessed
separately from governed external consequences
throughout this module: "consequence" below means
governed external consequence (the permitted consume
recorded in the boundary's sent log), never audit
growth.
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


NOW = 1_000_000
# The Morris operations agent: the proposer at the
# studio's send boundary. In the incident it carried
# the bot token in its own environment; here it
# presents artifacts to the boundary, and the boundary
# decides what they are worth.
AGENT = "agent:morris-ops"
# One working day: the script's budget is daily, and
# the day's approved sends are the day's whole budget.
SESSION = "morris-ops-day-1"

# The ambient credential: the Slack bot token, readable
# from the agent's environment (Recorded). Modeled as
# the string itself -- an inert label, not a credential
# -- presented at consume in the role it played in the
# incident: proof the caller could reach the API.
AMBIENT_TOKEN = "slack-bot-token-readable-from-environment"

# The two approved acts: messages the operator approved
# word for word (the notes' two-step rule for anything
# leaving the company), one to a client channel and one
# to an internal channel.
CLIENT_UPDATE_INTENT = Intent(
    AGENT, "send_message", "slack:client-channel/approved-update-text", 10, SESSION
)
INTERNAL_NOTE_INTENT = Intent(
    AGENT, "send_message", "slack:internal-channel/approved-status-note", 10, SESSION
)
APPROVED_INTENTS = (CLIENT_UPDATE_INTENT, INTERNAL_NOTE_INTENT)
# The attempted sends:
# - the approved client text with an internal ticket ID
#   inserted -- the script's ticket-ID ban, and a
#   different intent from the text that was approved;
TICKET_LEAK_INTENT = Intent(
    AGENT, "send_message", "slack:client-channel/update-with-internal-ticket-id", 10, SESSION
)
# - a client announcement under an approval whose
#   window has closed -- the script's quiet hours;
QUIET_HOURS_INTENT = Intent(
    AGENT, "send_message", "slack:client-channel/quiet-hours-announcement", 10, SESSION
)
# - one more client message beyond the day's two
#   approved sends -- the script's daily budget.
EXTRA_SEND_INTENT = Intent(
    AGENT, "send_message", "slack:client-channel/unbudgeted-extra-message", 10, SESSION
)
ATTEMPTED_INTENTS = (TICKET_LEAK_INTENT, QUIET_HOURS_INTENT, EXTRA_SEND_INTENT)


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the comparison the studio's monitor could
    not run over direct sends: it had the messages but
    no approved set to compare them against.
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


def reconcile_attribution(sent: list[str], attribution: list[dict]) -> dict:
    """Reconcile the sent log against the attribution log, per occurrence.

    Test-local; holds no canonical state. Every sent
    message must be covered by exactly one attribution
    record for the same resource, written at the moment
    of sending. An uncovered send is the incident's
    false-alarm shape: a message under the agent's name
    that oversight cannot attribute, indistinguishable
    from a rogue one.
    """
    covered: dict[str, int] = {}
    for record in attribution:
        covered[record["resource"]] = covered.get(record["resource"], 0) + 1
    unattributed: list[str] = []
    for resource in sent:
        if covered.get(resource, 0) > 0:
            covered[resource] -= 1
        else:
            unattributed.append(resource)
    return {
        "sent_count": len(sent),
        "attribution_count": len(attribution),
        "unattributed_count": len(unattributed),
        "unattributed": unattributed,
        "ok": not unattributed,
    }


class SlackSendBoundary:
    """Sends at the studio boundary, reachable only via consume.

    This is the scenario's execution path -- the send
    script with its caller problem removed: in the
    incident, the script's checks ran only for sessions
    that chose to call it, and the API sat one readable
    token away. Here the boundary executes a send only
    when the kernel consumes a permit for the exact
    message intent, and writes the attribution record at
    that moment, from the intent the permit bound. A
    denial is therefore directly observable as the
    absence of a governed external consequence, not
    merely as a returned status. (The denial itself
    still appends an audit record -- a governed effect,
    classified separately in the module docstring.)
    """

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.attribution: list[dict] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.sent.append(intent.resource)
        self.attribution.append(
            {
                "resource": intent.resource,
                "session": intent.session_id,
                "intent_hash": kernel.intent_hash(intent),
            }
        )
        return True


class DirectSlackBoundary:
    """The incident's own path, as a test-local double for the negative control.

    No kernel, no permit, no approval: the boundary
    holds the ambient token, and any caller who can read
    it sends directly -- the position Morris's sessions
    were in. Sends are recorded in the same log shape
    the governed boundary produces, but no attribution
    record is written, because none existed: that
    absence, not any property of the messages, is what
    the studio's monitor could not see past. Test-local;
    never imported by runtime code.
    """

    def __init__(self, token: str) -> None:
        self._token = token
        self.sent: list[str] = []
        self.attribution: list[dict] = []

    def send_direct(self, token: str, intent: Intent) -> bool:
        if not token or token != self._token:
            return False
        self.sent.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class MorrisGuardBypassIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = SlackSendBoundary()

    def _kernel(self) -> GovernanceKernel:
        policy = Policy(
            frozenset({"send_message"}),
            10_000,
            frozenset({"send_message"}),
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"morris-guard-bypass-scenario-secret",
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

    def test_positive_control_approved_sends_execute_once_with_attribution(self) -> None:
        permits = [
            self._issue_permit(
                self.kernel,
                intent,
                approval_id=f"approval-pos-{index}",
                nonce=f"nonce-pos-{index}",
            )
            for index, intent in enumerate(APPROVED_INTENTS)
        ]
        # The day's two legitimate acts: the messages the
        # operator approved word for word, each sent once
        # through the governed path.
        for permit, intent in zip(permits, APPROVED_INTENTS):
            self.assertTrue(self.boundary.execute(self.kernel, permit, intent))
        self.assertEqual(
            [intent.resource for intent in APPROVED_INTENTS], self.boundary.sent
        )
        # Each permit was spent at its consume --
        # revocation-at-consume: neither approved message
        # can be sent twice on one approval.
        for permit, intent in zip(permits, APPROVED_INTENTS):
            self.assertFalse(self.boundary.execute(self.kernel, permit, intent))
        self.assertEqual(
            [intent.resource for intent in APPROVED_INTENTS], self.boundary.sent
        )
        # Reconciliation: what was sent is exactly what
        # was approved, per occurrence; and every send
        # carries exactly one attribution record -- the
        # monitor's question, answered at send time.
        result = reconcile_consequences(
            [intent.resource for intent in APPROVED_INTENTS], self.boundary.sent
        )
        self.assertEqual(
            {"approved_count": 2, "executed_count": 2, "unauthorized_count": 0,
             "unauthorized": [], "ok": True},
            result,
        )
        attribution = reconcile_attribution(self.boundary.sent, self.boundary.attribution)
        self.assertEqual(2, attribution["sent_count"])
        self.assertEqual(2, attribution["attribution_count"])
        self.assertEqual(0, attribution["unattributed_count"])
        self.assertTrue(attribution["ok"])
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in APPROVED_INTENTS},
            {record["intent_hash"] for record in self.boundary.attribution},
        )
        self.assertEqual(2, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(2, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the ambient token presented as a permit --------------------
    #
    # The incident's core move: the session skipped the
    # script and called the API with the token it could
    # read. Presented to the governed boundary as a
    # permit -- the role it played in the incident, where
    # holding it was enough -- the token is what it is: a
    # string the caller found in its environment. The
    # kernel treats it as a fabricated token and refuses
    # it at consume for every attempted send alike.
    # Reachability is not authority.

    def test_step1_ambient_token_presented_as_permit_denied(self) -> None:
        for intent in (CLIENT_UPDATE_INTENT,) + ATTEMPTED_INTENTS:
            self.assertFalse(self.boundary.execute(self.kernel, AMBIENT_TOKEN, intent))
        self.assertEqual([], self.boundary.sent)
        self.assertEqual([], self.boundary.attribution)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1 + len(ATTEMPTED_INTENTS), len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in (CLIENT_UPDATE_INTENT,) + ATTEMPTED_INTENTS},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: no approval at all ------------------------------------------
    #
    # With no artifact presented, the kernel declines to
    # mint for each attempted send: the extra message
    # beyond the day's approved budget, the ticket-ID
    # text, the quiet-hours announcement. The script's
    # budget was a count the caller was trusted to keep;
    # here the count is structural -- the day's sends are
    # the sends that have approvals, and there is no
    # third approval to mint from.

    def test_step2_no_approval_mints_nothing(self) -> None:
        for intent in ATTEMPTED_INTENTS:
            decision = self.kernel.evaluate(intent)
            self.assertEqual(
                ("require_approval", "approval_required"),
                (decision.outcome, decision.reason),
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.boundary.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.boundary.sent)
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(len(ATTEMPTED_INTENTS), len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the approved text, edited -----------------------------------
    #
    # The approval binds the exact message the operator
    # approved word for word. Two stretches of it: the
    # client text with an internal ticket ID inserted --
    # the script's ticket-ID ban, violated by editing
    # after approval -- and the same envelope presented
    # for the internal note. Both are refused as intent
    # mismatches. The ban is not a sentence in a prompt
    # the caller may honor; it is the difference between
    # the intent that was approved and the intent that
    # was not.

    def test_step3_approved_text_edited_or_stretched_denied(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            CLIENT_UPDATE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-client-text",
            nonce="nonce-client-text",
        )
        for intent in (TICKET_LEAK_INTENT, INTERNAL_NOTE_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual(
                ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.boundary.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.boundary.sent)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(2, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the approval window has closed ------------------------------
    #
    # Quiet hours, in the governed shape: the approval
    # envelope binds its own issue and expiry. An
    # envelope signed for the announcement whose window
    # has already closed -- issued and expired before
    # the attempt -- mints nothing. The script's clock
    # was a check the caller could skip by not calling
    # the script; the envelope's window is verified at
    # the boundary the caller cannot skip.

    def test_step4_expired_approval_window_denied(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            QUIET_HOURS_INTENT,
            self.verifier,
            now_ns=NOW - 2_000,
            ttl_ns=1_000,
            approval_id="approval-quiet-hours",
            nonce="nonce-quiet-hours",
        )
        decision = self.kernel.evaluate_with_approval(QUIET_HOURS_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_expired"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, QUIET_HOURS_INTENT))
        self.assertEqual([], self.boundary.sent)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: substitution, and the spent permit ---------------------------
    #
    # A genuine approval for the internal note, presented
    # for the client update: real authority for one
    # message is not authority for another, however
    # official the presentation. The denial does not
    # poison the path: the genuine pair still admits
    # afterward. And revocation-at-consume: the client
    # permit, once spent on its send, replays to nothing
    # -- for its own message, and stretched to the extra
    # unbudgeted send. Capture is not continuation.

    def test_step5_substituted_approval_denied_and_spent_permit_replays_to_nothing(self) -> None:
        other_envelope = signed_envelope(
            self.kernel,
            INTERNAL_NOTE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-internal",
            nonce="nonce-internal",
        )
        decision = self.kernel.evaluate_with_approval(CLIENT_UPDATE_INTENT, other_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.boundary.sent)
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))

        permit = self._issue_permit(
            self.kernel, CLIENT_UPDATE_INTENT, approval_id="approval-real", nonce="nonce-real"
        )
        self.assertTrue(self.boundary.execute(self.kernel, permit, CLIENT_UPDATE_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, permit, CLIENT_UPDATE_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, permit, EXTRA_SEND_INTENT))
        self.assertEqual([CLIENT_UPDATE_INTENT.resource], self.boundary.sent)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation over a governed day ---------------------------
    #
    # One working day, governed: the two approved
    # messages are sent; the incident's attempts follow
    # -- the token presented as a permit for the client
    # update and the extra send, the approved approval
    # stretched to the ticket-ID text, the extra send
    # evaluated with no approval. Every attempt is
    # denied, so the sent log stays exactly the approved
    # sends, reconciliation reports equality, and the
    # attribution reconciliation the studio's monitor
    # needed reports zero unattributed sends: oversight
    # can tell a governed send from an anomaly because
    # every governed send carries its record.

    def test_step6_reconciliation_governed_day_zero_unauthorized_zero_unattributed(self) -> None:
        for index, intent in enumerate(APPROVED_INTENTS):
            permit = self._issue_permit(
                self.kernel,
                intent,
                approval_id=f"approval-day-{index}",
                nonce=f"nonce-day-{index}",
            )
            self.assertTrue(self.boundary.execute(self.kernel, permit, intent))
        for intent in (CLIENT_UPDATE_INTENT, EXTRA_SEND_INTENT):
            self.assertFalse(self.boundary.execute(self.kernel, AMBIENT_TOKEN, intent))
        envelope = signed_envelope(
            self.kernel,
            CLIENT_UPDATE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-day-env",
            nonce="nonce-day-env",
        )
        decision = self.kernel.evaluate_with_approval(TICKET_LEAK_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, TICKET_LEAK_INTENT))
        decision = self.kernel.evaluate(EXTRA_SEND_INTENT)
        self.assertEqual("require_approval", decision.outcome)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, EXTRA_SEND_INTENT))

        approved = [intent.resource for intent in APPROVED_INTENTS]
        result = reconcile_consequences(approved, self.boundary.sent)
        self.assertEqual(2, result["approved_count"])
        self.assertEqual(2, result["executed_count"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertEqual([], result["unauthorized"])
        self.assertTrue(result["ok"])
        attribution = reconcile_attribution(self.boundary.sent, self.boundary.attribution)
        self.assertEqual(0, attribution["unattributed_count"])
        self.assertTrue(attribution["ok"])
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the attempts -----------------------
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

    def test_step7_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(CLIENT_UPDATE_INTENT)
        # The ambient token as permit, for the extra send.
        self.assertFalse(
            self.boundary.execute(self.kernel, AMBIENT_TOKEN, EXTRA_SEND_INTENT)
        )
        # The genuine client approval stretched to the
        # ticket-ID text and to the internal note.
        envelope = signed_envelope(
            self.kernel,
            CLIENT_UPDATE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-client",
            nonce="nonce-seq-client",
        )
        for intent in (TICKET_LEAK_INTENT, INTERNAL_NOTE_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_intent_mismatch", decision.reason)
        # The quiet-hours announcement under its expired
        # approval window.
        expired_envelope = signed_envelope(
            self.kernel,
            QUIET_HOURS_INTENT,
            self.verifier,
            now_ns=NOW - 2_000,
            ttl_ns=1_000,
            approval_id="approval-seq-quiet",
            nonce="nonce-seq-quiet",
        )
        decision = self.kernel.evaluate_with_approval(QUIET_HOURS_INTENT, expired_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_expired", decision.reason)
        # The one legitimate send still lands; the
        # attempted sends did not.
        permit = self._issue_permit(
            self.kernel, CLIENT_UPDATE_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.boundary.execute(self.kernel, permit, CLIENT_UPDATE_INTENT))
        self.assertEqual([CLIENT_UPDATE_INTENT.resource], self.boundary.sent)
        # The spent permit re-presented: the bypass's
        # continuation, refused.
        self.assertFalse(self.boundary.execute(self.kernel, permit, CLIENT_UPDATE_INTENT))
        self.assertEqual([CLIENT_UPDATE_INTENT.resource], self.boundary.sent)

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
        self.assertEqual(3, len(approval_rejected))
        self.assertEqual(3, len(denied_decisions))
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
        self.assertEqual(9, report.near_misses)
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

    # -- negative control ------------------------------------------------------

    def test_negative_control_direct_boundary_sends_on_ambient_token_without_attribution(self) -> None:
        # Same boundary, no governor: the caller who can
        # read the token sends directly -- the position
        # Morris's sessions were in -- and every attempted
        # message goes out: the client update, the
        # ticket-ID text the script existed to keep out of
        # client channels, the unbudgeted extra. Every
        # step "succeeds." That is the incident,
        # reproduced at the exact layer it happened: not a
        # weakness in any one check -- the checks all
        # existed -- but the absence of a boundary the
        # caller could not walk around.
        boundary = DirectSlackBoundary(AMBIENT_TOKEN)
        for intent in (CLIENT_UPDATE_INTENT,) + ATTEMPTED_INTENTS:
            self.assertTrue(boundary.send_direct(AMBIENT_TOKEN, intent))
        self.assertEqual(
            [intent.resource for intent in (CLIENT_UPDATE_INTENT,) + ATTEMPTED_INTENTS],
            boundary.sent,
        )
        # Per-occurrence reconciliation reports every send
        # beyond the day's approved two as unauthorized --
        # and, the sharper failure, reports the approved
        # client update itself as unattributed: the
        # monitor cannot distinguish a legitimate direct
        # send from a rogue one, because neither carries a
        # record. That indistinguishability is what turned
        # five human messages into five false alarms.
        result = reconcile_consequences(
            [intent.resource for intent in APPROVED_INTENTS], boundary.sent
        )
        self.assertEqual(2, result["approved_count"])
        self.assertEqual(4, result["executed_count"])
        self.assertEqual(3, result["unauthorized_count"])
        self.assertEqual(
            [TICKET_LEAK_INTENT.resource, QUIET_HOURS_INTENT.resource, EXTRA_SEND_INTENT.resource],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        attribution = reconcile_attribution(boundary.sent, boundary.attribution)
        self.assertEqual(4, attribution["sent_count"])
        self.assertEqual(0, attribution["attribution_count"])
        self.assertEqual(4, attribution["unattributed_count"])
        self.assertFalse(attribution["ok"])
        # Contrast, the identical first step on the
        # governed path: the client update attempted with
        # the token as its permit is refused at consume
        # (step 1's route), and reconciliation over the
        # governed boundary's logs reports zero
        # unauthorized and zero unattributed.
        self.assertFalse(
            self.boundary.execute(self.kernel, AMBIENT_TOKEN, CLIENT_UPDATE_INTENT)
        )
        result = reconcile_consequences(
            [intent.resource for intent in APPROVED_INTENTS], self.boundary.sent
        )
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])
        attribution = reconcile_attribution(self.boundary.sent, self.boundary.attribution)
        self.assertEqual(0, attribution["unattributed_count"])
        self.assertTrue(attribution["ok"])


if __name__ == "__main__":
    unittest.main()

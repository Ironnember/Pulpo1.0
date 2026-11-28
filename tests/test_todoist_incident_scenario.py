"""Scenario test: the Todoist breach -- a possessed
credential treated as authority over the authority
system itself (disclosed 2026-11-24).

Event (graded from the public record): Todoist's own
security notice (Recorded, the company's incident
article "Security incident in November 2026,"
published 2026-11-24, read firsthand) establishes the
chain. Between November 22 and 23, 2026, an attacker
used a stolen credential associated with Todoist's
version control system to modify automated workflows
in three repositories and obtain additional
credentials; the attacker could also read source code,
and Todoist's investigation found no changes to
application code. One of the harvested credentials was
an administrative credential for the employee sign-in
system -- it "allowed them to change how employees
access our internal systems." The timeline the notice
publishes (UTC): earliest identified use of the stolen
development credential November 22, 14:04, modifying
workflows to harvest credentials; November 23, 06:06,
the administrative credential for the employee sign-in
system obtained through an infrastructure automation
workflow; 06:33-06:54, the attacker changed an
employee's authentication settings and signed in to
the cloud infrastructure as that employee; 08:20-08:22,
additional persistence accounts created; 09:08 onward,
production databases accessed and commands run in
production; 12:45-12:51, account records exported and
downloaded; 13:05-17:12, targeted queries for account
tokens, connected Outlook mailbox access, and searches
of customer content for credentials; 17:01, detection
-- security monitoring flagged an unexpected
administrator account. What was taken (Recorded, same
notice): email addresses, salted SHA1 password hashes,
and account creation dates for approximately 6% of
users (early accounts still on the legacy hashing
method); Todoist API and Slack integration tokens for
approximately 0.003%; credential-like content in tasks
and comments for approximately 0.001%; email previews
through connected Todoist for Outlook accounts for
approximately 0.001%. TechCrunch's reporting
(Recorded, 2026-11-25) corroborates the notice and
carries Todoist's figure of more than 50 million
users. How the original credential was stolen is
Unknown: Todoist states it has not established this;
its leading theory -- an employee's device may have
been compromised -- is expressly unconfirmed.

The failure is: **a possessed credential is not
approval of the act.** At no point in the reported
chain did any boundary ask whether THIS act was
approved by an accountable human. Possession of the
version-control credential was sufficient to rewrite
automated workflows; possession of what those
workflows yielded was sufficient to rewrite how
employees authenticate -- a change to the authority
system itself, executed on a credential alone;
possession of the rewritten access was sufficient to
sign in as an employee; and that session was
sufficient to export and download the bulk account
records. Each step's only requirement was the previous
step's output. Under the canonical kernel, each of
those acts is a consequential act that requires a
permit bound to a verified approval of its exact
intent -- principal, action, resource, cost, session
-- minted from an approval envelope signed by an
enrolled authority. A credential, stolen or otherwise,
presented at ``consume`` is an unauthenticated string:
it is evidence of possession, never authority. The
governed chain therefore breaks at its first
consequential link: the access-configuration change
refuses at consume, the refusal burns nothing, and the
takeover path downstream of it never opens. The bulk
export is likewise its own governed act: it executes
only under a permit bound to the exact file and scope
that a human approved, and no permit minted for any
other act -- and no credential, however privileged --
spends on it.

This module models that property against the
canonical kernel API. It does NOT reproduce Todoist's
or Doist's systems, any version-control platform, any
sign-in system, or any cloud infrastructure. The
mapping (Inferred, stated here so it can be argued
with): the internal-systems boundary is the governed
boundary; the authentication-settings change is one
intent, distinguished by its change set -- the change
a human approved versus the change the attacker made
to the same employee's settings; the sign-in-as-
employee is a second intent; the bulk export is a
third intent, distinguished by the exact file and
scope; the stolen and harvested credentials are
modeled as the artifacts the reported chain actually
ran on, presented at ``consume`` in the role they
played there. Every count in this module (an approved
export's scope, an attack export's size) is a scenario
parameter in abstract units, not a reported figure;
the reported scope percentages live in the change
record's claim classification, not in the intents.

Setup (approval path): exactly two acts are
legitimate -- one authentication-settings change,
under a verified approval envelope bound to its exact
change set, and one scoped records export, under its
own envelope bound to the exact file and scope. The
attacker's chain is then attempted on the governed
path: the unapproved configuration change with the
genuine change's permit (presented before the genuine
spend, so the refusal's cost is observable) and with
the harvested credential presented as a permit; the
takeover with the harvested credential; the bulk
export with the scoped export's permit, with the
stolen credential, and with no artifact at all. The
kernel must deny each one, the boundary's consequence
log must stay exactly the two approved acts, every
denial must land in the audit record, and each genuine
permit must still spend on its own act after the
mismatched attempts.

Negative control (the as-reported architecture): a
test-local possession boundary that does exactly what
the notice describes -- it takes the presented
credential at face value, and possession is the whole
check. On it, the stolen version-control credential
rewrites the workflows and harvests the sign-in
administrator credential; that credential rewrites an
employee's authentication settings; the rewritten
access signs in as the employee; and the session
exports and downloads the bulk account records.
Per-occurrence reconciliation over the control's log
counts every executed act as carrying no exact-action
approval: the records the reported architecture
produces cannot distinguish an approved act from an
unapproved one, because no approval was ever asked
for -- that absence is the finding.

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
for these action classes (Verified, executable
evidence). It proves nothing about Todoist's actual
systems or controls, any version-control or sign-in
product, or any deployed environment that does not
route its internal acts through this kernel -- an
internal path that executes on a possessed credential
alone is governed by nothing here. The replay models
the authorization steps the reported chain did not
have, not any participant's internals. A control not
on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this event is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act, and any path that treats a
possessed credential as authority for the act (the
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
# The presenters at the internal-systems boundary.
# The configuration acts arrive under the identity the
# harvested sign-in administrator credential
# authenticates as -- in the reported event, that
# credential's holder changed an employee's
# authentication settings, and the boundary saw the
# administrator, not the attacker. The production acts
# arrive under the taken-over employee's work account.
# That is precisely the property the scenario probes:
# the boundary sees a legitimate identity and a
# possessed credential, and must still ask whether the
# human approved THIS act.
SIGNIN_ADMIN = "cred:employee-signin-admin"
EMPLOYEE = "employee:work-account"
SESSION = "todoist-production-2026-11"

# The one legitimate configuration act: an
# authentication-settings change a human approver
# approved, identified by its change set.
GENUINE_CONFIG_INTENT = Intent(
    SIGNIN_ADMIN,
    "change_access_configuration",
    "employee-signin:auth-settings/change-set-approved",
    1,
    SESSION,
)
# The attacker's configuration act (Recorded as an
# event; modeled here as an intent): the change to an
# employee's authentication settings made at
# 06:33-06:54 UTC on November 23 under the harvested
# credential -- same system, same action, a change set
# no human approved.
ATTACKER_CONFIG_INTENT = Intent(
    SIGNIN_ADMIN,
    "change_access_configuration",
    "employee-signin:auth-settings/change-set-unapproved",
    1,
    SESSION,
)
# The takeover: signing in to the cloud infrastructure
# as the employee, downstream of the configuration
# change in the reported chain.
TAKEOVER_INTENT = Intent(
    SIGNIN_ADMIN, "sign_in_as_employee", "employee-account:work-account", 1, SESSION
)
# The one legitimate export: a scoped records export a
# human approver approved, bound to the exact file and
# scope. The scope figure is a scenario parameter in
# abstract units, not a reported count.
GENUINE_EXPORT_INTENT = Intent(
    EMPLOYEE,
    "export_account_records",
    "export:scoped-compliance-records",
    250,
    SESSION,
)
# The attacker's export (Recorded as an event; modeled
# here as an intent): the bulk download of the legacy
# account-records file at 12:45-12:51 UTC on
# November 23. Its size figure is a scenario parameter
# in abstract units, not a reported count.
ATTACKER_EXPORT_INTENT = Intent(
    EMPLOYEE, "export_account_records", "export:legacy-account-records-file", 9_000, SESSION
)
# The chain's entry act (negative control; also probed
# on the governed path in step 3): modifying the
# automated workflows in the repositories, presented
# under the stolen version-control credential's
# identity.
WORKFLOW_INTENT = Intent(
    "cred:version-control",
    "modify_automation_workflow",
    "vcs:workflow-change-credential-harvest",
    1,
    SESSION,
)

# The possessed artifacts the reported chain ran on,
# modeled as the strings they are when presented at a
# boundary: the stolen version-control credential, and
# the sign-in administrator credential the workflow
# modification harvested. Neither is a real credential;
# both are labels for the modeled artifacts.
STOLEN_VCS_CREDENTIAL = "cred:version-control-stolen"
HARVESTED_ADMIN_CREDENTIAL = "cred:employee-signin-admin-harvested"


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the reported internal path never
    runs: run over the reported architecture's own shape
    (the negative control), it reports every executed
    act as carrying no exact-action approval.
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


class GovernedBoundary:
    """Consequences on the internal path, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the reported chain was not: in
    the reported chain, possession of the next
    credential was itself sufficient to perform the
    next act. Here the harness executes an act only
    when the kernel consumes a permit for the exact
    intent, and records each executed act in the log
    the reconciliation checks. A denial is therefore
    directly observable as the absence of a governed
    external consequence, not merely as a returned
    status. (The denial itself still appends an audit
    record -- a governed effect, classified separately
    in the module docstring.)
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


class PossessionBoundary:
    """The reported architecture, as a test-local double for the negative control.

    No kernel, no permit, no verified approval of any
    act: the boundary takes the presented credential at
    face value -- the position the reported internal
    path was in at every step -- and possession is the
    whole check. Any act presented with a credential
    executes, whoever composed it and whatever it does;
    each step's output (a harvested credential, a
    rewritten configuration, a session) is simply the
    next step's presented artifact. Every execution is
    recorded in the same log shape the governed
    boundary produces, so the one reconciliation runs
    over both paths and the difference is in the
    counts, not in the bookkeeping. Test-local; never
    imported by runtime code.
    """

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute(self, credential: str | None, intent: Intent) -> bool:
        if not credential:
            return False
        self.executed.append(intent.resource)
        return True

    def harvest_admin_credential(self, credential: str | None, intent: Intent) -> str | None:
        # The workflow modification's yield, as reported:
        # among the credentials the modified workflows
        # harvested was the administrator credential for
        # the employee sign-in system.
        if not self.execute(credential, intent):
            return None
        return HARVESTED_ADMIN_CREDENTIAL


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class TodoistApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = GovernedBoundary()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset(
            {
                "change_access_configuration",
                "sign_in_as_employee",
                "export_account_records",
                "modify_automation_workflow",
            }
        )
        policy = Policy(
            actions,
            1_000_000,
            actions,
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"todoist-scenario-secret",
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

    def test_positive_control_approved_acts_execute_exactly_once(self) -> None:
        config_permit = self._issue_permit(
            self.kernel, GENUINE_CONFIG_INTENT, approval_id="approval-pc-1", nonce="nonce-pc-1"
        )
        export_permit = self._issue_permit(
            self.kernel, GENUINE_EXPORT_INTENT, approval_id="approval-pc-2", nonce="nonce-pc-2"
        )
        # The two legitimate acts: the approved
        # authentication-settings change, and the approved
        # scoped export -- each under a genuine,
        # well-formed verified approval bound to its exact
        # intent.
        self.assertTrue(self.boundary.execute(self.kernel, config_permit, GENUINE_CONFIG_INTENT))
        self.assertTrue(self.boundary.execute(self.kernel, export_permit, GENUINE_EXPORT_INTENT))
        self.assertEqual(
            [GENUINE_CONFIG_INTENT.resource, GENUINE_EXPORT_INTENT.resource],
            self.boundary.executed,
        )
        # Each permit was spent at its consume: neither
        # approved act can run twice on one approval.
        self.assertFalse(self.boundary.execute(self.kernel, config_permit, GENUINE_CONFIG_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, export_permit, GENUINE_EXPORT_INTENT))
        self.assertEqual(
            [GENUINE_CONFIG_INTENT.resource, GENUINE_EXPORT_INTENT.resource],
            self.boundary.executed,
        )
        # Reconciliation: what was executed is exactly
        # what was approved, per occurrence.
        result = reconcile_consequences(
            [GENUINE_CONFIG_INTENT.resource, GENUINE_EXPORT_INTENT.resource],
            self.boundary.executed,
        )
        self.assertEqual(
            {"approved_count": 2, "executed_count": 2, "unauthorized_count": 0,
             "unauthorized": [], "ok": True},
            result,
        )
        self.assertEqual(2, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(2, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the configuration change refused at consume, refusal is free --
    #
    # The scenario's central attempt: the genuine change's
    # permit -- real authority, minted through a verified
    # approval for the approved change set -- presented
    # FIRST for the attacker's change set: the same
    # system, the same action, a change no human approved.
    # The permit binds one intent hash; at consume the
    # kernel compares the token's authenticated digest to
    # the presented intent and refuses. And the refusal
    # burns nothing: the same permit then spends on its
    # own act, exactly once. Because the configuration
    # change never executes, the chain's next link never
    # becomes reachable on this path either: the takeover
    # attempted with the harvested credential -- the
    # artifact the ungoverned chain would have run on --
    # is refused at the same boundary. Under the reported
    # architecture neither attempt faces the question: the
    # possessed credential is the whole check at both.

    def test_step1_attacker_config_change_refused_at_consume_and_refusal_burns_nothing(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_CONFIG_INTENT)
        self.assertFalse(self.boundary.execute(self.kernel, permit, ATTACKER_CONFIG_INTENT))
        self.assertEqual([], self.boundary.executed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(ATTACKER_CONFIG_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The chain does not advance past the refusal: the
        # takeover, presented with the harvested
        # administrator credential as its permit, is
        # refused at the same boundary.
        self.assertFalse(
            self.boundary.execute(self.kernel, HARVESTED_ADMIN_CREDENTIAL, TAKEOVER_INTENT)
        )
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        # The denial consumed nothing: the approved change
        # still spends, exactly once.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_CONFIG_INTENT))
        self.assertEqual([GENUINE_CONFIG_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: a possessed credential is not a permit -----------------------
    #
    # The only artifacts the reported chain ever presented
    # were credentials -- stolen, harvested, and, through
    # the takeover, a live session. Presented at the
    # governed boundary as permits -- the role they played
    # on the reported path, where presenting one was
    # sufficient to perform the act -- each is what it is:
    # a string the presenter holds. The kernel cannot
    # authenticate any of them as a permit and refuses
    # each at consume: for the attacker's configuration
    # change, for the takeover, for the bulk export, and
    # for the genuine configuration change alike.
    # Possession authenticates a holder, and authorizes
    # no act -- not even a legitimate one.

    def test_step2_stolen_credential_presented_as_permit_authorizes_nothing(self) -> None:
        attempts = [
            (HARVESTED_ADMIN_CREDENTIAL, ATTACKER_CONFIG_INTENT),
            (HARVESTED_ADMIN_CREDENTIAL, TAKEOVER_INTENT),
            (STOLEN_VCS_CREDENTIAL, ATTACKER_EXPORT_INTENT),
            (STOLEN_VCS_CREDENTIAL, GENUINE_CONFIG_INTENT),
        ]
        for credential, intent in attempts:
            self.assertFalse(self.boundary.execute(self.kernel, credential, intent))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(4, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for _, intent in attempts},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: no minting path from possession ------------------------------
    #
    # Two remainders of the reported chain's shape. First,
    # with no artifact presented at all, the kernel
    # declines to mint for every act in the chain -- the
    # workflow modification, the configuration change,
    # the takeover, the bulk export: holding any of the
    # chain's credentials confers no route to a permit.
    # Second, the attacker's own signature: an approval
    # envelope for the configuration change, well-formed
    # in every field but signed with a key the attacker
    # controls rather than the enrolled authority's. The
    # kernel verifies against the enrolled authority, and
    # the party requesting the act cannot also be the
    # party approving it.

    def test_step3_no_approval_mints_nothing_and_attacker_signed_envelope_denied(self) -> None:
        chain = (
            WORKFLOW_INTENT,
            ATTACKER_CONFIG_INTENT,
            TAKEOVER_INTENT,
            ATTACKER_EXPORT_INTENT,
        )
        for intent in chain:
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
        self.assertEqual(4, len(decisions))

        attacker_signed = HmacTestVerifier(b"attacker-controlled-key")
        envelope = signed_envelope(
            self.kernel, ATTACKER_CONFIG_INTENT, attacker_signed, now_ns=NOW,
            approval_id="approval-attacker-asserted", nonce="nonce-attacker-asserted",
        )
        decision = self.kernel.evaluate_with_approval(ATTACKER_CONFIG_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.boundary.execute(self.kernel, decision.permit, ATTACKER_CONFIG_INTENT)
        )
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: reconciliation over the governed sequence ---------------------
    #
    # The reported chain ran end to end with nothing on
    # the path comparing what was done with what any human
    # approved. This step runs that comparison over a
    # governed sequence shaped like the event: the two
    # approved acts execute; between and around them, the
    # attacker's chain is attempted under every form the
    # event makes available -- the genuine change's permit
    # stretched to the attacker's change set, the
    # harvested credential presented for the takeover, the
    # scoped export's permit stretched to the bulk file,
    # the stolen credential presented for the bulk file,
    # and both spent permits replayed. Every unapproved
    # attempt is denied, so the executed log stays exactly
    # the approved acts and reconciliation reports
    # equality -- zero unauthorized occurrences, and no
    # refused attempt recorded as fulfilled.

    def test_step4_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        config_permit = self._issue_permit(
            self.kernel, GENUINE_CONFIG_INTENT, approval_id="approval-rec-1", nonce="nonce-rec-1"
        )
        self.assertFalse(self.boundary.execute(self.kernel, config_permit, ATTACKER_CONFIG_INTENT))
        self.assertFalse(
            self.boundary.execute(self.kernel, HARVESTED_ADMIN_CREDENTIAL, TAKEOVER_INTENT)
        )
        self.assertTrue(self.boundary.execute(self.kernel, config_permit, GENUINE_CONFIG_INTENT))
        export_permit = self._issue_permit(
            self.kernel, GENUINE_EXPORT_INTENT, approval_id="approval-rec-2", nonce="nonce-rec-2"
        )
        self.assertFalse(self.boundary.execute(self.kernel, export_permit, ATTACKER_EXPORT_INTENT))
        self.assertFalse(
            self.boundary.execute(self.kernel, STOLEN_VCS_CREDENTIAL, ATTACKER_EXPORT_INTENT)
        )
        self.assertTrue(self.boundary.execute(self.kernel, export_permit, GENUINE_EXPORT_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, config_permit, GENUINE_CONFIG_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, export_permit, GENUINE_EXPORT_INTENT))
        result = reconcile_consequences(
            [GENUINE_CONFIG_INTENT.resource, GENUINE_EXPORT_INTENT.resource],
            self.boundary.executed,
        )
        self.assertEqual(2, result["approved_count"])
        self.assertEqual(2, result["executed_count"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertEqual([], result["unauthorized"])
        self.assertTrue(result["ok"])
        self.assertEqual(6, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(2, len(_events(self.kernel, "permit_consumed")))
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
        self.kernel.evaluate(ATTACKER_CONFIG_INTENT)
        # The harvested credential presented as a permit,
        # for the attacker's configuration change.
        self.assertFalse(
            self.boundary.execute(self.kernel, HARVESTED_ADMIN_CREDENTIAL, ATTACKER_CONFIG_INTENT)
        )
        # The genuine approval stretched to the attacker's
        # change set.
        envelope = signed_envelope(
            self.kernel,
            GENUINE_CONFIG_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(ATTACKER_CONFIG_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate configuration act still lands;
        # the attacker's did not.
        permit = self._issue_permit(
            self.kernel, GENUINE_CONFIG_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_CONFIG_INTENT))
        self.assertEqual([GENUINE_CONFIG_INTENT.resource], self.boundary.executed)
        # The spent permit re-presented: refused.
        self.assertFalse(self.boundary.execute(self.kernel, permit, GENUINE_CONFIG_INTENT))
        self.assertEqual([GENUINE_CONFIG_INTENT.resource], self.boundary.executed)

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

    def test_negative_control_possession_boundary_executes_the_whole_chain(self) -> None:
        # Same boundary shape, no governor: the presented
        # credential is taken at face value -- the position
        # the reported internal path was in at every step
        # -- and possession is the only check there is.
        boundary = PossessionBoundary()
        # With no artifact at all, nothing executes: the
        # chain needs its first possessed credential, which
        # is the only threshold the reported architecture
        # ever enforced.
        self.assertFalse(boundary.execute(None, WORKFLOW_INTENT))
        self.assertEqual([], boundary.executed)
        # (a) The stolen version-control credential rewrites
        # the automated workflows, and the modification
        # yields the sign-in administrator credential --
        # November 22, 14:04 UTC onward, as reported.
        admin_credential = boundary.harvest_admin_credential(STOLEN_VCS_CREDENTIAL, WORKFLOW_INTENT)
        self.assertEqual(HARVESTED_ADMIN_CREDENTIAL, admin_credential)
        # (b) The harvested credential rewrites an
        # employee's authentication settings -- the change
        # to how employees access the internal systems,
        # November 23, 06:33-06:54 UTC.
        self.assertTrue(boundary.execute(admin_credential, ATTACKER_CONFIG_INTENT))
        # (c) Under the rewritten configuration, the
        # attacker signs in to the infrastructure as the
        # employee -- the takeover the configuration change
        # existed to enable.
        self.assertTrue(boundary.execute(admin_credential, TAKEOVER_INTENT))
        # (d) The session exports and downloads the bulk
        # legacy account-records file -- November 23,
        # 12:45-12:51 UTC. Nothing between (a) and (d)
        # asked whether any of it was approved; each step
        # required only the previous step's output.
        self.assertTrue(boundary.execute(admin_credential, ATTACKER_EXPORT_INTENT))
        self.assertEqual(
            [
                WORKFLOW_INTENT.resource,
                ATTACKER_CONFIG_INTENT.resource,
                TAKEOVER_INTENT.resource,
                ATTACKER_EXPORT_INTENT.resource,
            ],
            boundary.executed,
        )
        # Per-occurrence reconciliation against exact-action
        # approvals -- of which the possession architecture
        # produces none, for any act -- reports every
        # executed act as an unauthorized occurrence, named,
        # in chain order.
        result = reconcile_consequences([], boundary.executed)
        self.assertEqual(0, result["approved_count"])
        self.assertEqual(4, result["executed_count"])
        self.assertEqual(4, result["unauthorized_count"])
        self.assertEqual(
            [
                WORKFLOW_INTENT.resource,
                ATTACKER_CONFIG_INTENT.resource,
                TAKEOVER_INTENT.resource,
                ATTACKER_EXPORT_INTENT.resource,
            ],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        # Contrast, the identical bulk export on the
        # governed path: presented with the harvested
        # credential as its permit, it is refused at
        # consume (step 2's route), and reconciliation over
        # the governed boundary's log reports zero
        # unauthorized.
        self.assertFalse(
            self.boundary.execute(self.kernel, HARVESTED_ADMIN_CREDENTIAL, ATTACKER_EXPORT_INTENT)
        )
        result = reconcile_consequences([], self.boundary.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

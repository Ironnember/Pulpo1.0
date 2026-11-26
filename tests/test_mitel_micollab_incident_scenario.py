"""Scenario test: the Mitel MiCollab zero-day
exploitation -- five unauthenticated flaws, including an
authentication bypass, exploited before the advisory
existed (reported 2026-11-26).

Incident (Recorded, from SecurityWeek's 2026-11-26
reporting of Accenture Apex Labs' investigation,
converged with Mitel's advisory MISA-2026-0012, first
issued 2026-11-16 and updated 2026-11-24): Mitel patched
five vulnerabilities in MiCollab's Audio, Web and Video
Conferencing (AWV) component, all exploitable by
unauthenticated attackers -- CVE-2026-133275 (arbitrary
file upload, Medium 5.3), CVE-2026-133303 (XML injection,
Critical 9.0, arbitrary command execution),
CVE-2026-133311 (unauthorized access, Medium 5.9),
CVE-2026-133323 (command injection, Critical 10.0,
arbitrary command execution), and CVE-2026-133324
(authentication bypass, Medium 5.3). Accenture found
evidence the flaws were exploited in the wild before
Mitel published its advisory: a web shell was deployed
on a victim's systems on November 15, and a second
victim's MiCollab server had been communicating with the
same attacker infrastructure since November 9 (how that
second server was compromised could not be established;
it had also been affected by older vulnerabilities). In
the first attack, the attackers executed commands on the
MiCollab server just 12 minutes after the first request,
gained root privileges within half an hour, harvested
additional credentials, and, roughly 20 hours after the
first observed request, gained access to internal backup
and database servers; Accenture reports the attackers
also reached the organization's identity infrastructure
and stole sensitive business information. CISA added all
five flaws to its Known Exploited Vulnerabilities
catalog on November 25, with remediation deadlines of
November 28 for four of them and December 9 for the
last. Whether AI tools drove any part of the activity
is Unknown: Accenture observed attacker infrastructure
communicating with two commercial AI API services and
noted the sampled telemetry could not determine
precisely how they were used. This replay does not
model AI involvement in any form.

The failure is a fail-open consequence boundary: the
server's consequential acts -- uploading a file,
executing a command, opening a session, reaching an
internal server -- were reachable with no authentication
at all, and one of the five flaws removed even the
appearance of authentication by bypassing it. No act
required a per-action authorization bound to the exact
act, and nothing spent or revoked whatever access a
request appeared to carry, so the first request's reach
extended, unrechecked, from a web shell at minute zero
to root at 30 minutes to backup and database servers at
20 hours.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce MiCollab,
the AWV component, any of the five vulnerabilities, a
web shell, or any attacker tooling. The mapping
(Inferred, stated here so it can be argued with): the
consequential acts are commands executed by the
MiCollab server's executor -- the dispatch boundary the
incident's unauthenticated requests fed into. Each
incident step is a distinct intent over that executor:
the web-shell upload, the root command, and the
backup/database access. The one legitimate act is a
single approved administrative command. An approval for
that act presented for any incident step is refused as
an intent mismatch; the same approval presented in a
session the attacker opened for itself -- the
authentication-bypass session, CVE-2026-133324's shape
-- is refused as a session mismatch, because session
identity is part of the bound intent and a bypassed
authentication grants no session the kernel recognizes.
The only route from a request to a consequence is a
successful ``GovernanceKernel.consume`` of a permit
bound to the exact intent hash: principal, action,
resource, cost, session. A permit is spent at its first
consume -- revocation-at-consume -- so a consumed permit
re-presented for the same act, or stretched to a later
incident step, is refused at the consequence boundary.

Setup: exactly one act is legitimate in this scenario
-- one administrative command on the MiCollab server,
run once, in the session the approval names, under a
permit issued through a verified approval envelope.
Every act the incident records is then attempted on the
governed path: with no approval at all, under the
administrative approval in a bypassed-authentication
session, as the timeline's escalation steps under that
same approval, with a forged approval, with a genuine
approval for a different act substituted, and by
replaying the spent permit. The kernel must deny each
one, the executor's consequence log must stay exactly
the one approved act, and every denial must land in the
audit record.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records. A
bare ``evaluate`` that returns ``require_approval`` --
the kernel declining to mint without approval --
appends a decision record to the canonical audit but is
NOT derived as a near-miss by the channel. The scenario
asserts both halves of that statement exactly as they
hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit
for these action classes (Verified, executable
evidence). It proves nothing about any deployed
MiCollab server or AWV component that does not route
its requests through this kernel -- an unauthenticated
endpoint that executes directly is governed by nothing
here. The replay models the authorization step the
incident's server did not have, not Mitel internals. A
control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act and session, and any request
path that reaches a consequence without authentication
or through a bypassed session (the incident's own
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
recorded in the executor's log), never audit growth.
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
# The MiCollab server's executor: the dispatch boundary
# the incident's unauthenticated requests fed into.
# Every intent below is an act this executor would
# perform; an unauthenticated network peer proposes, the
# executor must not run anything without a permit bound
# to the act.
SERVER = "agent:mitel-micollab-server"
# The session the approval names -- the administrator's
# session. Session identity is part of the bound intent;
# the incident's authentication bypass is modeled as a
# session the attacker opened for itself, which no
# approval names.
SESSION = "admin-session-1"
BYPASS_SESSION = "auth-bypass-session"

# The one approved act: a single administrative command
# on the MiCollab server, in the named session.
ADMIN_INTENT = Intent(SERVER, "execute_command", "micollab:awv/admin-command", 25, SESSION)
# The incident's first observed consequence (November
# 15): a web shell deployed on the server -- an
# arbitrary file upload (CVE-2026-133275's class) turned
# into an executable foothold.
WEBSHELL_INTENT = Intent(SERVER, "execute_command", "micollab:awv/web-shell", 25, SESSION)
# The incident at 12 minutes and ~30 minutes: commands
# executed on the server, then root privileges (the
# command-execution flaws, CVE-2026-133303 and
# CVE-2026-133323, are the recorded route classes).
ROOT_INTENT = Intent(SERVER, "execute_command", "micollab:host/root-command", 25, SESSION)
# The incident at ~20 hours: access to internal backup
# and database servers, after harvested credentials.
BACKUP_DB_INTENT = Intent(
    SERVER, "execute_command", "micollab:internal/backup-and-database-access", 25, SESSION
)
# The authentication bypass (CVE-2026-133324) as an
# intent: the approved act's own resource, proposed in a
# session the attacker created by bypassing
# authentication. Same act, wrong session -- no approval
# names this session.
BYPASS_SESSION_INTENT = Intent(
    SERVER, "execute_command", "micollab:awv/admin-command", 25, BYPASS_SESSION
)
# A genuine but different act: an unprivileged diagnostic
# command. An approval for this is real authority -- for
# this intent.
DIAGNOSTIC_INTENT = Intent(
    SERVER, "execute_command", "micollab:awv/diagnostic-command", 25, SESSION
)


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the incident's server never ran:
    run over the incident's own shape (the negative
    control), it reports every step of the timeline as
    unauthorized, by count and by name.
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


class MiCollabServer:
    """Consequences at the MiCollab server, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's workflow did not have: in the
    incident, an unauthenticated request WAS the
    execution path, and root and the internal servers
    followed. Here the harness executes an act only when
    the kernel consumes a permit for the exact intent,
    and records each executed act in the log the
    reconciliation checks. A denial is therefore directly
    observable as the absence of a governed external
    consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a
    governed effect, classified separately in the module
    docstring.)
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


class UngovernedMiCollabServer:
    """The incident's own path, as a test-local double for the negative control.

    No kernel, no permit, no approval, no authentication:
    an unauthenticated request is executed as presented,
    in the incident's timeline order -- the web shell,
    the root command, then the backup and database
    access. Every execution is recorded in the same log
    shape the governed server produces, so the one
    reconciliation runs over both paths and the
    difference is in the counts, not in the bookkeeping.
    Test-local; never imported by runtime code.
    """

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute_unauthenticated(self, intent: Intent) -> bool:
        self.executed.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class MitelMiCollabIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.server = MiCollabServer()

    def _kernel(self) -> GovernanceKernel:
        policy = Policy(
            frozenset({"execute_command"}),
            10_000,
            frozenset({"execute_command"}),
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"mitel-micollab-scenario-secret",
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

    def test_positive_control_admin_command_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, ADMIN_INTENT)
        # The one legitimate act: the administrative
        # command under a genuine, well-formed verified
        # approval.
        self.assertTrue(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        self.assertEqual([ADMIN_INTENT.resource], self.server.executed)
        # The permit was spent at that consume --
        # revocation-at-consume: the same permit cannot
        # run the command twice.
        self.assertFalse(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        self.assertEqual([ADMIN_INTENT.resource], self.server.executed)
        # Reconciliation: what was executed is exactly
        # what was approved, per occurrence.
        result = reconcile_consequences([ADMIN_INTENT.resource], self.server.executed)
        self.assertEqual(
            {"approved_count": 1, "executed_count": 1, "unauthorized_count": 0,
             "unauthorized": [], "ok": True},
            result,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no approval at all ----------------------------------------
    #
    # The incident's entry condition: every one of the
    # five flaws was exploitable by an unauthenticated
    # attacker. On the governed path an unauthenticated
    # request is not a weaker kind of approval -- it is
    # no approval, and the kernel declines to mint for
    # each of the timeline's acts alike.

    def test_step1_unauthenticated_requests_denied(self) -> None:
        for intent in (WEBSHELL_INTENT, ROOT_INTENT, BACKUP_DB_INTENT):
            decision = self.kernel.evaluate(intent)
            self.assertEqual(
                ("require_approval", "approval_required"),
                (decision.outcome, decision.reason),
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.server.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.server.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(3, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the bypassed-authentication session ------------------------
    #
    # CVE-2026-133324's shape: the attacker does not
    # steal the administrator's session -- it manufactures
    # its own by bypassing authentication, then presents
    # itself as authenticated. On the governed path the
    # session is part of the bound intent: a genuine
    # approval envelope for the administrative command,
    # presented for that same command in the bypass
    # session, is refused as a session mismatch. A
    # bypassed authentication produces a session no
    # approval names, and an unnamed session mints
    # nothing.

    def test_step2_bypassed_auth_session_denied(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            ADMIN_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-admin",
            nonce="nonce-admin",
        )
        decision = self.kernel.evaluate_with_approval(BYPASS_SESSION_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_session_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.server.execute(self.kernel, decision.permit, BYPASS_SESSION_INTENT)
        )
        self.assertEqual([], self.server.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the timeline's escalation under one approval ---------------
    #
    # The incident's speed came from escalation without
    # re-authorization: first request to commands in 12
    # minutes, root within half an hour, backup and
    # database servers at roughly 20 hours, each step
    # riding the reach of the one before. On the governed
    # path each step is an intent of its own, and the one
    # administrative approval covers none of them: the
    # web shell, the root command, and the backup/database
    # access are each refused as an intent mismatch, in
    # the incident's own order. Speed is irrelevant to a
    # boundary that re-checks every act.

    def test_step3_timeline_escalation_under_admin_approval_denied(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            ADMIN_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-admin-esc",
            nonce="nonce-admin-esc",
        )
        for intent in (WEBSHELL_INTENT, ROOT_INTENT, BACKUP_DB_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual(
                ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.server.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.server.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(3, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the consumed permit cannot be replayed ----------------------
    #
    # Revocation-at-consume: a permit is spent by its
    # first successful consume, so whatever an attacker
    # captures after the legitimate act -- the permit
    # itself, in the incident's terms the foothold the
    # first request bought -- replays to nothing. The
    # spent permit is refused at consume for its own act,
    # and refused again when stretched to the timeline's
    # next step. Capture is not continuation.

    def test_step4_consumed_permit_replay_denied(self) -> None:
        permit = self._issue_permit(
            self.kernel, ADMIN_INTENT, approval_id="approval-s1", nonce="nonce-s1"
        )
        self.assertTrue(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        # Replay of the spent permit, for its own act and
        # stretched to the root command: refused at
        # consume both times.
        self.assertFalse(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        self.assertFalse(self.server.execute(self.kernel, permit, ROOT_INTENT))
        self.assertEqual([ADMIN_INTENT.resource], self.server.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        result = reconcile_consequences([ADMIN_INTENT.resource], self.server.executed)
        self.assertTrue(result["ok"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: substitution and forgery ------------------------------------

    def test_step5_substituted_and_forged_approvals_denied(self) -> None:
        # (a) A genuine approval for a DIFFERENT act (the
        # unprivileged diagnostic), presented for the
        # administrative command: real authority for one
        # act is not authority for another, however
        # similar the acts look.
        other_envelope = signed_envelope(
            self.kernel,
            DIAGNOSTIC_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-other",
            nonce="nonce-other",
        )
        decision = self.kernel.evaluate_with_approval(ADMIN_INTENT, other_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) An envelope for the administrative command
        # signed with an unauthorized key: whoever reaches
        # the server cannot mint its authority -- the
        # unauthenticated attacker's position exactly.
        forged_envelope = signed_envelope(
            self.kernel, ADMIN_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW,
            approval_id="approval-forged", nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(ADMIN_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.server.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_intent_mismatch", "approval_signature_invalid"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine
        # pair still admits.
        permit = self._issue_permit(
            self.kernel, ADMIN_INTENT, approval_id="approval-real", nonce="nonce-real"
        )
        self.assertTrue(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        self.assertEqual([ADMIN_INTENT.resource], self.server.executed)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation over the governed sequence -------------------
    #
    # The incident ran from November 15 (and, at the
    # second victim, November 9) until the advisory and
    # the investigation because nothing compared what the
    # server executed with what anyone had approved. This
    # step runs that comparison over a governed sequence
    # shaped like the incident's first day: one approved
    # administrative command, then the web shell, the
    # root command, and the backup/database access each
    # attempted under that approval. Every escalation
    # attempt is denied, so the executed log stays exactly
    # the approved act and reconciliation reports equality
    # -- zero unauthorized occurrences, not merely "the
    # server was touched." The same reconciliation
    # applied to the incident's reported shape is pinned
    # in the negative control, where it reports the counts
    # the governed path never produces.

    def test_step6_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, ADMIN_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertTrue(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        envelope = signed_envelope(
            self.kernel,
            ADMIN_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-rec-env",
            nonce="nonce-rec-env",
        )
        for intent in (WEBSHELL_INTENT, ROOT_INTENT, BACKUP_DB_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual("deny", decision.outcome)
            self.assertFalse(self.server.execute(self.kernel, decision.permit, intent))
        result = reconcile_consequences([ADMIN_INTENT.resource], self.server.executed)
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(1, result["executed_count"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertEqual([], result["unauthorized"])
        self.assertTrue(result["ok"])
        self.assertEqual(3, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the attempts ----------------------
    #
    # Surfacing, asserted exactly as it holds at this
    # commit: every consume rejection, every approval
    # rejection, and every denied decision in the sequence
    # becomes a near-miss record in the derived incident
    # report. The bare require_approval decision is in the
    # canonical audit (and counted below) but is NOT
    # derived as a near-miss -- the expected near-miss
    # count is built from the event classes the channel
    # actually derives, so this test pins the boundary
    # instead of papering over it.

    def test_step7_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(ADMIN_INTENT)
        envelope = signed_envelope(
            self.kernel,
            ADMIN_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-admin",
            nonce="nonce-seq-admin",
        )
        for intent in (WEBSHELL_INTENT, ROOT_INTENT):
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual("deny", decision.outcome)
            self.assertEqual("approval_intent_mismatch", decision.reason)
        other_envelope = signed_envelope(
            self.kernel,
            DIAGNOSTIC_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-other",
            nonce="nonce-seq-other",
        )
        decision = self.kernel.evaluate_with_approval(ADMIN_INTENT, other_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate act still lands; the
        # escalation steps did not.
        permit = self._issue_permit(
            self.kernel, ADMIN_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        self.assertEqual([ADMIN_INTENT.resource], self.server.executed)
        # The spent permit re-presented: the incident's
        # continuation, refused.
        self.assertFalse(self.server.execute(self.kernel, permit, ADMIN_INTENT))
        self.assertEqual([ADMIN_INTENT.resource], self.server.executed)

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
        self.assertEqual(1, len(permit_rejected))
        self.assertEqual(3, len(approval_rejected))
        self.assertEqual(3, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the
        # event classes the channel derives -- no more, no
        # fewer. The require_approval decision above is an
        # audit-recorded attempt that contributes zero
        # near-miss records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(7, report.near_misses)
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
                "decision": len(denied_decisions),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_ungoverned_server_executes_timeline(self) -> None:
        # Same server, no governor: unauthenticated
        # requests are executed as presented, in the
        # incident's timeline order -- the web shell
        # (November 15), commands and then root (12
        # minutes, ~30 minutes), and the backup and
        # database access (~20 hours). Every step
        # "succeeds." That is the incident, reproduced at
        # the exact layer it happened: not any one flaw --
        # the absence of an authorization boundary between
        # a network request and a consequence.
        server = UngovernedMiCollabServer()
        for intent in (WEBSHELL_INTENT, ROOT_INTENT, BACKUP_DB_INTENT):
            self.assertTrue(server.execute_unauthenticated(intent))
        self.assertEqual(
            [WEBSHELL_INTENT.resource, ROOT_INTENT.resource, BACKUP_DB_INTENT.resource],
            server.executed,
        )
        # Per-occurrence reconciliation reports the whole
        # timeline as unauthorized, by count and by name
        # -- the check whose absence let the exploitation
        # predate the advisory that described it.
        result = reconcile_consequences([], server.executed)
        self.assertEqual(0, result["approved_count"])
        self.assertEqual(3, result["executed_count"])
        self.assertEqual(3, result["unauthorized_count"])
        self.assertEqual(
            [WEBSHELL_INTENT.resource, ROOT_INTENT.resource, BACKUP_DB_INTENT.resource],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        # The bypassed session, ungoverned: the attacker
        # presents itself in a session it manufactured and
        # the act executes -- CVE-2026-133324's shape with
        # nothing behind the authentication to re-check
        # the act itself.
        bypass = UngovernedMiCollabServer()
        self.assertTrue(bypass.execute_unauthenticated(BYPASS_SESSION_INTENT))
        result = reconcile_consequences([], bypass.executed)
        self.assertEqual(1, result["unauthorized_count"])
        self.assertFalse(result["ok"])
        # Contrast, the identical first step on the
        # governed path: the web shell attempted under the
        # administrative approval is denied (step 3's
        # route), and reconciliation over the governed
        # server's log reports zero unauthorized.
        envelope = signed_envelope(
            self.kernel,
            ADMIN_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-nc-contrast",
            nonce="nonce-nc-contrast",
        )
        decision = self.kernel.evaluate_with_approval(WEBSHELL_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)


if __name__ == "__main__":
    unittest.main()

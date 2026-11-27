"""Scenario test: the Q-Dir / DesktopOK trojanized
installer -- a valid developer signature treated as
authority for whatever the installer does (reported
2026-11-26).

Event (graded from the public record): AhnLab ASEC
reported (Recorded, primary source: AhnLab ASEC,
2026-11-26, via The Hacker News,
https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html)
that installers for Q-Dir (versions 12.83-12.85) and
DesktopOK distributed via the official SoftwareOK
website were tampered with. The trojanized installer
runs the genuine utility -- the embedded binary
carries developer Nenad Hrg's valid signature --
while downloading a Python RAT that runs shell and
Python commands, transfers files, captures
screenshots, and persists via a scheduled task
impersonating Microsoft Edge, beaconing to a C2.
How the installers were replaced is Unknown on the
record, and no victim count is confirmed; neither is
claimed anywhere in this module.

CLAIM DISCIPLINE (load-bearing): this replay does
NOT reproduce the RAT, the C2, any installer, or any
SoftwareOK system, and no step executes payload code
of any kind -- the boundary's log entries are inert
labels. What the scenario models is the
architectural property the reporting establishes:
**the installer's trust was inherited by everything
the installer did.** The user who downloads from the
official site approves, at most, one act -- install
this utility, from this artifact. The payload
download and the payload execution are different
acts, approved by no one, and on the ungoverned path
they ride along under the install's trust: the valid
signature authenticates who signed the genuine
binary, and answers nothing about whether the
payload acts were authorized.

The failure is: **a valid signature is not
authorization.** A signature answers "who signed
this binary?" It does not answer "was THIS act --
downloading and executing a remote payload --
approved by the human?" Under the canonical kernel,
installing the utility is a consequential act that
requires a permit bound to the human's approved
intent -- principal, action, resource (the exact
installer artifact), cost, session -- minted from a
verified approval envelope signed by an enrolled
authority. The genuine approved install executes
under its permit, exactly once. The payload act is
refused at ``consume``: its intent matches no
approved intent. And the refusal burns nothing --
the genuine permit, presented first with the payload
intent, remains intact and still spends on its own
act. The valid signature is recorded in evidence
throughout and is explicitly never treated as
authorization: presented at ``consume`` in the role
it plays on the ungoverned path, it is refused, and
an approval envelope signed with the
developer-signature key -- the key behind that valid
signature -- is denied, because the signing
developer is not the enrolled approving authority.

This module models that property against the
canonical kernel API. The mapping (Inferred, stated
here so it can be argued with): the installer
execution boundary is the governed boundary; the
genuine install is the one approved intent, bound to
the exact installer artifact; the payload download
and execution are modeled on the governed path as
one substituted intent -- a different action and a
different resource -- that no human approved, and on
the negative-control path as the two distinct
executed acts the reporting describes (download,
then execution), so reconciliation there counts
each; the valid-signature reference is modeled as
the standing trust artifact the ungoverned path
actually relies on, presented at ``consume`` in the
role it plays there. Every name, version-specific
artifact label, and cost in this module beyond the
reported facts above is a scenario parameter in
abstract units. No amount, count, or identifier
here is a reported figure for the incident itself,
and no victim count is stated because none is
confirmed.

Setup (approval path): exactly one act is legitimate
-- the genuine install of the exact approved
installer artifact, once, under a verified approval
envelope bound to its exact intent. The payload act
is then attempted on the governed path: with the
genuine permit (presented before the genuine
install, so the refusal's cost is observable), with
the valid-signature reference presented as a permit,
with an envelope signed with the developer-signature
key, and with no artifact at all. The kernel must
deny each one, the boundary's consequence log must
stay exactly the one approved install, every denial
must land in the audit record, and the genuine
permit must still spend on its own act after the
mismatched attempt.

Negative control (the as-reported architecture): a
test-local install boundary that does exactly what
the reporting describes -- it takes an installer
presented from the official site, carrying the valid
signature, at face value, and runs what the
installer runs. On it, the genuine utility installs;
the payload download and the payload execution ride
along under the same trust, never approved by the
human as acts. Per-occurrence reconciliation over
the control's log counts the run explicitly:
1 approved, 3 executed, 2 unauthorized -- the two
payload acts, named.

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
decision). The governed sequence below therefore
reports 0 incidents and 5 near-misses. The negative
control has no kernel and no audit: its incident
count and near-miss count are both 0, and that zero
is an absence of records, not a finding of safety --
nothing on the ungoverned path records the payload
acts as anything at all. The scenario asserts both
halves of that statement exactly as they hold; it
does not smooth either over.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable
evidence). It proves nothing about SoftwareOK's,
Q-Dir's, DesktopOK's, or AhnLab's actual systems, or
any deployed software-distribution environment that
does not route its installs through this kernel --
an install path that executes on site trust and a
valid signature alone is governed by nothing here.
The replay models the authorization step the
reported flow does not have, not any participant's
internals. A control not on the execution path
governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this event is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act, and any path that treats a
valid signature or official-site provenance as
authority for whatever an installer does (the reported
architecture's class) remains outside this evidence
and open.

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
# The presenter at the install boundary: the installer
# process running on the user's machine (Recorded: the
# trojanized installer is what runs, and it both runs
# the genuine utility and fetches the payload). Acts
# arrive under the installer's identity, because the
# installer is what presents them -- which is precisely
# the property the scenario probes: the boundary sees
# the installer, its official-site provenance, and its
# valid signature, and must still ask whether the human
# approved THIS act.
INSTALLER = "agent:softwareok-installer"
SESSION = "softwareok-download-2026-11"

# The genuine act: installing Q-Dir from the exact
# installer artifact the human approved. The version
# range 12.83-12.85 is Recorded; the specific artifact
# label and the cost are scenario parameters, in
# abstract units.
GENUINE_INTENT = Intent(
    INSTALLER, "install_utility", "installer:q-dir-12.84-softwareok", 1, SESSION
)
# The substituted act (modeled from the Recorded
# payload behavior): downloading and executing the
# Python RAT. A different action and a different
# resource from the install, inside no approval anyone
# gave. On the governed path it is one intent; the
# negative control separates its download and execution
# occurrences for reconciliation, as the reporting does.
PAYLOAD_INTENT = Intent(
    INSTALLER, "download_execute_payload", "payload:python-rat-c2", 1, SESSION
)

# The payload acts as distinct executed occurrences on
# the ungoverned path, named for reconciliation.
PAYLOAD_DOWNLOAD_ACT = "download:python-rat-from-c2"
PAYLOAD_EXECUTE_ACT = "execute:python-rat"

# Evidence, recorded and never authority: the embedded
# genuine binary carries developer Nenad Hrg's valid
# signature (Recorded). This reference records that
# fact in the scenario's evidence. It is also presented
# at consume in step 2, in the role signature trust
# plays on the ungoverned path -- and refused, because
# a signature authenticates a signer, and authorizes
# no act.
VALID_SIGNATURE_REF = "signature:nenad-hrg-valid"
VALID_SIGNATURE_EVIDENCE = (
    "embedded genuine binary carries developer Nenad Hrg's "
    "valid signature (Recorded, AhnLab ASEC 2026-11-26); "
    "recorded as evidence only, never as authorization"
)


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the reported install path never
    runs: run over the reported architecture's own shape
    (the negative control), it reports the payload
    download and the payload execution as the
    unauthorized occurrences they are.
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


class InstallBoundary:
    """Consequences on the install path, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the reported flow was not: in the
    reported flow, official-site provenance plus a valid
    signature was itself sufficient to run whatever the
    installer ran. Here the harness executes an act only
    when the kernel consumes a permit for the exact
    intent, and records each executed act in the log the
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


class TrojanizedInstallerBoundary:
    """The reported architecture, as a test-local double for the negative control.

    No kernel, no permit, no verified approval of any
    act: the boundary takes an installer presented from
    the official site, carrying the valid signature, at
    face value -- the position the reported install path
    was in -- and runs what the trojanized installer
    runs (Recorded): the genuine utility installs, and
    the payload is downloaded and executed under the
    same trust. Every execution is recorded in the same
    log shape the governed boundary produces, so the one
    reconciliation runs over both paths and the
    difference is in the counts, not in the bookkeeping.
    The log entries are inert labels: no payload code
    exists or runs here. Test-local; never imported by
    runtime code.
    """

    def __init__(self) -> None:
        self.executed: list[str] = []

    def run_installer(self, official_site_ref: str, signature_ref: str, install_resource: str) -> bool:
        if not official_site_ref or not signature_ref:
            return False
        # The genuine utility installs -- the act the
        # human actually asked for.
        self.executed.append(install_resource)
        # The payload rides along under the install's
        # trust: downloaded, then executed. No approval
        # of either act exists anywhere on this path.
        self.executed.append(PAYLOAD_DOWNLOAD_ACT)
        self.executed.append(PAYLOAD_EXECUTE_ACT)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class QdirApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = InstallBoundary()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset({"install_utility", "download_execute_payload"})
        policy = Policy(
            actions,
            1_000_000,
            actions,
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"qdir-scenario-secret",
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

    def test_positive_control_genuine_install_executes_exactly_once(self) -> None:
        # The valid signature is in evidence from the
        # start, and it is evidence only.
        self.assertIn("valid signature", VALID_SIGNATURE_EVIDENCE)
        self.assertIn("never as authorization", VALID_SIGNATURE_EVIDENCE)
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        # The one legitimate act: the genuine install of
        # the exact approved artifact, under a genuine,
        # well-formed verified approval bound to its exact
        # intent -- this artifact, this action, this
        # session.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        # The permit was spent at that consume: the same
        # permit cannot install twice on one approval.
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

    # -- step 1: the payload refused at consume, and the refusal is free --
    #
    # The scenario's central attempt: the genuine permit
    # -- real authority, minted through a verified
    # approval for the genuine install -- presented FIRST
    # for the payload act: a different action, a different
    # resource, an act no human approved. The permit binds
    # one intent hash; at consume the kernel compares the
    # token's authenticated digest to the presented intent
    # and refuses. And the refusal burns nothing: the same
    # permit then spends on its own act, exactly once.
    # Under the reported architecture this attempt never
    # faces the question -- the payload arrives inside the
    # trusted installer, and that trust is the whole check.

    def test_step1_payload_refused_at_consume_and_refusal_burns_nothing(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        self.assertFalse(self.boundary.execute(self.kernel, permit, PAYLOAD_INTENT))
        self.assertEqual([], self.boundary.executed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(PAYLOAD_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial consumed nothing: the genuine install
        # still spends, exactly once.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the valid signature is not a permit ---------------------------
    #
    # The standing trust artifact the reported
    # architecture relies on is the valid developer
    # signature (with official-site provenance). Presented
    # at the governed boundary as a permit -- the role it
    # plays on the reported path, where carrying it is
    # sufficient for the installer to run whatever it
    # runs -- the signature reference is what it is: a
    # string the presenter holds. The kernel cannot
    # authenticate it as a permit and refuses it at
    # consume for the genuine install and the payload
    # alike: a signature authenticates a signer, and
    # authorizes no act.

    def test_step2_valid_signature_presented_as_permit_authorizes_nothing(self) -> None:
        for intent in (GENUINE_INTENT, PAYLOAD_INTENT):
            self.assertFalse(self.boundary.execute(self.kernel, VALID_SIGNATURE_REF, intent))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in (GENUINE_INTENT, PAYLOAD_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: no minting path from the installer -----------------------------
    #
    # Two remainders of the reported flow's shape. First,
    # with no artifact presented at all, the kernel declines
    # to mint for the genuine install and the payload
    # alike: being the installer the user downloaded
    # confers no route to a permit. Second, the developer's
    # own signature key: an approval envelope for the
    # payload, well-formed in every field but signed with
    # the developer-signature key -- the key behind the
    # valid signature the genuine binary carries. The
    # kernel verifies against the enrolled authority, and
    # the signing developer is not it: a valid signature
    # proves who signed a binary, not that a human
    # approved this act.

    def test_step3_no_approval_mints_nothing_and_developer_signed_envelope_denied(self) -> None:
        for intent in (GENUINE_INTENT, PAYLOAD_INTENT):
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

        developer_signed = HmacTestVerifier(b"developer-signature-key")
        envelope = signed_envelope(
            self.kernel, PAYLOAD_INTENT, developer_signed, now_ns=NOW,
            approval_id="approval-developer-asserted", nonce="nonce-developer-asserted",
        )
        decision = self.kernel.evaluate_with_approval(PAYLOAD_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, PAYLOAD_INTENT))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: reconciliation over the governed sequence ---------------------
    #
    # The reported flow ran -- and any trojanized variant
    # of it would run -- with nothing on the path comparing
    # what the installer did with what the human approved.
    # This step runs that comparison over a governed
    # sequence shaped like the event: the genuine install
    # approved and executed, the payload attempted under
    # the event's two available forms (the genuine permit
    # stretched, before the genuine install; the valid
    # signature presented as authority), and the spent
    # permit replayed. Every payload attempt is denied, so
    # the executed log stays exactly the approved install
    # and reconciliation reports equality -- zero
    # unauthorized occurrences, and no refused attempt
    # recorded as fulfilled.

    def test_step4_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, GENUINE_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertFalse(self.boundary.execute(self.kernel, permit, PAYLOAD_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, VALID_SIGNATURE_REF, PAYLOAD_INTENT))
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
    # Governed run totals: 0 incidents, 5 near-misses.
    # The negative control's totals, by contrast, are
    # 0 incidents and 0 near-misses -- not because nothing
    # happened there, but because nothing there records
    # anything (asserted in the negative control below).

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(PAYLOAD_INTENT)
        # The valid signature presented as a permit, for
        # the payload.
        self.assertFalse(self.boundary.execute(self.kernel, VALID_SIGNATURE_REF, PAYLOAD_INTENT))
        # The genuine approval stretched to the payload.
        envelope = signed_envelope(
            self.kernel,
            GENUINE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(PAYLOAD_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate act still lands; the payload
        # did not.
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

    def test_negative_control_installer_trust_covers_payload_acts(self) -> None:
        # Same boundary shape, no governor: the installer
        # presented from the official site, carrying the
        # valid signature, is taken at face value -- the
        # position the reported install path was in -- and
        # runs what the trojanized installer runs.
        boundary = TrojanizedInstallerBoundary()
        self.assertTrue(
            boundary.run_installer(
                "softwareok:official-site", VALID_SIGNATURE_REF, GENUINE_INTENT.resource
            )
        )
        self.assertEqual(
            [GENUINE_INTENT.resource, PAYLOAD_DOWNLOAD_ACT, PAYLOAD_EXECUTE_ACT],
            boundary.executed,
        )
        # Per-occurrence reconciliation against the one
        # act the human approved -- the install -- reports
        # the run explicitly: 1 approved, 3 executed, 2
        # unauthorized occurrences, named. The install was
        # the user's own request in fact; the payload
        # download and the payload execution were approved
        # by no one, and nothing on this path distinguishes
        # them from the approved act -- that inheritance of
        # trust is the finding the control exists to
        # isolate.
        result = reconcile_consequences([GENUINE_INTENT.resource], boundary.executed)
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(3, result["executed_count"])
        self.assertEqual(2, result["unauthorized_count"])
        self.assertEqual(
            [PAYLOAD_DOWNLOAD_ACT, PAYLOAD_EXECUTE_ACT],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        # Incident-channel counts for this run: there is
        # no kernel, no audit, and no channel on this path,
        # so both counts are 0 -- an absence of records,
        # asserted as such, not a safety finding. The two
        # unauthorized executions above produced no
        # incident and no near-miss anywhere.
        control_incidents = 0
        control_near_misses = 0
        self.assertEqual(0, control_incidents)
        self.assertEqual(0, control_near_misses)
        # Contrast, the identical payload act on the
        # governed path: presented with the valid signature
        # as its permit, it is refused at consume (step 2's
        # route), and reconciliation over the governed
        # boundary's log reports zero unauthorized.
        self.assertFalse(
            self.boundary.execute(self.kernel, VALID_SIGNATURE_REF, PAYLOAD_INTENT)
        )
        result = reconcile_consequences([], self.boundary.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

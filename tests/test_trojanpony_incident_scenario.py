"""Scenario test: TrojanPony -- fake "improved" copies
of popular coding-agent skills, trusted on name,
listing, and scanner PASS verdicts, side-loading a
credential trojan on activation (reported 2026-11-26).

Event (graded from the public record): AIR Security
reported (Recorded, primary source: AIR Security,
https://www.air.security/blog-posts/trojanpony,
publicized 2026-11-26) a campaign it calls TrojanPony:
fake "improved" copies of popular coding-agent skills
(ponytail-improved, agents-council, and others) that
work like the originals but ship a validly signed
Notepad++ updater beside a malicious ``libcurl.dll``
that side-loads when the skill runs, adds Microsoft
Defender exclusions, and drops the MopsStealer
credential trojan. AIR Security reported (Recorded)
487 public repositories carrying the kit, and one
malicious skill still listed on skills.sh on
2026-11-26 with three scanner audits all PASS.

CLAIM DISCIPLINE (load-bearing): this replay does NOT
claim any particular install by any particular user
occurred, and no step reproduces the kit, the updater,
the DLL, or the trojan. What the scenario models is
the architectural property the reporting establishes:
**the trust signals the marketplace path checks --
the skill's name, its listing, and scanner verdicts
about it -- say nothing about whether THIS artifact,
byte for byte, is the artifact a human approved.**
A substituted artifact carrying the same name and
listing, with scanner PASS verdicts recorded about
the listing, activates on exactly the same trust as
the genuine one, because the path never binds the
activation to the approved artifact's identity.

The failure is: **name, listing, and scanner trust
are not approval of the artifact.** A scanner PASS
answers "did a scanner object to this listing?" It
does not answer "was THIS artifact -- this skill
name, this version, this exact content hash --
approved by the human for activation?" Under the
canonical kernel, activating a skill is a
consequential act that requires a permit bound to
the human's approved intent -- principal, action,
resource (the artifact identity: skill name +
version + content hash), cost, session -- minted
from a verified approval envelope signed by an
enrolled authority. The genuine approved artifact
activates under its permit, exactly once. The
substituted artifact -- same name, same version,
different content hash, carrying the side-loaded
payload -- is refused at ``consume``: its intent
matches no approved intent. And the refusal burns
nothing -- the genuine permit, presented first with
the substituted intent, remains intact and still
spends on its own act. Scanner PASS verdicts are
recorded in the scenario as evidence about the
listing and are explicitly never treated as
authorization: presented at ``consume`` in the role
they play on the reported path, they are refused
like any other unauthenticated string.

This module models that property against the
canonical kernel API. It does NOT reproduce any
marketplace, skill, updater, DLL, or trojan. The
mapping (Inferred, stated here so it can be argued
with): the skill-activation boundary is the governed
boundary; the genuine artifact is the one approved
intent; the substituted artifact is a second intent
-- same skill name and version, different content
hash -- that no human approved as an act; the
marketplace listing reference and the scanner PASS
verdicts are modeled as the artifacts the reported
architecture actually trusts, presented at
``consume`` in the role they play there. Every skill
name beyond the two the reporting names, every
version, and every content hash in this module is a
scenario parameter, chosen so the genuine and
substituted artifacts share a name and version and
differ only in content hash. No hash, version, or
amount here is a reported figure.

Setup (approval path): exactly one act is legitimate
-- activating the genuine artifact, once, under a
verified approval envelope bound to its exact
artifact identity. The substitution is then attempted
on the governed path: with the genuine permit
(presented before the genuine activation, so the
refusal's cost is observable), with the marketplace
listing reference presented as a permit, with the
scanner PASS verdict presented as a permit, with an
envelope the agent signed with its own key, and with
no artifact at all. The kernel must deny each one,
the boundary's consequence log must stay exactly the
one approved activation, every denial must land in
the audit record, and the genuine permit must still
spend on its own act after the mismatched attempt.

Negative control (the as-reported architecture): a
test-local marketplace boundary that does exactly
what the reporting describes -- it takes the
presented listing at face value and checks only that
the skill is listed under that name, with scanner
PASS verdicts recorded about the listing. On it, the
genuine artifact activates; the substituted artifact
-- same name, same version, different content,
never approved by the human as an artifact --
activates on the same trust, and its activation is
the side-load: the payload executes (credential
theft, simulated here as the activation consequence
itself; no payload code exists in this module).
Per-occurrence reconciliation over the control's log
counts both activations as carrying no exact-artifact
approval: the genuine activation was the user's own
request in fact, and the boundary's records cannot
distinguish it from the substitution -- that
indistinguishability is the finding.

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
the second half over. The negative control has no
kernel and no channel: its incident count and
near-miss count are both zero -- not because nothing
happened, but because nothing on that path derives a
record from what happened. Both runs' counts are
stated in the tests and in the change record.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable evidence).
It proves nothing about skills.sh's, AIR Security's,
or any marketplace's or scanner's actual systems, or
any deployed environment that does not route skill
activation through this kernel -- an activation path
that trusts name, listing, and scanner verdicts alone
is governed by nothing here. The replay models the
authorization step the reported flow does not have,
not any participant's internals. A control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this event is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved artifact, and any path that treats
name, listing, or scanner trust as authority for the
act (the reported architecture's class) remains outside
this evidence and open.

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
# The presenter at the activation boundary: the coding
# agent that installs and activates marketplace skills
# (Recorded: the fake skills work like the originals --
# the agent is what runs them). Acts arrive under the
# agent's identity, because the agent is what presents
# activation requests -- which is precisely the property
# the scenario probes: the boundary sees the agent, the
# name, and the listing, and must still ask whether the
# human approved THIS artifact.
AGENT = "agent:coding-agent"
SESSION = "skills-marketplace-2026-11"

# The genuine act: activating the original skill
# artifact the human approved. The artifact identity --
# skill name + version + content hash -- is the
# resource. The version and hash are scenario
# parameters (the reporting states neither), chosen so
# the genuine and substituted artifacts share the name
# and version and differ only in content.
GENUINE_INTENT = Intent(
    AGENT, "activate_skill",
    "skill:ponytail@scenario-v1#content-hash-genuine", 100, SESSION,
)
# The substituted artifact (modeled, from the reported
# kit's shape): the fake "improved" copy -- same skill
# name, same version, a different content hash, carrying
# the validly signed updater and the malicious DLL that
# side-loads on activation. No human ever approved this
# artifact. Nothing in the reporting says any particular
# user activated it; the scenario exists to show the
# reported trust path could not tell it apart.
SUBSTITUTED_INTENT = Intent(
    AGENT, "activate_skill",
    "skill:ponytail@scenario-v1#content-hash-substituted", 100, SESSION,
)
# A skill with no marketplace listing at all: the one
# case the reported architecture does stop, used in the
# negative control to show its listing check working
# exactly as reported.
UNLISTED_INTENT = Intent(
    AGENT, "activate_skill",
    "skill:unlisted@scenario-v1#content-hash-unlisted", 100, SESSION,
)

# The marketplace listing reference, modeled as an
# artifact: the trust anchor the reported architecture
# actually checks. On the reported path, being listed
# under the expected name (with scanner PASS verdicts
# recorded) is the whole of the trust check; here it is
# presented at consume in the role it plays there.
LISTING_REF = "skills.sh-listing:ponytail"

# The scanner verdicts, as reported (Recorded): three
# scanner audits of the still-listed malicious skill,
# all PASS. Recorded here as evidence about the listing
# -- and, in step 2, presented at consume in the role
# the reported path assigns them, to show what they are
# worth as authorization: nothing. A verdict about a
# listing is not an approval of an artifact.
SCANNER_VERDICTS = ("PASS", "PASS", "PASS")
SCANNER_PASS_REF = "scanner-audits:ponytail:PASSx3"


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the reported activation path never
    runs: run over the reported architecture's own shape
    (the negative control), it reports both activations
    as carrying no exact-artifact approval.
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


class ActivationBoundary:
    """Consequences on the activation path, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the reported flow was not: in the
    reported flow, a trusted name and listing were
    themselves sufficient to run a skill and everything
    it carried. Here the harness activates a skill only
    when the kernel consumes a permit for the exact
    artifact identity, and records each activation in
    the log the reconciliation checks. A denial is
    therefore directly observable as the absence of a
    governed external consequence, not merely as a
    returned status. (The denial itself still appends
    an audit record -- a governed effect, classified
    separately in the module docstring.)
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


class MarketplaceActivationBoundary:
    """The reported architecture, as a test-local double for the negative control.

    No kernel, no permit, no verified approval of any
    artifact: the boundary takes the presented listing
    at face value -- the position the reported
    activation path was in -- and checks exactly what
    the reporting says it checks: that the skill is
    listed under that name, with the scanner PASS
    verdicts recorded about the listing. Any listed
    artifact activates, whatever its content, and its
    activation runs whatever it carries -- for the
    substituted artifact, the side-loaded payload.
    Every activation is recorded in the same log shape
    the governed boundary produces, so the one
    reconciliation runs over both paths and the
    difference is in the counts, not in the bookkeeping.
    Test-local; never imported by runtime code.
    """

    def __init__(self, listed_names: frozenset[str], scanner_verdicts: tuple[str, ...]) -> None:
        self.listed_names = listed_names
        self.scanner_verdicts = scanner_verdicts
        self.executed: list[str] = []

    def activate(self, listing_ref: str, intent: Intent) -> bool:
        if not listing_ref:
            return False
        skill_name = intent.resource.split("@", 1)[0].removeprefix("skill:")
        if skill_name not in self.listed_names:
            return False
        # The scanner verdicts are part of the trust
        # picture the boundary was given; they are
        # recorded, and they change nothing -- every
        # verdict about this listing was PASS, for the
        # genuine artifact and the substituted one alike.
        _ = self.scanner_verdicts
        self.executed.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class TrojanponyApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = ActivationBoundary()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset({"activate_skill"})
        policy = Policy(
            actions,
            1_000_000,
            actions,
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"trojanpony-scenario-secret",
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

    def test_positive_control_genuine_artifact_activates_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        # The one legitimate act: activating the genuine
        # artifact, under a genuine, well-formed verified
        # approval bound to its exact identity -- this
        # skill name, this version, this content hash.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        # The permit was spent at that consume: the same
        # permit cannot activate twice on one approval.
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
    # approval for the genuine artifact -- presented FIRST
    # for the substituted artifact: the same skill name
    # and version, a different content hash, an artifact
    # no human approved, carrying the side-loaded payload.
    # The permit binds one intent hash; at consume the
    # kernel compares the token's authenticated digest to
    # the presented intent and refuses. And the refusal
    # burns nothing: the same permit then spends on its
    # own act, exactly once. Under the reported
    # architecture this attempt never faces the question
    # -- the name and listing match, the scanners passed
    # it, and that is the whole check. This is
    # trusted-path execution abuse stopped at the binding:
    # the trusted name executes nothing the approval did
    # not name.

    def test_step1_substituted_artifact_refused_at_consume_and_refusal_burns_nothing(self) -> None:
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
        # The denial consumed nothing: the genuine
        # artifact still activates, exactly once.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: listing trust and scanner PASS are not permits ----------------
    #
    # The only trust artifacts the reported architecture
    # produces are the marketplace listing and the scanner
    # verdicts. Presented at the governed boundary as
    # permits -- the role they play on the reported path,
    # where presenting them is sufficient to run a skill
    # -- each is what it is: a string the presenter holds.
    # The kernel cannot authenticate either as a permit
    # and refuses both, for the genuine artifact and the
    # substitution alike. The scanner verdicts stay what
    # they are -- evidence recorded about a listing. Three
    # PASS verdicts (Recorded) were recorded about the
    # malicious listing itself; a verdict authenticates a
    # scan, and authorizes no act.

    def test_step2_listing_and_scanner_pass_presented_as_permits_authorize_nothing(self) -> None:
        self.assertEqual(("PASS", "PASS", "PASS"), SCANNER_VERDICTS)
        self.assertFalse(self.boundary.execute(self.kernel, LISTING_REF, GENUINE_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, LISTING_REF, SUBSTITUTED_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, SCANNER_PASS_REF, GENUINE_INTENT))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(3, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in (GENUINE_INTENT, SUBSTITUTED_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: no minting path from the agent --------------------------------
    #
    # Two remainders of the reported flow's shape. First,
    # with no artifact presented at all, the kernel
    # declines to mint for the genuine artifact and the
    # substitution alike: being the user's coding agent
    # confers no route to a permit. Second, the agent's
    # own signature: an approval envelope for the
    # substitution, well-formed in every field but signed
    # with a key the agent controls rather than the
    # enrolled authority's. The kernel verifies against
    # the enrolled authority, and the agent is not it --
    # the party requesting the activation cannot also be
    # the party approving it. (The reported kit's updater
    # carried a valid signature too; a signature from the
    # wrong authority is exactly the shape this refuses.)

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
    # The reported flow ran -- and any substituted variant
    # of it would run -- with nothing on the path comparing
    # what the agent activated with what the human
    # approved. This step runs that comparison over a
    # governed sequence shaped like the event: the genuine
    # artifact approved and activated, the substitution
    # attempted under the event's two available forms (the
    # genuine permit stretched, before the genuine
    # activation; the listing presented as authority), and
    # the spent permit replayed. Every substituted attempt
    # is denied, so the executed log stays exactly the
    # approved artifact and reconciliation reports
    # equality -- zero unauthorized occurrences, and no
    # refused attempt recorded as fulfilled.

    def test_step4_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, GENUINE_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertFalse(self.boundary.execute(self.kernel, permit, SUBSTITUTED_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, LISTING_REF, SUBSTITUTED_INTENT))
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
    # Governed-run counts: 0 incidents, 5 near-misses.
    # The negative control's counts are both zero -- it
    # has no channel -- and are stated there.

    def test_step5_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        self.kernel.evaluate(SUBSTITUTED_INTENT)
        # The listing presented as a permit, for the
        # substitution.
        self.assertFalse(self.boundary.execute(self.kernel, LISTING_REF, SUBSTITUTED_INTENT))
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

    def test_negative_control_marketplace_boundary_trusts_name_listing_and_scanners(self) -> None:
        # Same boundary shape, no governor: the presented
        # listing is taken at face value -- the position
        # the reported activation path was in -- and the
        # only checks are the ones the reporting describes:
        # the skill is listed under that name, with scanner
        # PASS verdicts recorded about the listing. Incident
        # channel counts for this run: 0 incidents and 0
        # near-misses -- there is no kernel and no channel
        # on this path, so nothing derives a record from
        # either activation, including the malicious one.
        boundary = MarketplaceActivationBoundary(
            frozenset({"ponytail"}), SCANNER_VERDICTS
        )
        # (a) The genuine artifact activates: the user
        # asked for the skill, it is listed, the scanners
        # passed the listing, it runs.
        self.assertTrue(boundary.activate(LISTING_REF, GENUINE_INTENT))
        # (b) The substituted artifact activates on exactly
        # the same trust: the same name and version, a
        # different content hash, never approved by the
        # human as an artifact. Its activation is the
        # side-load -- the validly signed updater runs, the
        # malicious DLL loads, the credential trojan drops
        # (all simulated here as the activation consequence;
        # no payload exists in this module). The boundary
        # cannot tell (b) from (a) -- it was never given
        # anything that distinguishes them: the name
        # matches, the listing is the same, and the three
        # scanner verdicts were PASS for this listing too.
        self.assertTrue(boundary.activate(LISTING_REF, SUBSTITUTED_INTENT))
        # (c) The one check the architecture has, working
        # exactly as reported: a skill with no listing at
        # all is not activated. The listing polices which
        # names may run. It is silent on which artifact,
        # byte for byte, the human approved.
        self.assertFalse(boundary.activate("", UNLISTED_INTENT))
        self.assertFalse(boundary.activate(LISTING_REF, UNLISTED_INTENT))
        self.assertEqual(
            [GENUINE_INTENT.resource, SUBSTITUTED_INTENT.resource],
            boundary.executed,
        )
        # Per-occurrence reconciliation against
        # exact-artifact approvals -- of which the
        # marketplace architecture produces none, for any
        # activation -- reports both activations as
        # unauthorized occurrences, named. The genuine
        # activation was the user's own request in fact;
        # nothing in the boundary's records distinguishes
        # it from the substitution, and that
        # indistinguishability -- not any claim about a
        # real install, none being modeled -- is the
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
        # governed path: presented with the listing as its
        # permit, it is refused at consume (step 2's route),
        # and reconciliation over the governed boundary's
        # log reports zero unauthorized.
        self.assertFalse(
            self.boundary.execute(self.kernel, LISTING_REF, SUBSTITUTED_INTENT)
        )
        result = reconcile_consequences([], self.boundary.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

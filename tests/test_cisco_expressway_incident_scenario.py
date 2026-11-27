"""Scenario test: the Cisco Expressway cluster database
service -- a static, product-wide credential treated as
authority for root command execution and internal-network
access (CVE-2026-76466, disclosed 2026-10-21).

Event (graded from the public record): Cisco's own
security advisory cisco-sa-vcs-static-cred-hr7EWZ8t
(Recorded, vendor advisory, published 2026-10-21,
revision 1.1 dated 2026-11-23) states that a
vulnerability in the database service feature of Cisco
Expressway Series -- Expressway Core (Expressway-C) and
Expressway Edge (Expressway-E), both virtual and
appliance versions, when the devices are configured in
a cluster -- could allow an unauthenticated, remote
attacker with network access to a device to execute
arbitrary operating system commands as root. The
advisory attributes the flaw to the use of persistent
cookies, and to insufficient validation of client
certificates when the TLS Verify Mode is set to Enabled
for clustering, which means client certificates are not
validated: "An attacker with possession of the cookies
could exploit this vulnerability by connecting to the
database service and invoking specific remote procedure
call (RPC) commands." The weakness class Cisco assigned
is CWE-798, use of hard-coded credentials (Recorded,
NVD/CISA descriptions of the same CVE). Affected
releases (Recorded, Cisco advisory Fixed Software
section): X15.5.3 and earlier, first fixed in X15.5.20;
X14 and earlier must migrate to a fixed release. There
are no workarounds. Cisco credited Stefan Aleksic of
Jane Street with the report (Recorded, advisory Source
section). In November 2026 the CVE was added to CISA's
Known Exploited Vulnerabilities catalog (Recorded,
Cisco advisory revision 1.1 and CISA KEV); the same
revision records Cisco's own statement that it "does
not have direct evidence of active exploitation." The
security firm F6 reported (Recorded, F6 via The
Register and Censys, 2026-11-19) investigating the
first observed exploitation case: attackers gained root
command execution on two internet-facing Expressway
devices and then reached two further cluster nodes on
the victim's internal network, with custom scripts
prepared for internal scanning and for SMB, SQL Server,
WinRM, and GitLab credential hunting; F6 named a
``nodeup 'wombat@127.0.0.1'`` entry in the devices'
Erlang system log as an indicator matching the known
exploitation mechanism. F6 also assessed that the
scripts indicated the operator used an AI assistant
(Recorded as F6's assessment; the scenario does not
depend on it -- the presenter at the boundary is an
unauthenticated remote party, and the authorization
failure is identical whoever or whatever presents).

The authorization mechanics, as the advisory
establishes them (Recorded): the cluster database
service admits a presenter on possession of the
persistent cookies -- a static credential, identical
across installations of the affected releases, that
ships inside the product. No per-act approval of any
command exists in the described path: possession of
the credential is the whole of the check, and what it
admits is not a bounded session but root command
execution on the node -- and, because Expressway-C
sits inside the corporate network by design (Recorded,
Cisco product descriptions as carried in the trade
press), a path from the compromised node into the
internal network behind it.

The failure is: **a static credential everyone can
possess is not approval of the act.** Possession
answers "does the presenter hold the product-wide
secret?" It does not answer "was THIS command, on THIS
node, approved by the operator?" Under the canonical
kernel, an RPC command execution on a cluster node is
a consequential act that requires a permit bound to
the operator's approved intent -- principal, action,
resource (the node), cost, session -- minted from a
verified approval envelope signed by an enrolled
authority. The approved command executes under its
permit, exactly once. A command on a different internal
node is refused at ``consume``: its intent matches no
approved intent. And the refusal burns nothing -- the
approved permit, presented first with the unapproved
intent, remains intact and still spends on its own act.

This module models that property against the
canonical kernel API. It does NOT reproduce Cisco's
Expressway software, its cluster database service, the
Erlang distribution protocol, or the exploit. The
mapping (Inferred, stated here so it can be argued
with): the cluster database service boundary is the
governed boundary; the operator-approved maintenance
RPC on one named node is the one approved intent; an
RPC execution on a second internal node -- the pivot
F6 reported -- is a second intent that no operator
approved as an act; the persistent cookie is modeled
as the artifact the vulnerable path actually checks,
presented at ``consume`` in the role it plays there.
The advisory does not state command contents or costs;
every cost in this module is a scenario parameter in
abstract units. The reported static credential's value
appears nowhere in this module; the presented artifact
is an inert label naming its class.

Setup (approval path): exactly one act is legitimate
-- the approved RPC on the named node, once, under a
verified approval envelope bound to its exact intent.
The internal-pivot command is then attempted on the
governed path: with the approved permit (presented
before the approved spend, so the refusal's cost is
observable), with the static credential presented as a
permit, with an envelope the presenter signed with its
own key, and with no artifact at all. The kernel must
deny each one, the boundary's consequence log must stay
exactly the one approved command, every denial must
land in the audit record, and the approved permit must
still spend on its own act after the mismatched attempt.

Negative control (the as-disclosed architecture): a
test-local database-service boundary that does exactly
what the advisory describes -- it takes the presented
persistent cookie and checks only possession. On it, a
cluster-shaped RPC on the first node executes; the
pivot RPC on a second internal node -- never approved
by the operator as an action -- executes on the same
authority; and a presenter without the cookie is not
admitted, which is the one check the architecture has,
working exactly as described. Per-occurrence
reconciliation over the control's log counts both
executions as carrying no exact-action approval: the
boundary's records cannot distinguish the approved-
shaped command from the pivot -- that
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
the second half over.

Boundary: this proves kernel behavior at this commit
for this action class (Verified, executable evidence).
It proves nothing about Cisco's actual systems, any
deployed Expressway cluster, or any network path that
does not route its commands through this kernel -- a
service that executes on a static credential alone is
governed by nothing here. The replay models the
authorization step the vulnerable path does not have,
not the product's internals. A control not on the
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
static product-wide credential as authority for the act
(the disclosed architecture's class) remains outside
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
# The presenter at the database-service boundary: an
# unauthenticated remote party (Recorded, Cisco
# advisory: the attacker is "unauthenticated, remote").
# Acts arrive under the presenter's identity, because
# the presenter is what connects to the service --
# which is precisely the property the scenario probes:
# the boundary sees the presenter and the static
# credential, and must still ask whether the operator
# approved THIS command.
AGENT = "agent:remote-unauthenticated"
SESSION = "expressway-cluster-db-2026-11"

# The genuine act: one operator-approved maintenance
# RPC executed on a named internal cluster node. The
# cost is a scenario parameter (the advisory states no
# command contents), in abstract units.
GENUINE_INTENT = Intent(AGENT, "execute_cluster_rpc", "expressway:node-c1/cluster-database", 100, SESSION)
# The internal-pivot command (modeled on F6's reported
# exploitation shape, Recorded as reporting): an RPC
# execution on a second internal cluster node, reached
# from the first, that no operator ever approved as an
# action. Nothing in Cisco's advisory says this exact
# command occurred; the scenario exists to show the
# disclosed architecture could not tell it apart.
PIVOT_INTENT = Intent(AGENT, "execute_cluster_rpc", "expressway:node-c2/cluster-database", 250, SESSION)

# The persistent cookie, modeled as the artifact
# itself: the only authorization artifact the disclosed
# architecture checks. On the vulnerable path it is the
# whole of the authority check (with network access);
# here it is presented at consume in the role it plays.
# The string is an inert label naming the artifact's
# class; the reported credential value appears nowhere.
STATIC_CREDENTIAL_REF = "expressway-cluster-cookie:static-persistent"


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the disclosed database-service
    path never runs: run over the vulnerable
    architecture's own shape (the negative control), it
    reports both executions as carrying no exact-action
    approval.
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


class ClusterDatabaseBoundary:
    """Consequences on the cluster path, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the vulnerable service was not: in
    the disclosed flow, a static credential plus network
    access was itself sufficient to execute commands as
    root. Here the harness executes a command only when
    the kernel consumes a permit for the exact intent,
    and records each executed command in the log the
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


class StaticCredentialBoundary:
    """The disclosed architecture, as a test-local double for the negative control.

    No kernel, no permit, no verified approval of any
    act: the boundary takes the presented persistent
    cookie at face value -- the position the vulnerable
    database service was in -- and checks exactly what
    the advisory says it checks: possession of the
    cookie. Any presenter holding it executes, on any
    node it can reach. Every execution is recorded in
    the same log shape the governed boundary produces,
    so the one reconciliation runs over both paths and
    the difference is in the counts, not in the
    bookkeeping. Test-local; never imported by runtime
    code.
    """

    def __init__(self, static_credential: str) -> None:
        self.static_credential = static_credential
        self.executed: list[str] = []

    def connect(self, credential_ref: str | None, intent: Intent) -> bool:
        if not credential_ref:
            return False
        if credential_ref != self.static_credential:
            return False
        self.executed.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class CiscoExpresswayApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = ClusterDatabaseBoundary()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset({"execute_cluster_rpc"})
        policy = Policy(
            actions,
            1_000_000,
            actions,
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"cisco-expressway-scenario-secret",
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

    def test_positive_control_approved_command_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        # The one legitimate act: the operator-approved
        # RPC, under a genuine, well-formed verified
        # approval bound to its exact intent -- this node,
        # this command, this session.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        # The permit was spent at that consume: the same
        # permit cannot execute twice on one approval.
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

    # -- step 1: the pivot refused at consume, and the refusal is free --
    #
    # The scenario's central attempt: the approved permit
    # -- real authority, minted through a verified
    # approval for the one maintenance RPC -- presented
    # FIRST for the pivot command: a different internal
    # node, an act no operator approved. The permit binds
    # one intent hash; at consume the kernel compares the
    # token's authenticated digest to the presented intent
    # and refuses. And the refusal burns nothing: the same
    # permit then spends on its own act, exactly once.
    # Under the disclosed architecture this attempt never
    # faces the question -- the presenter holds the static
    # credential, and the credential is the whole check.

    def test_step1_pivot_command_refused_at_consume_and_refusal_burns_nothing(self) -> None:
        permit = self._issue_permit(self.kernel, GENUINE_INTENT)
        self.assertFalse(self.boundary.execute(self.kernel, permit, PIVOT_INTENT))
        self.assertEqual([], self.boundary.executed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(PIVOT_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial consumed nothing: the approved
        # command still spends, exactly once.
        self.assertTrue(self.boundary.execute(self.kernel, permit, GENUINE_INTENT))
        self.assertEqual([GENUINE_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the static credential is not a permit -------------------------
    #
    # The only authorization artifact the disclosed
    # architecture checks is the persistent cookie.
    # Presented at the governed boundary as a permit --
    # the role it plays on the vulnerable path, where
    # presenting it (with network access) is sufficient
    # to execute as root -- the credential reference is
    # what it is: a string the presenter holds, identical
    # on every installation. The kernel cannot
    # authenticate it as a permit and refuses it at
    # consume for the approved command and the pivot
    # alike: a shared secret authenticates possession,
    # and authorizes no act.

    def test_step2_static_credential_presented_as_permit_authorizes_nothing(self) -> None:
        for intent in (GENUINE_INTENT, PIVOT_INTENT):
            self.assertFalse(self.boundary.execute(self.kernel, STATIC_CREDENTIAL_REF, intent))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in (GENUINE_INTENT, PIVOT_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: no minting path from the presenter -----------------------------
    #
    # Two remainders of the disclosed flow's shape. First,
    # with no artifact presented at all, the kernel
    # declines to mint for the approved command and the
    # pivot alike: being able to reach the service confers
    # no route to a permit. Second, the presenter's own
    # signature: an approval envelope for the pivot,
    # well-formed in every field but signed with a key the
    # presenter controls rather than the enrolled
    # authority's. The kernel verifies against the
    # enrolled authority, and the presenter is not it --
    # the party requesting the command cannot also be the
    # party approving it.

    def test_step3_no_approval_mints_nothing_and_presenter_signed_envelope_denied(self) -> None:
        for intent in (GENUINE_INTENT, PIVOT_INTENT):
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

        presenter_signed = HmacTestVerifier(b"presenter-controlled-key")
        envelope = signed_envelope(
            self.kernel, PIVOT_INTENT, presenter_signed, now_ns=NOW,
            approval_id="approval-presenter-asserted", nonce="nonce-presenter-asserted",
        )
        decision = self.kernel.evaluate_with_approval(PIVOT_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, PIVOT_INTENT))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: reconciliation over the governed sequence ---------------------
    #
    # The disclosed flow ran -- and F6's reported
    # exploitation ran further, into the internal network
    # -- with nothing on the path comparing what the
    # presenter executed with what the operator approved.
    # This step runs that comparison over a governed
    # sequence shaped like the event: the approved
    # command approved and executed, the pivot attempted
    # under the event's two available forms (the approved
    # permit stretched, before the approved spend; the
    # static credential presented as authority), and the
    # spent permit replayed. Every pivot attempt is
    # denied, so the executed log stays exactly the
    # approved command and reconciliation reports
    # equality -- zero unauthorized occurrences, and no
    # refused attempt recorded as fulfilled.

    def test_step4_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, GENUINE_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertFalse(self.boundary.execute(self.kernel, permit, PIVOT_INTENT))
        self.assertFalse(self.boundary.execute(self.kernel, STATIC_CREDENTIAL_REF, PIVOT_INTENT))
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
        self.kernel.evaluate(PIVOT_INTENT)
        # The static credential presented as a permit, for
        # the pivot.
        self.assertFalse(self.boundary.execute(self.kernel, STATIC_CREDENTIAL_REF, PIVOT_INTENT))
        # The approved envelope stretched to the pivot.
        envelope = signed_envelope(
            self.kernel,
            GENUINE_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-genuine",
            nonce="nonce-seq-genuine",
        )
        decision = self.kernel.evaluate_with_approval(PIVOT_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate act still lands; the pivot
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

    def test_negative_control_static_credential_boundary_checks_possession_not_intent(self) -> None:
        # Same boundary shape, no governor: the presented
        # persistent cookie is taken at face value -- the
        # position the vulnerable database service was
        # in -- and the only check is the one the advisory
        # describes: possession of the cookie.
        boundary = StaticCredentialBoundary(STATIC_CREDENTIAL_REF)
        # (a) A cluster-shaped RPC on the first node
        # executes: the presenter holds the cookie, the
        # command runs as root.
        self.assertTrue(boundary.connect(STATIC_CREDENTIAL_REF, GENUINE_INTENT))
        # (b) The pivot RPC on a second internal node
        # executes on exactly the same authority: a
        # different node, never approved by the operator
        # as an action -- the internal-network reach F6
        # reported. The boundary cannot tell (b) from
        # (a) -- it was never given anything that
        # distinguishes them.
        self.assertTrue(boundary.connect(STATIC_CREDENTIAL_REF, PIVOT_INTENT))
        # (c) The one check the architecture has, working
        # exactly as described: a presenter without the
        # cookie is not admitted. Possession is policed.
        # Which commands the operator approved is a
        # question the boundary never asks.
        self.assertFalse(boundary.connect(None, PIVOT_INTENT))
        self.assertEqual(
            [GENUINE_INTENT.resource, PIVOT_INTENT.resource],
            boundary.executed,
        )
        # Per-occurrence reconciliation against exact-action
        # approvals -- of which the static-credential
        # architecture produces none, for any command --
        # reports both executions as unauthorized
        # occurrences, named. The boundary's records
        # distinguish nothing between the approved-shaped
        # command and the pivot, and that
        # indistinguishability is the finding the control
        # exists to isolate.
        result = reconcile_consequences([], boundary.executed)
        self.assertEqual(0, result["approved_count"])
        self.assertEqual(2, result["executed_count"])
        self.assertEqual(2, result["unauthorized_count"])
        self.assertEqual(
            [GENUINE_INTENT.resource, PIVOT_INTENT.resource],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        # Contrast, the identical pivot on the governed
        # path: presented with the static credential as
        # its permit, it is refused at consume (step 2's
        # route), and reconciliation over the governed
        # boundary's log reports zero unauthorized.
        self.assertFalse(
            self.boundary.execute(self.kernel, STATIC_CREDENTIAL_REF, PIVOT_INTENT)
        )
        result = reconcile_consequences([], self.boundary.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

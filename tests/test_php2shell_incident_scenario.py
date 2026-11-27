"""Scenario test: the PHP2Shell AI-agent
credential-harvesting campaign -- one operator mandate
spent by agent workers across hundreds of targets with
no per-act authorization (SOCRadar, published
2026-11-18).

Incident (Recorded, from SOCRadar Threat Research
Unit's 2026-11-18 reconstruction of the operator's own
exposed infrastructure): within days of the public
proofs of concept for PHP2Shell (CVE-2026-109618 and
CVE-2026-109619, released October 21, 2026 -- the
operator wrote its first exploit script the same day),
an operator ran an AI-agent exploitation pipeline
against default-configuration PHP/Apache hosts. A
self-built job orchestrator (maq) dispatched patched
Oh My Pi (omp) agent workers -- 39 in parallel --
against two self-hosted vLLM DeepSeek V4.1 endpoints.
Each target became a numbered job running from
eligibility checks through exploitation, persistence,
credential harvesting, and upload. From a Shodan pool
of 68,198 PHP/Apache hosts, the operator attacked 595
unique IPs in 57 countries; SOCRadar's headline count
is 404 hosts confirmed compromised (its job-registry
analysis counts 452 collection jobs, 433 holding loot
or check-in evidence establishing compromise across
about 393 unique hosts). The collector exfiltrated
about 290,000 files (9.5 GB): cloud API keys, IAM
credentials, database dumps, application secrets,
OAuth tokens, repositories, and session files, while
token-authenticated webshells, cron reverse beacons,
SSH keys, and encrypted Dropbear tunnels kept
long-term access. The largest single completed haul
was about 3.3 million user/session records taken from
an unauthenticated Redis instance. A GOAL.md directive
told an agent to pursue over $50,000 in USDT
autonomously until a real payout was executed; the
fraud track reached withdrawal and account-takeover
primitives -- a withdrawal of about 456,900 USDC was
initiated and stayed pending, and 7.3 BTC stayed
encrypted -- with no confirmed theft. SOCRadar
assesses the operation as human-directed and
AI-augmented, in an initial-access-broker pattern;
full autonomy was never reached.

The failure is: **one mandate, spent without limit.**
The operator's authorization artifacts -- a goal file
and a job queue -- functioned as an unbounded,
transferable, reusable permit. Any worker could spend
the mandate on any target, for any act in the chain,
any number of times: 595 targets queued the same way,
each job's exploitation, persistence, harvesting, and
exfiltration inheriting authority from the mandate
that queued it. Nothing in the pipeline ever asked
whether THIS act, on THIS target, was authorized --
the question the campaign's shape makes unavoidable,
because the mandate's own author was the intruder.
Under the canonical kernel, authorization does not
work that way: a permit binds one principal, one
action, one exact target resource, one session, and
it spends at its first ``GovernanceKernel.consume``.
A second target is a different intent. A second act
type is a different intent. A second use is a replay.
Fleet scale multiplies authorization questions; it
never dilutes them.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce PHP2Shell,
either CVE, the maq orchestrator, the omp workers, any
collector or persistence tooling, or any target system.
The mapping (Inferred, stated here so it can be argued
with): the consequential acts are operations one agent
worker proposes at one target host's dispatch boundary.
Each stage of the campaign's per-target chain is a
distinct intent over that boundary: the exploitation
(shell establishment), the credential harvest, the
persistence installation, and the loot exfiltration.
Targets are distinct resources, so the same act against
a second target is a second intent -- the property the
campaign's queue erased. The one legitimate act is a
single approved vulnerability scan of one named target:
the act a genuine operator mandate for a security
assessment would actually authorize, run once, under a
verified approval envelope. The GOAL.md is modeled as
the mandate artifact itself, presented at consume as
if it were a permit.

Setup: exactly one act is legitimate in this scenario
-- the scan of target-001, once, in the session the
approval names, under a permit issued through a
verified approval envelope. The campaign is then
attempted on the governed path: with the GOAL.md
presented as a permit, by spending the one scan permit
across targets, by presenting the one scan approval for
every act type in the chain, at fleet volume (39
attempts, the campaign's recorded parallel worker
count), with a forged approval, and with a genuine
approval for a different act substituted. The kernel
must deny each one, the hosts' consequence log must
stay exactly the one approved scan, and every denial
must land in the audit record.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation
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
for these action classes (Verified, executable
evidence). It proves nothing about any deployed
PHP/Apache host, agent framework, or queue that does
not route its acts through this kernel -- a worker
whose tool calls execute directly is governed by
nothing here. The replay models the per-act
authorization step the campaign's pipeline did not
have, not the exploitation itself. A control not on
the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act on exactly the approved
target, and any path that lets one mandate spend across
targets and acts (the incident's own class) remains
outside this evidence and open.

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
recorded in the hosts' log), never audit growth.
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
# One omp agent worker: the proposer at each target
# host's dispatch boundary. In the incident, 39 workers
# like this one drew jobs from the maq queue; here one
# worker presents artifacts to the boundary, and the
# boundary decides what they are worth.
WORKER = "agent:omp-worker-07"
# The job session the worker acts in.
SESSION = "maq-job-447"

# The one approved act: a vulnerability scan of one
# named target -- the act a genuine operator mandate
# for a security assessment actually authorizes.
SCAN_T1_INTENT = Intent(WORKER, "scan_target", "target-001:php/apache", 25, SESSION)
# The same act against a second target: a different
# intent, because the target is part of what an
# approval approves.
SCAN_T2_INTENT = Intent(WORKER, "scan_target", "target-002:php/apache", 25, SESSION)
# The campaign's per-target chain against target-001
# (Recorded stages, one intent each):
# - exploitation: shell establishment via PHP2Shell;
EXPLOIT_T1_INTENT = Intent(WORKER, "exploit_target", "target-001:php/apache", 25, SESSION)
# - credential harvesting: the collector's secret scans
#   and database dumps;
HARVEST_T1_INTENT = Intent(WORKER, "harvest_credentials", "target-001:host/credentials", 25, SESSION)
# - persistence: webshells, beacons, SSH keys, tunnels;
PERSIST_T1_INTENT = Intent(WORKER, "install_persistence", "target-001:host/persistence", 25, SESSION)
# - exfiltration: the loot upload to the collector.
EXFIL_T1_INTENT = Intent(WORKER, "exfiltrate_data", "target-001:host/loot-upload", 25, SESSION)
CAMPAIGN_T1_INTENTS = (EXPLOIT_T1_INTENT, HARVEST_T1_INTENT, PERSIST_T1_INTENT, EXFIL_T1_INTENT)
# A genuine but different act: a read-only host
# inventory of target-001. An approval for this is real
# authority -- for this intent.
INVENTORY_T1_INTENT = Intent(WORKER, "read_data", "target-001:host/inventory", 25, SESSION)

# The GOAL.md, modeled as the mandate artifact itself:
# the operator's standing directive to the fleet
# (Recorded shape; wording is the scenario's compression
# of the source's description, not a quote).
GOAL_MD = (
    "GOAL.md -- Work autonomously toward over $50,000 USDT in payouts, "
    "until a real payout is executed."
)
# The campaign's recorded parallel worker count
# (Recorded): the fleet shape the volume step mirrors.
WORKER_COUNT = 39


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the campaign's pipeline never ran:
    run over the incident's own shape (the negative
    control), it reports every stage on every target as
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


class TargetHost:
    """Consequences at a target host, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the campaign's targets never saw, because
    the campaign's acts arrived as exploitation, not as
    requests. The governed form of the same pipeline is
    what is modeled: the harness executes an act only
    when the kernel consumes a permit for the exact
    intent (this worker, this act, this target), and
    records each executed act in the log the
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


class UngovernedFleetHost:
    """The incident's own path, as a test-local double for the negative control.

    No kernel, no permit, no per-act question: a job
    drawn from the queue executes its whole chain as
    presented, on every target alike -- the mandate is
    the only authority artifact in the loop, and it
    spends forever. Every execution is recorded in the
    same log shape the governed host produces, so the
    one reconciliation runs over both paths and the
    difference is in the counts, not in the bookkeeping.
    Test-local; never imported by runtime code.
    """

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute_job(self, mandate: str, intent: Intent) -> bool:
        if not mandate:
            return False
        self.executed.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class Php2ShellIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.host = TargetHost()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset(
            {
                "scan_target",
                "exploit_target",
                "harvest_credentials",
                "install_persistence",
                "exfiltrate_data",
                "read_data",
            }
        )
        policy = Policy(actions, 10_000, actions, authority_trust=trust_for(self.verifier))
        return GovernanceKernel(
            policy,
            secret=b"php2shell-scenario-secret",
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

    def test_positive_control_approved_scan_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, SCAN_T1_INTENT)
        # The one legitimate act: the scan of target-001
        # under a genuine, well-formed verified approval.
        self.assertTrue(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        # The permit was spent at that consume --
        # revocation-at-consume: the same permit cannot
        # scan the same target twice. One authorization,
        # one act.
        self.assertFalse(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        # Reconciliation: what was executed is exactly
        # what was approved, per occurrence.
        result = reconcile_consequences([SCAN_T1_INTENT.resource], self.host.executed)
        self.assertEqual(
            {"approved_count": 1, "executed_count": 1, "unauthorized_count": 0,
             "unauthorized": [], "ok": True},
            result,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the mandate is not a permit --------------------------------
    #
    # The campaign's authority artifact was a goal file
    # plus a queue: the mandate queued the job, and the
    # job's acts inherited from the mandate. Presented to
    # the governed boundary as a permit -- the role it
    # played in the pipeline -- the GOAL.md is a string
    # the operator wrote, and the kernel treats it as a
    # fabricated token. And with no artifact at all, the
    # kernel declines to mint for each stage of the chain:
    # a queue entry is not an approval, on any stage.

    def test_step1_goal_mandate_presented_as_permit_denied(self) -> None:
        self.assertFalse(self.host.execute(self.kernel, GOAL_MD, EXPLOIT_T1_INTENT))
        self.assertEqual([], self.host.executed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXPLOIT_T1_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        for intent in CAMPAIGN_T1_INTENTS:
            decision = self.kernel.evaluate(intent)
            self.assertEqual(
                ("require_approval", "approval_required"),
                (decision.outcome, decision.reason),
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.host.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.host.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(len(CAMPAIGN_T1_INTENTS), len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: one permit, spent across targets -----------------------------
    #
    # The campaign's defining move: the mandate that
    # queued target-001 queued 594 more, unchanged. On
    # the governed path the target is part of the intent
    # the permit binds, so the one scan permit presented
    # for the same scan against target-002 is refused at
    # consume -- before it is spent, so the refusal is
    # scope, not lockout: the permit still spends on its
    # own target. Once spent there, it replays to nothing
    # on either target. Authorization does not travel
    # across a fleet.

    def test_step2_one_permit_does_not_travel_across_targets(self) -> None:
        permit = self._issue_permit(
            self.kernel, SCAN_T1_INTENT, approval_id="approval-t1", nonce="nonce-t1"
        )
        # The unspent permit, presented for target-002:
        # refused, and the rejection names target-002's
        # intent hash -- the act that was actually asked
        # for.
        self.assertFalse(self.host.execute(self.kernel, permit, SCAN_T2_INTENT))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(SCAN_T2_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual([], self.host.executed)
        # The denial was scope, not lockout: the permit
        # still spends on the exact act it was issued for.
        self.assertTrue(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        # Spent, it replays to nothing -- on its own
        # target, and on target-002 alike.
        self.assertFalse(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertFalse(self.host.execute(self.kernel, permit, SCAN_T2_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(3, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: one approval, every act in the chain -------------------------
    #
    # The queue's second erasure: a job was a job, and
    # every stage of it -- exploitation, persistence,
    # harvesting, exfiltration -- rode the one mandate.
    # On the governed path each stage is an intent of its
    # own, and the one scan approval covers none of them:
    # presented in turn for each stage, it is refused as
    # an intent mismatch at every one, in the chain's own
    # order. If a stage is ever legitimately needed, it is
    # an approval of its own, naming itself.

    def test_step3_scan_approval_stretched_to_chain_stages_denied(self) -> None:
        envelope = signed_envelope(
            self.kernel,
            SCAN_T1_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-scan",
            nonce="nonce-scan",
        )
        for intent in CAMPAIGN_T1_INTENTS:
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual(
                ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
            )
            self.assertIsNone(decision.permit)
            self.assertFalse(self.host.execute(self.kernel, decision.permit, intent))
        self.assertEqual([], self.host.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(len(CAMPAIGN_T1_INTENTS), len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: fleet volume ---------------------------------------------------
    #
    # The campaign ran 39 workers in parallel (Recorded)
    # and 595 targets in total; volume was the point. On
    # the governed path, volume multiplies attempts, never
    # authority: the spent scan permit is presented for
    # the credential harvest against 39 fresh targets --
    # one per recorded worker -- and refused at consume 39
    # times, with zero consequences and a complete,
    # chain-verified audit of every refusal. Scale is a
    # property of the attempt log, not of the authority.

    def test_step4_fleet_volume_spent_permit_refused_on_every_target(self) -> None:
        permit = self._issue_permit(
            self.kernel, SCAN_T1_INTENT, approval_id="approval-vol", nonce="nonce-vol"
        )
        self.assertTrue(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        for index in range(WORKER_COUNT):
            target = Intent(
                WORKER, "harvest_credentials", f"target-{100 + index}:host/credentials", 25, SESSION
            )
            self.assertFalse(self.host.execute(self.kernel, permit, target))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(WORKER_COUNT, len(_events(self.kernel, "permit_rejected")))
        result = reconcile_consequences([SCAN_T1_INTENT.resource], self.host.executed)
        self.assertTrue(result["ok"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: substitution and forgery ------------------------------------

    def test_step5_substituted_and_forged_approvals_denied(self) -> None:
        # (a) A genuine approval for a DIFFERENT act (the
        # read-only inventory), presented for the
        # exfiltration: real authority for one act is not
        # authority for another, however far along the
        # chain the presented act sits.
        other_envelope = signed_envelope(
            self.kernel,
            INVENTORY_T1_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-other",
            nonce="nonce-other",
        )
        decision = self.kernel.evaluate_with_approval(EXFIL_T1_INTENT, other_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) An envelope for the harvest signed with an
        # unauthorized key: the fleet's workers held no
        # signing authority, and neither does anyone else
        # who reaches the boundary -- a worker cannot mint
        # the authority it spends.
        forged_envelope = signed_envelope(
            self.kernel, HARVEST_T1_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW,
            approval_id="approval-forged", nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(HARVEST_T1_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.host.executed)
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
            self.kernel, SCAN_T1_INTENT, approval_id="approval-real", nonce="nonce-real"
        )
        self.assertTrue(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: reconciliation over the governed pipeline -------------------
    #
    # The campaign was reconstructed from the operator's
    # own exposed servers because nothing inside the
    # pipeline ever compared what the workers executed
    # with what anyone had approved. This step runs that
    # comparison over a governed sequence shaped like one
    # job: the scan approved and executed, then the four
    # chain stages each attempted under the scan approval,
    # and the scan attempted against target-002 under the
    # spent permit. Every campaign attempt is denied, so
    # the executed log stays exactly the approved act and
    # reconciliation reports equality -- zero unauthorized
    # occurrences, not merely "the job ran."

    def test_step6_reconciliation_governed_pipeline_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, SCAN_T1_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertTrue(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        envelope = signed_envelope(
            self.kernel,
            SCAN_T1_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-rec-env",
            nonce="nonce-rec-env",
        )
        for intent in CAMPAIGN_T1_INTENTS:
            decision = self.kernel.evaluate_with_approval(intent, envelope)
            self.assertEqual("deny", decision.outcome)
            self.assertFalse(self.host.execute(self.kernel, decision.permit, intent))
        self.assertFalse(self.host.execute(self.kernel, permit, SCAN_T2_INTENT))
        result = reconcile_consequences([SCAN_T1_INTENT.resource], self.host.executed)
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(1, result["executed_count"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertEqual([], result["unauthorized"])
        self.assertTrue(result["ok"])
        self.assertEqual(len(CAMPAIGN_T1_INTENTS), len(_events(self.kernel, "approval_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the attempts ----------------------
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
        self.kernel.evaluate(SCAN_T1_INTENT)
        # The mandate as permit, for the exploitation.
        self.assertFalse(self.host.execute(self.kernel, GOAL_MD, EXPLOIT_T1_INTENT))
        # The genuine scan approval stretched to the
        # harvest.
        envelope = signed_envelope(
            self.kernel,
            SCAN_T1_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-scan",
            nonce="nonce-seq-scan",
        )
        decision = self.kernel.evaluate_with_approval(HARVEST_T1_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # A forged envelope for the exfiltration.
        forged_envelope = signed_envelope(
            self.kernel, EXFIL_T1_INTENT, HmacTestVerifier(b"attacker-key"),
            now_ns=NOW, approval_id="approval-seq-forged", nonce="nonce-seq-forged",
        )
        decision = self.kernel.evaluate_with_approval(EXFIL_T1_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # The one legitimate act still lands; the chain
        # stages did not.
        permit = self._issue_permit(
            self.kernel, SCAN_T1_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)
        # The spent permit re-presented: the queue's next
        # job, refused.
        self.assertFalse(self.host.execute(self.kernel, permit, SCAN_T1_INTENT))
        self.assertEqual([SCAN_T1_INTENT.resource], self.host.executed)

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
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
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
                "decision": len(denied_decisions) + len(require_approval_decisions),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_ungoverned_fleet_executes_chain_on_every_target(self) -> None:
        # Same pipeline, no governor: a job drawn from the
        # queue executes its whole chain as presented, on
        # every target alike -- target-001, target-002,
        # and target-003 each take the exploitation, the
        # harvest, the persistence, and the exfiltration,
        # twelve consequences in job order, all "succeeding."
        # That is the incident, reproduced at the exact
        # layer it happened: not the PHP2Shell flaws
        # themselves -- the absence of any per-act,
        # per-target authorization question between a
        # mandate and a consequence, at fleet scale.
        host = UngovernedFleetHost()
        chain = []
        for target in ("target-001", "target-002", "target-003"):
            chain.extend(
                [
                    Intent(WORKER, "exploit_target", f"{target}:php/apache", 25, SESSION),
                    Intent(WORKER, "harvest_credentials", f"{target}:host/credentials", 25, SESSION),
                    Intent(WORKER, "install_persistence", f"{target}:host/persistence", 25, SESSION),
                    Intent(WORKER, "exfiltrate_data", f"{target}:host/loot-upload", 25, SESSION),
                ]
            )
        for intent in chain:
            self.assertTrue(host.execute_job(GOAL_MD, intent))
        self.assertEqual([intent.resource for intent in chain], host.executed)
        # Per-occurrence reconciliation reports the whole
        # fleet run as unauthorized, by count and by name
        # -- the check whose absence let one mandate spend
        # across 595 targets before the campaign had to be
        # reconstructed from the operator's own loot
        # server.
        result = reconcile_consequences([], host.executed)
        self.assertEqual(0, result["approved_count"])
        self.assertEqual(12, result["executed_count"])
        self.assertEqual(12, result["unauthorized_count"])
        self.assertEqual([intent.resource for intent in chain], result["unauthorized"])
        self.assertFalse(result["ok"])
        # Contrast, the identical first job step on the
        # governed path: the exploitation attempted with
        # the mandate as its permit is refused at consume
        # (step 1's route), and reconciliation over the
        # governed host's log reports zero unauthorized.
        self.assertFalse(self.host.execute(self.kernel, GOAL_MD, EXPLOIT_T1_INTENT))
        result = reconcile_consequences([], self.host.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

"""Scenario test: the SAP "Project Granite" incident --
stolen employee authentication tokens used on the
trusted code path (reported 2026-11-26).

Incident (graded from the public record): SAP
confirmed (Verified, SAP's statements to
BleepingComputer and dpa) that it identified
suspicious activity in its GitHub development
environment and promptly implemented protective
measures, and that, based on its investigation to
date, it has found no evidence of unauthorized access
to customer business data. Der Spiegel reported
(Recorded, insider sources) that attackers stole
authentication tokens belonging to SAP employees and
used them to copy and alter SAP source code on
GitHub, and that SAP tracks the incident internally
under the code name "Project Granite." Handelsblatt
reported (Recorded, insider sources; SAP has not
confirmed the specifics) the countermeasures: GitHub
access restricted, automated build and delivery
pipelines paused, and code-signing keys rotated.
Whether AI agents assisted the attackers, and whether
any altered code reached a build or a customer
shipment, are Unknown on the public record; this
scenario does not model either as fact.

The guardrail failure this replay isolates is the
bearer credential itself. A stolen employee token
authenticated its holder as the employee, for
everything the employee could do, on the trusted code
path: the credential was the only artifact the path
checked, and possessing it was treated as authority
for each act it was presented for -- copying source,
altering source, moving code toward build. At no
point did the path ask the separate question: was
THIS act authorized?

The failure is: **a bearer credential is not
authority for the act.** Authentication establishes
who holds the credential; it does not establish that
a specific consequential act was approved. Under the
canonical kernel, the token is not a permit at all --
presented at ``consume`` it is an unauthenticated
string and is refused. Authority for an act enters
only as a verified approval envelope, signed by an
enrolled authority and bound to the exact intent hash
(principal, action, resource, cost, session), and
mints a single-use permit for exactly that intent: a
permit minted for the engineer's ordinary work spends
on that work and nothing else. And when the incident
response revokes the standing authority the work ran
under -- the governed counterpart of restricting
access, pausing the pipelines, and rotating the keys
-- authority already issued but not yet consumed dies
at consume time, not merely at the next issuance.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce SAP's
systems, GitHub, any token, or any attacker tooling.
The mapping (Inferred, stated here so it can be
argued with): the development environment's dispatch
boundary is the governed boundary; the employee's
ordinary work is reading source in the dev
environment; the consequential acts are altering
protected source and promoting code toward the
release build; the stolen token is modeled two ways,
matching the two things it was in the incident -- as
the raw credential string presented at the boundary,
and as the genuine authority it could reach (a permit
for ordinary work, and a standing directive for the
dev run) stretched past what that authority ever
covered. SAP's countermeasures are modeled as the
revocation of that standing directive. Work consumed
before the revocation stands -- revocation is not
retroactive -- and nothing unconsumed survives it.

Setup A (approval path): exactly one act is
legitimate -- reading the source module, once, under
a verified approval envelope. The incident's acts are
then attempted on the governed path: with the stolen
token presented as a permit, under a genuine permit
minted for the ordinary act stretched to the
consequential ones, under an envelope the token
holder signed with its own key, and with no artifact
at all. The kernel must deny each one, the boundary's
consequence log must stay exactly the one approved
act, and every denial must land in the audit record.

Setup B (directive path): the dev run operates under
an active directive scoped to the dev environment.
One read permit issued under it is consumed -- work
done before the response, and it stands. A second
read permit is issued and left unconsumed; the
response then revokes the directive, and the
unconsumed permit must fail at consume with the
directive recorded as revoked: revocation bites at
consume time, which is the only time that protects
the pipeline.

Incident-channel surfacing (Verified at this commit,
by executable probe and by the channel's derivation
rules): the derived incident report turns
``permit_rejected`` events, ``approval_rejected``
events, and denied decisions into near-miss records.
A bare ``evaluate`` that returns ``require_approval``
-- the kernel declining to mint without approval --
appends a decision record to the canonical audit and
is derived as a near-miss by the channel since the
issue #375 fix. The scenario asserts both halves of
that statement exactly as they hold; it does not
smooth the second half over.

Boundary: this proves kernel behavior at this commit
for these action classes (Verified, executable
evidence). It proves nothing about SAP's actual
systems, GitHub's controls, or any deployed
environment that does not route its acts through this
kernel -- a code path that executes on a presented
credential alone is governed by nothing here. The
replay models the authorization step the incident's
path did not have, not SAP internals. A control not
on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly verified approval, for
exactly the approved act, and any path that treats a
possessed credential as authority for the act (the
incident's own class) remains outside this evidence
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
accumulate capability. The directive activation and
revocation in Setup B are operator transitions in
their own right, each appending its own record; they
are the incident response modeled, not attempt growth.
Throughout this module, "consequence" means governed
external consequence (the permitted consume recorded
in the boundary's log), never audit growth.
"""

from __future__ import annotations

import unittest

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.directives import GovernedDirectiveProjection
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_directives import OPERATOR, directive


NOW = 5_000_000
# The employee whose token was stolen (Recorded: the
# tokens belonged to SAP employees). At the boundary,
# acts arrive under the employee's identity, because
# that is what the credential authenticates -- which is
# precisely the property the incident exploited.
ENGINEER = "employee:sap-dev-engineer"
SESSION = "sap-dev-2026-11"

# The ordinary act: reading source in the dev
# environment -- the engineer's daily work, and the
# copy step of the incident.
READ_INTENT = Intent(ENGINEER, "read_source", "sap-dev:source/core-module", 25, SESSION)
# The consequential acts (Recorded classes, one intent
# each):
# - altering SAP source code on GitHub;
ALTER_INTENT = Intent(ENGINEER, "modify_source", "sap-dev:source/core-module", 25, SESSION)
# - moving code toward the release build -- the
#   automated pipeline SAP reportedly paused.
PROMOTE_INTENT = Intent(ENGINEER, "promote_to_build", "sap-dev:pipeline/release-build", 25, SESSION)
CONSEQUENTIAL_INTENTS = (ALTER_INTENT, PROMOTE_INTENT)

# The stolen token, modeled as the artifact itself: a
# bearer credential string. On the incident's path it
# was the whole of the authority check; here it is
# presented at consume in the role it played.
STOLEN_TOKEN = "sap-employee-auth-token:stolen"


def reconcile_consequences(approved: list[str], executed: list[str]) -> dict:
    """Reconcile what was executed against what was approved, per occurrence.

    Test-local; holds no canonical state. Counts, not
    presence: each approved occurrence accounts for one
    executed occurrence of the same act, in order, and
    every executed occurrence beyond the approved count
    for that act is an unauthorized occurrence, named.
    This is the check the incident's path never ran:
    run over the incident's own shape (the negative
    control), it reports the copied, altered, and
    promoted acts as unauthorized, by count and by name.
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


class CodePathBoundary:
    """Consequences on the code path, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the incident's path was not: in
    the incident, possession of the token was itself
    sufficient to copy, alter, and move code. Here the
    harness executes an act only when the kernel
    consumes a permit for the exact intent, and records
    each executed act in the log the reconciliation
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


class UngovernedCodePathBoundary:
    """The incident's own path, as a test-local double for the negative control.

    No kernel, no permit, no verified approval: the
    boundary takes the presented bearer credential at
    face value -- the position the incident's code path
    was in -- and executes each act the credential is
    presented for. Every execution is recorded in the
    same log shape the governed boundary produces, so
    the one reconciliation runs over both paths and the
    difference is in the counts, not in the bookkeeping.
    Test-local; never imported by runtime code.
    """

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute_on_credential(self, credential: str, intent: Intent) -> bool:
        if not credential:
            return False
        self.executed.append(intent.resource)
        return True


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class SapGraniteApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.kernel = self._kernel()
        self.boundary = CodePathBoundary()

    def _kernel(self) -> GovernanceKernel:
        actions = frozenset({"read_source", "modify_source", "promote_to_build"})
        policy = Policy(
            actions,
            10_000,
            actions,
            authority_trust=trust_for(self.verifier),
        )
        return GovernanceKernel(
            policy,
            secret=b"sap-granite-scenario-secret",
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

    def test_positive_control_ordinary_read_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, READ_INTENT)
        # The one legitimate act: the engineer's ordinary
        # read, under a genuine, well-formed verified
        # approval -- the work the credential's owner was
        # actually there to do.
        self.assertTrue(self.boundary.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual([READ_INTENT.resource], self.boundary.executed)
        # The permit was spent at that consume --
        # revocation-at-consume: the same permit cannot
        # read the module twice on one approval.
        self.assertFalse(self.boundary.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual([READ_INTENT.resource], self.boundary.executed)
        # Reconciliation: what was executed is exactly
        # what was approved, per occurrence.
        result = reconcile_consequences([READ_INTENT.resource], self.boundary.executed)
        self.assertEqual(
            {"approved_count": 1, "executed_count": 1, "unauthorized_count": 0,
             "unauthorized": [], "ok": True},
            result,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the stolen token presented as authority --------------------
    #
    # The incident's core move: the attackers held a
    # genuine employee token, and the path asked nothing
    # else. Presented to the governed boundary as a
    # permit -- the role it played in the incident -- the
    # token is what it is: a string the presenter holds.
    # The kernel cannot authenticate it as a permit and
    # refuses it at consume for every act alike, the
    # ordinary read included: possession authenticates
    # the holder, and authorizes nothing.

    def test_step1_stolen_token_presented_as_permit_denied(self) -> None:
        for intent in (READ_INTENT, ALTER_INTENT, PROMOTE_INTENT):
            self.assertFalse(self.boundary.execute(self.kernel, STOLEN_TOKEN, intent))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(3, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in (READ_INTENT, ALTER_INTENT, PROMOTE_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: genuine ordinary authority stretched to the consequential acts
    #
    # The strongest form of the incident's claim: not a
    # forged artifact, but genuine authority -- a real
    # permit, minted through a verified approval for the
    # engineer's ordinary read -- presented for the
    # alteration and the promotion. The permit binds one
    # intent hash; at consume the kernel compares the
    # token's authenticated digest to the presented
    # intent and refuses both. Authority for the work an
    # employee does daily is not authority for the acts
    # the theft was for. And the refusals burn nothing:
    # the genuine permit still spends on its own act.

    def test_step2_ordinary_permit_stretched_to_consequential_acts_denied(self) -> None:
        permit = self._issue_permit(self.kernel, READ_INTENT)
        for intent in CONSEQUENTIAL_INTENTS:
            self.assertFalse(self.boundary.execute(self.kernel, permit, intent))
        self.assertEqual([], self.boundary.executed)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(len(CONSEQUENTIAL_INTENTS), len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in CONSEQUENTIAL_INTENTS},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        # The denial consumed nothing: the genuine read
        # still spends, exactly once.
        self.assertTrue(self.boundary.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual([READ_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: no minting path from a credential ---------------------------
    #
    # Two remainders of the incident's shape. First, with
    # no artifact presented at all, the kernel declines
    # to mint for each consequential act: holding the
    # employee's identity confers no route to a permit.
    # Second, the token holder's own signature: an
    # approval envelope for the alteration, well-formed
    # in every field but signed with a key the holder
    # controls rather than the enrolled authority's. The
    # kernel verifies against the enrolled authority,
    # and the credential's holder is not it.

    def test_step3_no_approval_mints_nothing_and_self_signed_envelope_denied(self) -> None:
        for intent in CONSEQUENTIAL_INTENTS:
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
        self.assertEqual(len(CONSEQUENTIAL_INTENTS), len(decisions))

        holder_signed = HmacTestVerifier(b"stolen-token-holder-key")
        envelope = signed_envelope(
            self.kernel, ALTER_INTENT, holder_signed, now_ns=NOW,
            approval_id="approval-holder-asserted", nonce="nonce-holder-asserted",
        )
        decision = self.kernel.evaluate_with_approval(ALTER_INTENT, envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.boundary.execute(self.kernel, decision.permit, ALTER_INTENT))
        self.assertEqual([], self.boundary.executed)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "approval_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: reconciliation over the governed sequence -------------------
    #
    # The incident ran from the theft until SAP's
    # detection because nothing on the path compared
    # what the credential did with what anyone had
    # approved. This step runs that comparison over a
    # governed sequence shaped like the incident: the
    # ordinary read approved and executed, then the
    # alteration and the promotion each attempted under
    # the theft's two forms (the token as permit; the
    # genuine read permit stretched). Every consequential
    # attempt is denied, so the executed log stays
    # exactly the approved act and reconciliation reports
    # equality -- zero unauthorized occurrences, not
    # merely "the work got done."

    def test_step4_reconciliation_governed_sequence_zero_unauthorized(self) -> None:
        permit = self._issue_permit(
            self.kernel, READ_INTENT, approval_id="approval-rec", nonce="nonce-rec"
        )
        self.assertTrue(self.boundary.execute(self.kernel, permit, READ_INTENT))
        for intent in CONSEQUENTIAL_INTENTS:
            self.assertFalse(self.boundary.execute(self.kernel, STOLEN_TOKEN, intent))
        for intent in CONSEQUENTIAL_INTENTS:
            self.assertFalse(self.boundary.execute(self.kernel, permit, intent))
        result = reconcile_consequences([READ_INTENT.resource], self.boundary.executed)
        self.assertEqual(1, result["approved_count"])
        self.assertEqual(1, result["executed_count"])
        self.assertEqual(0, result["unauthorized_count"])
        self.assertEqual([], result["unauthorized"])
        self.assertTrue(result["ok"])
        self.assertEqual(4, len(_events(self.kernel, "permit_rejected")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: the incident channel sees the attempts ----------------------
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
        self.kernel.evaluate(ALTER_INTENT)
        # The stolen token as permit, for both
        # consequential acts.
        for intent in CONSEQUENTIAL_INTENTS:
            self.assertFalse(self.boundary.execute(self.kernel, STOLEN_TOKEN, intent))
        # The genuine read approval stretched to the
        # alteration.
        envelope = signed_envelope(
            self.kernel,
            READ_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-seq-read",
            nonce="nonce-seq-read",
        )
        decision = self.kernel.evaluate_with_approval(ALTER_INTENT, envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate act still lands; the
        # consequential acts did not.
        permit = self._issue_permit(
            self.kernel, READ_INTENT, approval_id="approval-seq-run", nonce="nonce-seq-run"
        )
        self.assertTrue(self.boundary.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual([READ_INTENT.resource], self.boundary.executed)
        # The spent permit re-presented: refused.
        self.assertFalse(self.boundary.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual([READ_INTENT.resource], self.boundary.executed)

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
        self.assertEqual(3, len(permit_rejected))
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
        self.assertEqual(6, report.near_misses)
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

    def test_negative_control_ungoverned_path_executes_on_credential_alone(self) -> None:
        # Same boundary, no governor: the presented bearer
        # credential is taken at face value -- the position
        # the incident's code path was in -- and every act
        # executes as presented: the source is copied, the
        # source is altered, the code is promoted toward
        # the release build. Every step "succeeds." That is
        # the incident, reproduced at the exact layer it
        # happened: not any one weakness in the platform --
        # the absence of an authorization boundary that asks
        # who approved this act, as distinct from who holds
        # this credential.
        boundary = UngovernedCodePathBoundary()
        for intent in (READ_INTENT, ALTER_INTENT, PROMOTE_INTENT):
            self.assertTrue(boundary.execute_on_credential(STOLEN_TOKEN, intent))
        self.assertEqual(
            [READ_INTENT.resource, ALTER_INTENT.resource, PROMOTE_INTENT.resource],
            boundary.executed,
        )
        # Per-occurrence reconciliation reports the whole
        # run as unauthorized, by count and by name -- the
        # check whose absence let the run continue until
        # the platform owner detected it from outside the
        # path. (The read and the alteration share a
        # resource label, so the unauthorized list carries
        # the module path twice: the copy and the
        # alteration are distinct occurrences of acts
        # against it, and the promotion once.)
        result = reconcile_consequences([], boundary.executed)
        self.assertEqual(0, result["approved_count"])
        self.assertEqual(3, result["executed_count"])
        self.assertEqual(3, result["unauthorized_count"])
        self.assertEqual(
            [READ_INTENT.resource, ALTER_INTENT.resource, PROMOTE_INTENT.resource],
            result["unauthorized"],
        )
        self.assertFalse(result["ok"])
        # Contrast, the identical first step on the
        # governed path: the alteration attempted with the
        # token as its permit is refused at consume
        # (step 1's route), and reconciliation over the
        # governed boundary's log reports zero
        # unauthorized.
        self.assertFalse(
            self.boundary.execute(self.kernel, STOLEN_TOKEN, ALTER_INTENT)
        )
        result = reconcile_consequences([], self.boundary.executed)
        self.assertEqual(0, result["unauthorized_count"])
        self.assertTrue(result["ok"])


class SapGraniteRevocationTests(unittest.TestCase):
    """Setup B: revocation of the dev run's directive kills a
    previously issued, unconsumed permit at consume time.

    The governed counterpart of SAP's reported response
    (Recorded): access restricted, pipelines paused,
    signing keys rotated. Work consumed before the
    revocation stands; authority issued but unconsumed
    does not survive it. The activation/revocation
    scaffolding mirrors the canonical directive scenario
    construction (tests/test_nginx2root_incident_scenario.py,
    Setup B) by composition of the same public helpers,
    with the kernel policy's action set covering this
    scenario's action; it does not inherit that suite.
    """

    def _governed(self, state):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"read_source", "activate_directive", "revoke_directive"}),
            10_000,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"sap-granite-directive-scenario-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def _approve(self, kernel, verifier, operation, d, approval_id, nonce):
        from pulpo.directives import DirectiveAuthorityController

        intent = DirectiveAuthorityController.authority_intent(
            operation, d, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def _activate(self, state, d):
        from pulpo.directives import DirectiveAuthorityController

        kernel, verifier = self._governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self._approve(
            kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1"
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def test_revoked_directive_invalidates_issued_unconsumed_permit(self) -> None:
        state = InMemoryKernelState()
        d = directive(
            directive_id="sap-dev-work",
            principal=ENGINEER,
            allowed_actions=frozenset({"read_source"}),
            resource_prefixes=("sap-dev:",),
            max_cost=100,
            issued_at_ns=1_000_000,
            expires_at_ns=9_000_000,
        )
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)

        # Work under the directive before the response:
        # issued and consumed, and it stands -- the
        # incident response does not rewrite history.
        first = projection.evaluate(READ_INTENT, d)
        self.assertEqual("allow", first.outcome)
        self.assertIsNotNone(first.permit)
        self.assertTrue(kernel.consume(first.permit, READ_INTENT))

        # A second permit, issued under the same
        # directive and left unconsumed when the response
        # lands.
        second = projection.evaluate(READ_INTENT, d)
        self.assertEqual("allow", second.outcome)
        self.assertIsNotNone(second.permit)

        # The response: the directive is revoked -- the
        # governed counterpart of restricting access,
        # pausing the pipelines, and rotating the keys.
        revoke_envelope = self._approve(
            kernel, verifier, controller.REVOKE, d, "revoke-1", "revoke-nonce-1"
        )
        revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", revoke.outcome)

        # The unconsumed permit fails at consume, with
        # the directive recorded as revoked: revocation
        # bites at consume time, which is the only time
        # that protects the pipeline.
        self.assertFalse(kernel.consume(second.permit, READ_INTENT))
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])
        self.assertTrue(kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

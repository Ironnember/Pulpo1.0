"""Scenario test: the Radware Cloud WAF management API
exposure (unauthorized access 2026-11-19; disclosed
2026-11-24).

Incident (Recorded, from BleepingComputer's 2026-11-24
reporting of Radware's root cause analysis, which
reached BleepingComputer from an anonymous source;
Radware had issued no public statement and no SEC
filing as of that reporting): "On 19 November 2026, an
unauthorized party accessed an internal-only Cloud WAF
management API that was reachable from the Public
Internet without requiring authentication." The
confirmed information potentially accessed includes
customer contact details and, for a subset of
customers, the credentials configured for log export
into their self-managed storage (AWS S3, Azure Blob
Storage, or SFTP). Per the root cause analysis as
reported, Radware blocked the originating IP address
and access to the internal management API and revoked
and replaced all internal account credentials after
detecting the breach, ten hours after the initial
unauthorized API access. Radware said the breach did
not expose WAF traffic inspection, certificates,
end-users' data, customer application traffic, or
cloud DDoS services and data, and that it had found no
evidence of changes to customer security policies or
of access to customer application traffic. Affected
customers were advised to rotate their log-export
credentials and to review access logs on their cloud
storage accounts for unexpected access since at least
November 19; Radware had already received reports from
customers about AWS alerts for an unfamiliar IP address
attempting to access their log-export buckets.

The failure is an authorization failure with no
authorization step in it: the management API's access
control was its presumed network position. The API was
"internal-only" by intention and reachable from the
public internet in fact, and a request that arrived was
executed because of where the API was supposed to sit
-- there was no authentication to bypass and no per-act
authorization to defeat. A network position is evidence
about reachability. It is not a permit: it names no
principal, no act, and no resource, and it authorizes
nothing in particular.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce Radware's
API, any network behavior, or any credential material:
the credentials at issue are represented only by the
resource identity of the act that would read them out,
and no secret value exists anywhere in this module. The
mapping (Inferred, stated here so it can be argued
with): the consequential act is exporting the
log-export credential material configured on the
management plane -- the disclosure the incident's
customers now have to rotate keys against. That act
requires a permit bound to the exact intent hash:
principal, action, resource, cost, session. The
incident's trusted channel is the management plane's
presumed-internal session, presented in the scenario
both as the requests' session (where it belongs -- as
context, bound into the intent, authorizing nothing)
and, in step 1, as the permit itself (where it does
not). The only route from a request to a consequence
is a successful ``GovernanceKernel.consume`` of a
permit bound to that exact intent.

Setup: exactly one export is legitimate in this
scenario -- an operator's credential export from the
management plane, performed once, under a permit issued
through a verified approval envelope: the accountable
per-action authorization actually granted. The
incident's act is then attempted on every route the
management plane has: with no permit at all, with the
trusted internal channel itself presented as the
permit, with a genuine permit to read the configuration
of the same resource (a different act), with a genuine
permit to export a different resource on the same plane
(customer contact details -- the incident's other
disclosure), with forged and mismatched approval
envelopes, and with a replayed spent permit. The kernel
must deny each one, the consequence ledger must stay
empty for all of them, and every denial must land in
the audit record. A genuine, well-formed approval
verifies and authorizes exactly one execution, and
then spends.

Incident-channel surfacing (Verified by execution at
this commit; the derivation behavior matches the
GL.iNet GoodCloud and SSHole replays Verified at the
base lineage): the derived incident report turns
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
evidence). It proves nothing about Radware's deployed
systems or any management plane that does not route its
dispatch through this kernel. Two limits are stated
plainly. First, the replay governs the act at the
dispatch boundary; it does not model or repair network
reachability -- a governed API that is unintentionally
reachable still denies unauthenticated acts, and an
ungoverned API that is unreachable is merely lucky, and
this evidence speaks only to the authorization half of
that pair. Second, once credential material has left
the plane, no permit system recalls it: the downstream
use of the exposed keys against customers' own cloud
storage is outside this boundary, and the incident's
actual remedy -- rotation -- is incident response, not
authorization. The replay governs the export before it
happens, not the exposure afterward. A control not on
the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly scoped permit, and any
dispatch path that executes on channel trust alone (the
incident's own class) remains outside this evidence and
open.

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
recorded in the consequence ledger), never audit
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
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The Cloud WAF management API service: the dispatch
# boundary the incident's requests reached. Every intent
# below is an act this service would perform; an
# unauthenticated network peer proposes, the service
# must not perform anything without a permit bound to
# the act.
API = "agent:radware-management-api"
# The management plane's presumed-internal session, in
# the harness's naming. Session identity is part of the
# bound intent; it is not itself authority for anything
# -- in the incident, its presumed trustworthiness was
# the entire access control.
CHANNEL = "internal-management-channel"

# The incident's consequential act: export the
# credential material configured for log export into
# customer-managed storage (AWS S3, Azure Blob, SFTP).
# No credential value exists in this scenario; the act
# is identified by the resource whose material it would
# read out.
EXPORT_INTENT = Intent(
    API, "export_credentials", "radware:cloud-waf/log-export-credentials", 25, CHANNEL
)
# A different act on the same resource: read the
# log-export configuration (which storage, which
# schedule) without reading out the credential material
# configured in it. A permit for this is real authority
# -- for this intent.
READ_INTENT = Intent(
    API, "read_configuration", "radware:cloud-waf/log-export-credentials", 25, CHANNEL
)
# The same act on a different resource: export the
# customer contact details -- the incident's other
# confirmed disclosure. A permit for this export is
# real authority -- for this resource.
CONTACT_EXPORT_INTENT = Intent(
    API, "export_credentials", "radware:cloud-waf/customer-contact-details", 25, CHANNEL
)

# The trusted internal channel itself, presented as if
# it were a permit. The channel is genuinely the plane's
# own internal path -- and it is not an approval
# envelope, not ceremony evidence, and not a permit. In
# the incident, arriving over this path was sufficient.
# The kernel must treat this string as a fabricated
# token, because as authority for the export that is
# what it is.
CHANNEL_TOKEN = "radware:internal-network-management-channel"

# Token presented to ``GovernanceKernel.consume`` when the
# executor holds no permit at all. The kernel's consume
# contract takes a permit string; issued permits are
# ``<intent-hash>:<nonce>:<signature>`` and are never empty,
# so the empty string is a never-issued token that
# represents unavailable authority -- as distinct from a
# fabricated token such as CHANNEL_TOKEN above, which
# represents forged authority. Presenting it lets the
# KERNEL, not this harness, reject the attempt and write
# the canonical ``permit_rejected`` audit record for it.
NO_PERMIT_TOKEN: str = ""


class ManagementApiExecutor:
    """Consequences on the management plane, reachable only via consume.

    This is the scenario's execution path -- the
    dispatch boundary the incident's API did not have:
    in the incident, a request that arrived WAS the
    execution path, and the response followed
    immediately. Here the harness records an effect only
    when the kernel consumes a permit for the exact
    intent. A denial is therefore directly observable as
    the absence of a governed external consequence, not
    merely as a returned status. (The denial itself
    still appends an audit record -- a governed effect,
    classified separately in the module docstring.)

    The harness never denies on its own: every attempt
    -- including one holding no permit (``permit=None``)
    -- is presented to ``GovernanceKernel.consume``,
    with the never-issued ``NO_PERMIT_TOKEN`` standing
    in for the absent permit, so a regression in the
    kernel's handling of unavailable authority fails
    this scenario instead of being masked by a
    harness-side short-circuit.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if not kernel.consume(NO_PERMIT_TOKEN if permit is None else permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued,
    unspent permit spends for any intent. It exists only
    to prove the scenario's denial assertions discriminate
    -- under this double the credential export must
    EXECUTE, or the scenario would be denying by
    construction rather than by the kernel's binding.
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

    Its consume() performs none of the kernel's spend-path
    checks -- neither token authentication nor the
    token-to-intent binding -- and delegates straight to
    the state. Paired with the intent-blind state double
    above, no layer binds the permit to the presented
    intent, so the credential export must EXECUTE here
    under a permit issued for a configuration read. Even
    this double grants the incident's API more checking
    than it had -- some permit must exist and be unspent,
    where the real API required nothing at all.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class RadwareIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"export_credentials", "read_configuration"}),
            10_000,
            frozenset({"export_credentials", "read_configuration"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.executor = ManagementApiExecutor()

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

    def test_positive_control_exact_permit_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, EXPORT_INTENT)
        # The one legitimate act: the operator's
        # credential export under a genuine, well-formed,
        # verified approval executes once.
        self.assertTrue(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        # The same permit cannot export the same material
        # twice -- a verified approval is not a standing
        # management session.
        self.assertFalse(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no permit; the trusted channel is not one -----------------

    def test_step1_no_permit_denied_trusted_channel_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for the credential export, and the
        # request's arrival over the network is not one.
        # (The incident's route (a): no permit at all, via
        # the trusted channel.)
        decision = self.kernel.evaluate(EXPORT_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        # The attempt is still presented for dispatch, and
        # the executor routes it through the canonical
        # kernel with the never-issued NO_PERMIT_TOKEN
        # standing in for the absent permit, so the
        # kernel's own rejection path is exercised and the
        # refusal lands in the audit -- the fail-closed
        # result below is the kernel's, not a harness-side
        # short-circuit on permit=None (Codex P2 on
        # PR #394).
        self.assertFalse(self.executor.execute(self.kernel, decision.permit, EXPORT_INTENT))
        # The plane presents its presumed-internal channel
        # itself as its authority -- the incident's exact
        # move, and the only one it needed. The channel is
        # genuine; as a permit it is a fabricated token,
        # and the kernel treats it as one. Nothing is
        # exported.
        self.assertFalse(self.executor.execute(self.kernel, CHANNEL_TOKEN, EXPORT_INTENT))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # Both presentations were refused by the kernel at
        # consume, and each refusal is in the audit: the
        # never-issued token standing in for the absent
        # permit, and the channel token. Neither carries a
        # state row or an authentic signature, and both
        # rejections are bound to the export's intent hash.
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        for record in rejected:
            self.assertEqual(
                self.kernel.intent_hash(EXPORT_INTENT),
                record["payload"]["intent_hash"],
            )
            self.assertEqual("permit_signature_invalid", record["payload"]["reason"])
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: a permit for a different action ----------------------------

    def test_step2_read_permit_does_not_authorize_the_export(self) -> None:
        permit = self._issue_permit(self.kernel, READ_INTENT)
        # Same plane, same session, same resource -- a
        # different act. The permit authorizes reading the
        # log-export configuration; the request is to read
        # out the credential material configured in it,
        # and the read permit spends on the export not at
        # all. (The incident's route (b), action half: in
        # the incident this distinction did not exist,
        # because no act on the plane was distinguished
        # from any other -- a request was a request.)
        self.assertFalse(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        self.assertEqual([], self.executor.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXPORT_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit
        # still spends on the exact act it was issued for.
        self.assertTrue(self.executor.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual(
            [("read_configuration", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: a permit for a different resource ---------------------------

    def test_step3_contact_export_permit_does_not_authorize_credential_export(self) -> None:
        permit = self._issue_permit(self.kernel, CONTACT_EXPORT_INTENT)
        # Same plane, same session, same action -- a
        # different resource. The permit authorizes
        # exporting the customer contact details; the
        # request is to export the log-export credential
        # material, and the contact permit spends on it
        # not at all. (The incident's route (b), resource
        # half: the incident disclosed both resources
        # through the same unauthenticated path, because
        # the path distinguished nothing.)
        self.assertFalse(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        self.assertEqual([], self.executor.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXPORT_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The permit still spends on the resource it
        # names.
        self.assertTrue(self.executor.execute(self.kernel, permit, CONTACT_EXPORT_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/customer-contact-details")],
            self.executor.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the exact permit authorizes exactly one export --------------

    def test_step4_exact_permit_authorizes_exactly_one_export(self) -> None:
        permit = self._issue_permit(self.kernel, EXPORT_INTENT)
        # A correctly scoped, live permit for the
        # credential export authorizes the export -- once.
        # (The incident's route (c): the only path that
        # may execute. Whether such a permit should ever
        # be granted for credential material is the
        # approver's judgment; the kernel's claim is
        # narrower: if granted, it is this act, this
        # resource, one time.)
        self.assertTrue(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        # The replay's shape -- the same request
        # re-arriving over the same channel, carrying the
        # now-spent authorization -- gets nothing, on the
        # export route or re-aimed at the configuration
        # read.
        self.assertFalse(self.executor.execute(self.kernel, permit, EXPORT_INTENT))
        self.assertFalse(self.executor.execute(self.kernel, permit, READ_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ----------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, READ_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the export signed with an
        # unauthorized key: whoever can reach the API
        # cannot mint the operator's authority by reaching
        # it.
        forged_envelope = signed_envelope(
            self.kernel, EXPORT_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(EXPORT_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine read envelope presented for the
        # export intent: a real approval for a lesser act
        # is not approval for the disclosure.
        decision = self.kernel.evaluate_with_approval(EXPORT_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_signature_invalid", "approval_intent_mismatch"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine
        # pair still admits.
        decision = self.kernel.evaluate_with_approval(READ_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the attempts ----------------------
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
    #
    # The frozen sequence is the full attempt sequence of
    # steps 1-5, not a subset: the no-permit and
    # channel-token routes (step 1), the different-action
    # permit route (step 2), the different-resource permit
    # route (step 3), both approval-envelope attempts
    # (step 5), the one legitimate export, and the
    # spent-permit replays (step 4). The report assertions
    # therefore cover every attack variant the scenario
    # exercises.
    #
    # The counts below were confirmed by the executed run
    # of this module at this head and at the clean base
    # checkpoint 9aca02e (see the change record, sections
    # 8 and 9): 6 permit_rejected, 2 approval_rejected, 2
    # denied decisions, 10 near-misses, 0 incidents. The
    # sixth permit_rejected is the no-permit route's
    # kernel refusal of the never-issued token, added by
    # the post-review fix recorded in section 9; before
    # that fix the harness short-circuited the route and
    # the counts were 5 and 9.

    def test_step6_incident_channel_surfaces_the_attempts(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        export_permit = self._issue_permit(
            self.kernel, EXPORT_INTENT, approval_id="approval-export", nonce="nonce-export"
        )
        read_permit = self._issue_permit(
            self.kernel, READ_INTENT, approval_id="approval-read", nonce="nonce-read"
        )
        contact_permit = self._issue_permit(
            self.kernel,
            CONTACT_EXPORT_INTENT,
            approval_id="approval-contact",
            nonce="nonce-contact",
        )
        # The incident, compressed: the export attempted on
        # every route the plane has -- no permit, the
        # trusted channel as a token, the different-action
        # permit, and the different-resource permit.
        self.kernel.evaluate(EXPORT_INTENT)
        self.assertFalse(self.executor.execute(self.kernel, None, EXPORT_INTENT))
        self.assertFalse(self.executor.execute(self.kernel, CHANNEL_TOKEN, EXPORT_INTENT))
        self.assertFalse(self.executor.execute(self.kernel, read_permit, EXPORT_INTENT))
        self.assertFalse(self.executor.execute(self.kernel, contact_permit, EXPORT_INTENT))
        forged_envelope = signed_envelope(
            self.kernel,
            EXPORT_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(EXPORT_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the
        # genuine read envelope presented for the export
        # intent. A real approval for a lesser act is not
        # approval for the disclosure; the decision is a
        # denial and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            READ_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(EXPORT_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate export still lands; the
        # incident did not.
        self.assertTrue(self.executor.execute(self.kernel, export_permit, EXPORT_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for
        # the same export and re-aimed at the configuration
        # read. A consumed permit is not a reusable channel
        # credential; both re-presentations are rejected at
        # consume.
        self.assertFalse(self.executor.execute(self.kernel, export_permit, EXPORT_INTENT))
        self.assertFalse(self.executor.execute(self.kernel, export_permit, READ_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )

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
        self.assertEqual(6, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
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
        self.assertEqual(10, report.near_misses)
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

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers --
        # a kernel double whose consume skips token
        # authentication and the kernel's token-to-intent
        # binding, over a state double whose consume ignores
        # the store's binding: the credential export
        # EXECUTES under a permit issued for a configuration
        # read. That is the incident's own shape -- a plane
        # that performs what arrives because it arrived over
        # the trusted path. The double in fact checks more
        # than the incident's API did: it requires some
        # issued, unspent permit, where the real API
        # required no authentication at all, and the export
        # still executes. The denials in the steps above
        # therefore come from the real consume path's
        # binding checks, not from a harness that denies by
        # construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_permit(blind_kernel, READ_INTENT)
        self.assertTrue(self.executor.execute(blind_kernel, permit, EXPORT_INTENT))
        self.assertEqual(
            [("export_credentials", "radware:cloud-waf/log-export-credentials")],
            self.executor.effects,
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route).
        real_permit = self._issue_permit(self.kernel, READ_INTENT)
        real_executor = ManagementApiExecutor()
        self.assertFalse(real_executor.execute(self.kernel, real_permit, EXPORT_INTENT))
        self.assertEqual([], real_executor.effects)


if __name__ == "__main__":
    unittest.main()

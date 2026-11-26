"""Scenario test: the GL.iNet GoodCloud trusted-channel
root shell execution incident (vendor notice 2026-11-20;
mechanism detail reported 2026-11-23).

Incident (Recorded, from GL.iNet's vendor notice of
2026-11-20 and from The Hacker News's 2026-11-23
reporting of RemoteToHome Consulting's research): an
unauthorized party exploited a flaw in GL.iNet's
GoodCloud cloud-management service to install malware --
root reverse shells calling back to 170.39.226[.]219 --
on GL.iNet routers and KVM devices. Per the researcher's
finding as reported, the GoodCloud client handler on the
device runs two cloud-message values as root via a shell
without checking them: values carried in a message that
arrived over the trusted cloud channel were passed to a
shell as a command. The mechanism is researcher-reported
and has NOT been confirmed by the vendor; this module
grades it Recorded on that basis and asserts nothing
stronger about the real service.

The failure is an authorization failure at the dispatch
boundary: a trusted channel was treated as authorization
for a specific act. The message arrived over a channel
the device already trusted, so the device executed it --
no per-act authorization, no binding between whatever
the channel session was for and the command it was asked
to run as root. A channel is evidence that two endpoints
are connected. It is not a permit, and it names no act.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce GoodCloud,
any GL.iNet firmware, any network behavior, or the
incident's payload. No shell command is ever executed
from message content in this module: the cloud message's
command-shaped values are represented by inert stand-in
bytes held by this harness, and the values' identity in
every intent is the SHA-256 digest of the bytes actually
presented at dispatch time, derived by the dispatch
boundary itself -- never a caller-supplied label, because
a label can be re-typed and a digest cannot be argued
with. The only route from a cloud message to a
consequence is a successful ``GovernanceKernel.consume``
of a permit bound to the exact intent hash: principal,
action, the presented values' digest, cost, session.

Setup: exactly one shell execution is legitimate in this
scenario -- an operator-issued maintenance command, run
once on one device, under a permit issued through a
verified approval envelope: the accountable per-action
authorization actually granted. The incident's act is
then attempted on every route the device agent has: with
no permit at all, with the established cloud channel
itself presented as the permit, with a genuine permit
for a benign cloud act on the same message (sync its
configuration -- not run it), with a genuine execution
permit for a different command, with the genuine
execution permit for the incident's values presented
against mutated values, with a replayed spent permit,
and with forged and mismatched approval envelopes. The
kernel must deny each one, the consequence ledger must
stay empty for all of them, and every denial must land
in the audit record. A correctly scoped execution permit
for the incident's exact values authorizes exactly one
execution and then spends.

Incident-channel surfacing (Verified by execution at
this commit; the derivation behavior matches the
ScreenConnect replay Verified at the base lineage): the
derived incident report turns ``permit_rejected``
events, ``approval_rejected`` events, and denied
decisions into near-miss records. A bare ``evaluate``
that returns ``require_approval`` -- the kernel declining
to mint without approval -- appends a decision record to
the canonical audit but is NOT derived as a near-miss by
the channel. The scenario asserts both halves of that
statement exactly as they hold; it does not smooth the
second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (executable evidence). It
proves nothing about any deployed device agent that does
not route its cloud-message dispatch through this
kernel -- a handler that executes first and asks never
(or asks the channel, which is not an authorizer) is
governed by nothing here. The replay models the
authorization step the handler skipped, not GoodCloud
internals. A control not on the execution path governs
nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken,
Lighten, Amplify, Negate) for this incident is recorded
in this scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel
path only -- exactly one governed external consequence
is permitted per correctly scoped permit, and any
non-kernel dispatch path (the incident's own class)
remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT
!= NO_GOVERNED_EFFECT``): a denied attempt is not "no
state changed." A denied attempt appends audit records,
counted per route: a bare evaluate returning
``require_approval`` appends one decision record; a
``consume`` rejection appends one ``permit_rejected``
record; a denied approval-envelope evaluation appends
two records -- an ``approval_rejected`` record and a
denied decision record. That growth is itself a governed
effect -- evidence production -- bounded at two records
per attempt, append-only, and it does not alter
authority (``authority_effect=none``) or accumulate
capability. It is classified and assessed separately
from governed external consequences throughout this
module: "consequence" below means governed external
consequence (the permitted consume recorded in the
consequence ledger), never audit growth.
"""

from __future__ import annotations

import hashlib
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
# The device agent: the GoodCloud client handler on a
# router/KVM device -- the executor the cloud message is
# aimed at. Every intent below is an act this handler
# would perform; the channel proposes, the handler must
# not execute without a permit bound to the act.
DEVICE = "agent:glinet-device-agent"
# The established GoodCloud channel session, in the
# harness's naming. Session identity is part of the bound
# intent; it is not itself authority for anything.
CHANNEL = "goodcloud-channel-device-01"

# The message values, as inert stand-in bytes. No byte
# here is the incident's payload and no byte is ever
# passed to a shell; the bytes exist so the dispatch
# boundary can derive the values' identity from the bytes
# actually presented, the way the kernel's binding
# requires.
#
# The one command an execution was actually approved
# for: a known operator maintenance command (its two
# message values: a command label and an argument label),
# issued by the operator for this device.
APPROVED_COMMAND_BYTES = (
    b"stand-in bytes: the approved operator maintenance command\r\n"
)
# The incident's values: command-shaped values carried in
# a cloud message from the compromised channel, wave AAAA.
CLOUD_COMMAND_BYTES = b"cloud message command-shaped values stand-in, wave AAAA"
# The same presentation with its bytes mutated after the
# fact: same length, different bytes. Under a label-based
# identity this would pass as the approved command; under
# the digest it is different values and a different
# intent.
MUTATED_COMMAND_BYTES = b"cloud message command-shaped values stand-in, wave BBBB"


def _values_digest(values: bytes) -> str:
    return hashlib.sha256(values).hexdigest()


def _command_resource(values: bytes) -> str:
    return f"goodcloud:command/sha256:{_values_digest(values)}"


# The incident's act: execute the cloud message's values
# as a shell command (as root, on the real device). The
# resource identity names the exact bytes, so this intent
# is these values and no others.
EXECUTE_INTENT = Intent(
    DEVICE, "execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES), 25, CHANNEL
)
# The benign cloud act on the same message: sync the
# device configuration the message carries, without
# executing anything. A channel may legitimately deliver
# configuration; the incident is that delivering values
# was allowed to become running them with no
# authorization step in between.
SYNC_INTENT = Intent(
    DEVICE, "sync_configuration", _command_resource(CLOUD_COMMAND_BYTES), 25, CHANNEL
)
# An execution of a different command: the approved
# operator maintenance command. A permit for this
# execution is genuine authority -- for this command.
APPROVED_EXECUTE_INTENT = Intent(
    DEVICE,
    "execute_shell_command",
    _command_resource(APPROVED_COMMAND_BYTES),
    25,
    CHANNEL,
)

# The established cloud channel itself, presented as if
# it were a permit. The channel is real, trusted, and
# fully established -- and it is not an approval envelope,
# not ceremony evidence, and not a permit. The kernel
# must treat this string as a fabricated token, because
# as authority for the execution that is what it is.
CHANNEL_TOKEN = "goodcloud:established-channel-session-device-01"


class DeviceAgentExecutor:
    """Consequences on the device, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's handler did not have. The
    harness records an effect only when the kernel
    consumes a permit for the exact intent; it never
    invokes a shell. A denial is therefore directly
    observable as the absence of a governed external
    consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a
    governed effect, classified separately in the module
    docstring.)
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

    def dispatch_command(self, kernel: GovernanceKernel, permit: str | None, values: bytes) -> bool:
        """Execute presented message values: the intent derives from the bytes.

        The dispatcher derives the values' digest from the
        bytes actually presented at dispatch time and
        submits the act those bytes constitute. A permit
        issued for other bytes -- the same label, an
        earlier wave, a mutated copy -- therefore cannot
        spend here, because the intent it was bound to is
        not the intent these bytes produce.
        """
        intent = Intent(
            DEVICE, "execute_shell_command", _command_resource(values), 25, CHANNEL
        )
        return self.execute(kernel, permit, intent)


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued,
    unspent permit spends for any intent. It exists only
    to prove the scenario's denial assertions discriminate
    -- under this double the cloud command must EXECUTE,
    or the scenario would be denying by construction
    rather than by the kernel's binding.
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
    intent, so the cloud command must EXECUTE here under
    a permit issued for a benign configuration sync. This
    is the incident's own shape: a handler that runs what
    the trusted channel delivers because the channel
    exists.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class GlinetGoodCloudIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"execute_shell_command", "sync_configuration"}),
            10_000,
            frozenset({"execute_shell_command", "sync_configuration"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.executor = DeviceAgentExecutor()

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

    def test_positive_control_approved_command_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_EXECUTE_INTENT)
        # The one legitimate execution: the operator's
        # maintenance command, dispatched by its bytes,
        # executes once.
        self.assertTrue(
            self.executor.dispatch_command(self.kernel, permit, APPROVED_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(APPROVED_COMMAND_BYTES))],
            self.executor.effects,
        )
        # The same permit cannot run the same command
        # twice -- an approval to execute a command is not
        # a standing one.
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, permit, APPROVED_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(APPROVED_COMMAND_BYTES))],
            self.executor.effects,
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no permit; the trusted channel is not one -----------------

    def test_step1_command_without_permit_denied_trusted_channel_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for executing the cloud message's values,
        # and the channel's existence is not one.
        decision = self.kernel.evaluate(EXECUTE_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, decision.permit, CLOUD_COMMAND_BYTES)
        )
        # The handler presents the established channel
        # itself as its authority -- the incident's exact
        # move. The channel is genuine and trusted; as a
        # permit it is a fabricated token, and the kernel
        # treats it as one. Nothing is executed.
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, CHANNEL_TOKEN, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXECUTE_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: a benign cloud permit does not authorize execution --------

    def test_step2_sync_permit_does_not_authorize_the_execution(self) -> None:
        permit = self._issue_permit(self.kernel, SYNC_INTENT)
        # Same channel, same message, same principal -- a
        # different act. The permit authorizes syncing the
        # configuration the message carries; the message's
        # request is to run its values as a shell command,
        # and the sync permit spends on the execution not
        # at all. In the incident this distinction did not
        # exist: the handler passed message values to a
        # shell as part of handling the message.
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual([], self.executor.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXECUTE_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit
        # still spends on the exact act it was issued for.
        self.assertTrue(self.executor.execute(self.kernel, permit, SYNC_INTENT))
        self.assertEqual(
            [("sync_configuration", _command_resource(CLOUD_COMMAND_BYTES))],
            self.executor.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: an execution permit for a different command ----------------

    def test_step3_execution_permit_for_another_command_does_not_authorize_this_one(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_EXECUTE_INTENT)
        # A genuine execution permit -- for the operator's
        # maintenance command. Presented at dispatch for
        # the cloud message's bytes, the derived intent
        # names a different digest, and the permit spends
        # on it not at all. Authority to execute a command
        # is authority for that command's bytes, not for
        # the execute verb.
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual([], self.executor.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXECUTE_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The permit still spends on the command it names.
        self.assertTrue(
            self.executor.dispatch_command(self.kernel, permit, APPROVED_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(APPROVED_COMMAND_BYTES))],
            self.executor.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the exact permit authorizes exactly one execution ----------

    def test_step4_exact_permit_authorizes_exactly_one_execution(self) -> None:
        permit = self._issue_permit(self.kernel, EXECUTE_INTENT)
        # A correctly scoped, live permit for the cloud
        # values' exact bytes authorizes the execution --
        # once. (Whether such a permit should ever be
        # granted for channel-delivered values is the
        # approver's judgment; the kernel's claim is
        # narrower: if granted, it is this act, these
        # bytes, one time.)
        self.assertTrue(
            self.executor.dispatch_command(self.kernel, permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES))],
            self.executor.effects,
        )
        # The replay's shape -- the same message
        # re-delivered over the valid channel, carrying the
        # now-spent authorization -- gets nothing, on the
        # execution route or re-aimed at the benign act.
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, permit, CLOUD_COMMAND_BYTES)
        )
        self.assertFalse(self.executor.execute(self.kernel, permit, SYNC_INTENT))
        self.assertEqual(
            [("execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES))],
            self.executor.effects,
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: mutated values under a genuine permit ------------------------

    def test_step5_mutated_values_denied_under_genuine_permit(self) -> None:
        permit = self._issue_permit(self.kernel, EXECUTE_INTENT)
        # The permit names the cloud values' digest. The
        # dispatch boundary is now presented with bytes of
        # the same length and nearly the same content -- a
        # later wave of the same campaign, or the same
        # label carrying different values. The derived
        # intent is a different intent, and the permit
        # spends on it not at all. No bytes exist in this
        # scenario outside the dispatch derivation, so
        # altered bytes cannot slip under a consumed permit
        # while the test passes.
        self.assertEqual(len(CLOUD_COMMAND_BYTES), len(MUTATED_COMMAND_BYTES))
        self.assertNotEqual(CLOUD_COMMAND_BYTES, MUTATED_COMMAND_BYTES)
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, permit, MUTATED_COMMAND_BYTES)
        )
        self.assertEqual([], self.executor.effects)
        mutated_intent = Intent(
            DEVICE,
            "execute_shell_command",
            _command_resource(MUTATED_COMMAND_BYTES),
            25,
            CHANNEL,
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(mutated_intent),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The genuine bytes still spend the permit.
        self.assertTrue(
            self.executor.dispatch_command(self.kernel, permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES))],
            self.executor.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: forged and mismatched approvals ----------------------------

    def test_step6_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, SYNC_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the execution signed with an
        # unauthorized key: whoever controls the channel
        # end of a session cannot mint the operator's
        # authority.
        forged_envelope = signed_envelope(
            self.kernel, EXECUTE_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(EXECUTE_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine sync envelope presented for the
        # execution intent: a real approval for a benign
        # act is not approval for execution.
        decision = self.kernel.evaluate_with_approval(EXECUTE_INTENT, genuine_envelope)
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
        decision = self.kernel.evaluate_with_approval(SYNC_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: the incident channel sees the campaign ---------------------
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
    # The frozen sequence below is the full attempt
    # sequence of steps 1-6, not a subset: the no-permit
    # and channel-token routes (step 1), the benign-permit
    # route (step 2), the other-command permit route
    # (step 3), the mutated-bytes dispatch (step 5), both
    # approval-envelope attempts (step 6), the one
    # legitimate execution, and the spent-permit replays
    # (step 4). The report assertions therefore cover
    # every attack variant the scenario exercises.
    #
    # The counts below were confirmed by the executed
    # run of this module at this head and at the clean
    # base checkpoint 5297d1c (see the change record, §8):
    # 6 permit_rejected, 2 approval_rejected, 2 denied
    # decisions, 10 near-misses, 0 incidents.

    def test_step7_incident_channel_surfaces_the_campaign(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        execute_permit = self._issue_permit(
            self.kernel, EXECUTE_INTENT, approval_id="approval-execute", nonce="nonce-execute"
        )
        sync_permit = self._issue_permit(
            self.kernel,
            SYNC_INTENT,
            approval_id="approval-sync",
            nonce="nonce-sync",
        )
        other_permit = self._issue_permit(
            self.kernel,
            APPROVED_EXECUTE_INTENT,
            approval_id="approval-other",
            nonce="nonce-other",
        )
        # The campaign, compressed: the execution attempted
        # on every route the handler has -- its own say-so,
        # the trusted channel as a token, the benign
        # permit, the other command's permit, and mutated
        # bytes under the genuine permit.
        self.kernel.evaluate(EXECUTE_INTENT)
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, CHANNEL_TOKEN, CLOUD_COMMAND_BYTES)
        )
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, sync_permit, CLOUD_COMMAND_BYTES)
        )
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, other_permit, CLOUD_COMMAND_BYTES)
        )
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, execute_permit, MUTATED_COMMAND_BYTES)
        )
        forged_envelope = signed_envelope(
            self.kernel,
            EXECUTE_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(EXECUTE_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 6's second attempt, also replayed: the
        # genuine sync envelope presented for the execution
        # intent. A real approval for a benign act is not
        # approval for execution; the decision is a denial
        # and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            SYNC_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(EXECUTE_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate execution still lands; the
        # campaign did not.
        self.assertTrue(
            self.executor.dispatch_command(self.kernel, execute_permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES))],
            self.executor.effects,
        )
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for
        # the same execution and re-aimed at the benign
        # act. A consumed permit is not a reusable channel
        # credential; both re-presentations are rejected at
        # consume.
        self.assertFalse(
            self.executor.dispatch_command(self.kernel, execute_permit, CLOUD_COMMAND_BYTES)
        )
        self.assertFalse(self.executor.execute(self.kernel, execute_permit, SYNC_INTENT))
        self.assertEqual(
            [("execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES))],
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
        # the store's binding: the cloud command EXECUTES
        # under a permit issued for a benign configuration
        # sync. That is the incident's own shape -- a
        # handler that runs what the trusted channel
        # delivers because the channel exists. The denials
        # in the steps above therefore come from the real
        # consume path's binding checks, not from a harness
        # that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_permit(blind_kernel, SYNC_INTENT)
        self.assertTrue(
            self.executor.dispatch_command(blind_kernel, permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual(
            [("execute_shell_command", _command_resource(CLOUD_COMMAND_BYTES))],
            self.executor.effects,
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route).
        real_permit = self._issue_permit(self.kernel, SYNC_INTENT)
        real_executor = DeviceAgentExecutor()
        self.assertFalse(
            real_executor.dispatch_command(self.kernel, real_permit, CLOUD_COMMAND_BYTES)
        )
        self.assertEqual([], real_executor.effects)


if __name__ == "__main__":
    unittest.main()

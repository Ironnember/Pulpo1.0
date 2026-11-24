"""Scenario test: the ConnectWise ScreenConnect
CVE-2026-84869 technician exploitation (disclosed
2026-09-08; exploitation observed 2026-10-20 to
2026-11-16).

Incident (Recorded, from Huntress's primary reporting of
its own telemetry and server-database observations, and
from ConnectWise's advisory as quoted there):
CVE-2026-84869 (CVSS 9.9, disclosed by ConnectWise
2026-09-08; added to CISA's Known Exploited
Vulnerabilities catalog 2026-09-11) -- in both Support
and Access sessions, a guest could trigger file-transfer
actions that the technician's host client processed
without authorization or confirmation, including running
the transferred file with elevated rights. ConnectWise
listed 26.6.5 as the fixed version for host clients and
Access agents, and recommended removing the
``TransferFiles`` permission as an interim mitigation.

Across 42 MSP ScreenConnect servers between 2026-10-20
and 2026-11-16, attacker guests made 688,000 "run file"
requests for files named ``update.bat`` or
``update_<8 hex>.bat`` from 29 source IP addresses,
repeatedly, in case a technician happened to join. On
2026-11-12 a technician used their host client to join a
blank-named Access session; at 16:46:20.7 UTC the host
client ran a guest-pushed ``update_224ac089.bat``, and
within about nine seconds the script had reported the
new victim to a Telegram bot, downloaded an installer
from masterdarky[.]com, and started a rebranded
ScreenConnect client connected to the attacker's relay.
From the technician's view, no prompt appeared: they
only had to join the session. Huntress also recorded a
canary push (``marker.txt``, 2026-11-13), path-traversal
pushes aimed at a technician's Startup folder (October),
and an October 19 near-miss in which the closest push
arrived 4.3 seconds after the technician disconnected.
This campaign is distinct from the SCKit / rogue-client
wave Huntress reported separately; SCKit appears to
leverage a vulnerable third-party server-side extension,
not CVE-2026-84869 directly.

The failure is an authorization failure at the dispatch
boundary: an established, trusted session was treated as
authorization for a specific act. The guest's request
arrived over a channel the host client already trusted,
so the host client executed it -- no per-act
authorization, no confirmation, no binding between
whatever the session was for and the file it was asked
to run. A session is evidence that two endpoints are
connected. It is not a permit, and it names no act.

This module models that failure mode against the
canonical kernel API. It does NOT reproduce
ScreenConnect, any session protocol, any network
behavior, or the incident's payload. The guest-pushed
file is represented by inert stand-in bytes held by this
harness; the file's identity in every intent is the
SHA-256 digest of the bytes actually presented at
dispatch time, derived by the dispatch boundary itself
-- never a caller-supplied name, because the incident's
file names (``update.bat``, ``update_<8 hex>.bat``, a
Startup-folder traversal path) were attacker-chosen
decoration. The only route from a run request to a
consequence is a successful ``GovernanceKernel.consume``
of a permit bound to the exact intent hash: principal,
action, the file's digest, cost, session.

Setup: exactly one run is legitimate in this scenario --
a technician-approved diagnostic file, run once, under a
permit issued through a verified approval envelope: the
accountable per-action authorization actually granted.
The incident's act is then attempted on every route the
host client has: with no permit at all, with the
established session itself presented as the permit, with
a genuine permit for a benign session action on the same
file (transfer it -- not run it), with a genuine run
permit for a different file, with the genuine run permit
for the incident's file presented against mutated bytes,
and with forged and mismatched approval envelopes. The
kernel must deny each one, the consequence ledger must
stay empty for all of them, and every denial must land
in the audit record. A correctly scoped run permit for
the incident's exact file bytes authorizes exactly one
execution and then spends.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules):
the derived incident report turns ``permit_rejected``
events, ``approval_rejected`` events, and denied
decisions into near-miss records. A bare ``evaluate``
that returns ``require_approval`` -- the kernel declining
to mint without approval -- appends a decision record to
the canonical audit but is NOT derived as a near-miss by
the channel. The scenario asserts both halves of that
statement exactly as they hold; it does not smooth the
second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any deployed remote-support product
that does not route its run-file dispatch through this
kernel -- a host client that executes first and asks
never (or asks the session, which is not an authorizer)
is governed by nothing here. The replay models the
authorization step the host client skipped, not
ScreenConnect internals. A control not on the execution
path governs nothing.

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
# The technician's host client: the executor the guest's
# request is aimed at. Every intent below is an act this
# client would perform; the guest proposes, the client
# must not execute without a permit bound to the act.
HOST = "agent:screenconnect-host-client"
# The blank-named Access session of 2026-11-12, in the
# harness's naming. Session identity is part of the bound
# intent; it is not itself authority for anything.
SESSION = "access-session-2026-11-12"

# The files, as inert stand-in bytes. No byte here is the
# incident's payload; the bytes exist so the dispatch
# boundary can derive the file identity from the bytes
# actually presented, the way the kernel's binding
# requires -- a name can be re-typed, a digest cannot be
# argued with.
#
# The one file a run was actually approved for: a known
# diagnostic script the technician meant to run.
APPROVED_FILE_BYTES = (
    b"stand-in bytes: the approved diagnostic script\r\n"
)
# The incident's file: guest-pushed, sprayed in volume,
# named update_<8 hex>.bat by its sender.
GUEST_FILE_BYTES = b"guest-pushed batch file stand-in bytes, wave AAAA"
# The same presentation with its bytes mutated after the
# fact: same length, different bytes. Under a name-based
# identity this would pass as the approved file; under
# the digest it is a different file and a different
# intent.
MUTATED_FILE_BYTES = b"guest-pushed batch file stand-in bytes, wave BBBB"


def _file_digest(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def _file_resource(file_bytes: bytes) -> str:
    return f"screenconnect:file/sha256:{_file_digest(file_bytes)}"


APPROVED_DIGEST = _file_digest(APPROVED_FILE_BYTES)
GUEST_DIGEST = _file_digest(GUEST_FILE_BYTES)

# The incident's act: run the guest-pushed file. The
# resource identity names the exact bytes, so this intent
# is this file and no other.
RUN_INTENT = Intent(HOST, "run_file", _file_resource(GUEST_FILE_BYTES), 25, SESSION)
# The benign session action on the same file: transfer it
# (receive it into the session's temp area) without
# running it. A session may legitimately move files; the
# incident is that moving one was allowed to become
# running one with no authorization step in between.
TRANSFER_INTENT = Intent(
    HOST, "transfer_file", _file_resource(GUEST_FILE_BYTES), 25, SESSION
)
# A run of a different file: the approved diagnostic
# script. A permit for this run is genuine authority --
# for this file.
APPROVED_RUN_INTENT = Intent(
    HOST, "run_file", _file_resource(APPROVED_FILE_BYTES), 25, SESSION
)

# The established session itself, presented as if it were
# a permit. The session is real, trusted, and fully
# established -- and it is not an approval envelope, not
# ceremony evidence, and not a permit. The kernel must
# treat this string as a fabricated token, because as
# authority for the run that is what it is.
SESSION_TOKEN = "screenconnect:established-session-2026-11-12"


class SessionExecutor:
    """Consequences on the technician's workstation, reachable only via consume.

    This is the scenario's execution path -- the dispatch
    boundary the incident's host client did not have. The
    harness records an effect only when the kernel
    consumes a permit for the exact intent. A denial is
    therefore directly observable as the absence of a
    governed external consequence, not merely as a
    returned status. (The denial itself still appends an
    audit record -- a governed effect, classified
    separately in the module docstring.)
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

    def dispatch_run(self, kernel: GovernanceKernel, permit: str | None, file_bytes: bytes) -> bool:
        """Run a presented file: the intent is derived from the bytes.

        The dispatcher derives the file's digest from the
        bytes actually presented at dispatch time and
        submits the act those bytes constitute. A permit
        issued for other bytes -- the same name, an earlier
        wave, a mutated copy -- therefore cannot spend
        here, because the intent it was bound to is not
        the intent these bytes produce.
        """
        intent = Intent(HOST, "run_file", _file_resource(file_bytes), 25, SESSION)
        return self.execute(kernel, permit, intent)


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued,
    unspent permit spends for any intent. It exists only
    to prove the scenario's denial assertions discriminate
    -- under this double the guest-pushed run must
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
    intent, so the guest-pushed run must EXECUTE here
    under a permit issued for a benign transfer. This is
    the incident's own shape: a host client that runs
    what the session delivers because the session exists.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class ScreenConnectIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"run_file", "transfer_file"}),
            10_000,
            frozenset({"run_file", "transfer_file"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.executor = SessionExecutor()

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

    def test_positive_control_approved_run_executes_exactly_once(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_RUN_INTENT)
        # The one legitimate run: the approved diagnostic
        # file, dispatched by its bytes, executes once.
        self.assertTrue(self.executor.dispatch_run(self.kernel, permit, APPROVED_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(APPROVED_FILE_BYTES))], self.executor.effects
        )
        # The same permit cannot run the same file twice --
        # an approval to run a file is not a standing one.
        self.assertFalse(self.executor.dispatch_run(self.kernel, permit, APPROVED_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(APPROVED_FILE_BYTES))], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: no permit; the trusted session is not one -----------------

    def test_step1_run_without_permit_denied_trusted_session_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for running the guest-pushed file, and the
        # session's existence is not one.
        decision = self.kernel.evaluate(RUN_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.executor.dispatch_run(self.kernel, decision.permit, GUEST_FILE_BYTES))
        # The host client presents the established session
        # itself as its authority -- the incident's exact
        # move. The session is genuine and trusted; as a
        # permit it is a fabricated token, and the kernel
        # treats it as one. The file is never executed.
        self.assertFalse(self.executor.dispatch_run(self.kernel, SESSION_TOKEN, GUEST_FILE_BYTES))
        self.assertEqual([], self.executor.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(RUN_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: a benign session permit does not authorize execution ------

    def test_step2_transfer_permit_does_not_authorize_the_run(self) -> None:
        permit = self._issue_permit(self.kernel, TRANSFER_INTENT)
        # Same session, same file, same principal -- a
        # different act. The permit authorizes receiving
        # the file; the guest's request is to run it, and
        # the transfer permit spends on the run not at all.
        # In the incident this distinction did not exist:
        # file-transfer machinery carried the run with it.
        self.assertFalse(self.executor.dispatch_run(self.kernel, permit, GUEST_FILE_BYTES))
        self.assertEqual([], self.executor.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(RUN_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit
        # still spends on the exact act it was issued for.
        self.assertTrue(self.executor.execute(self.kernel, permit, TRANSFER_INTENT))
        self.assertEqual(
            [("transfer_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: a run permit for a different file --------------------------

    def test_step3_run_permit_for_another_file_does_not_authorize_this_file(self) -> None:
        permit = self._issue_permit(self.kernel, APPROVED_RUN_INTENT)
        # A genuine run permit -- for the approved
        # diagnostic file. Presented at dispatch for the
        # guest-pushed bytes, the derived intent names a
        # different digest, and the permit spends on it not
        # at all. Authority to run a file is authority for
        # that file's bytes, not for the run-file verb.
        self.assertFalse(self.executor.dispatch_run(self.kernel, permit, GUEST_FILE_BYTES))
        self.assertEqual([], self.executor.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(RUN_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The permit still spends on the file it names.
        self.assertTrue(self.executor.dispatch_run(self.kernel, permit, APPROVED_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(APPROVED_FILE_BYTES))], self.executor.effects
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the exact permit authorizes exactly one execution ----------

    def test_step4_exact_permit_authorizes_exactly_one_execution(self) -> None:
        permit = self._issue_permit(self.kernel, RUN_INTENT)
        # A correctly scoped, live permit for the
        # guest-pushed file's exact bytes authorizes the
        # run -- once. (Whether such a permit should ever
        # be granted for a guest-pushed file is the
        # approver's judgment; the kernel's claim is
        # narrower: if granted, it is this act, this file,
        # one time.)
        self.assertTrue(self.executor.dispatch_run(self.kernel, permit, GUEST_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
        )
        # The spray's shape -- the same request repeated --
        # gets nothing from the spent permit, on the run
        # route or re-aimed at the benign act.
        self.assertFalse(self.executor.dispatch_run(self.kernel, permit, GUEST_FILE_BYTES))
        self.assertFalse(self.executor.execute(self.kernel, permit, TRANSFER_INTENT))
        self.assertEqual(
            [("run_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: mutated bytes under a genuine permit ------------------------

    def test_step5_mutated_bytes_denied_under_genuine_permit(self) -> None:
        permit = self._issue_permit(self.kernel, RUN_INTENT)
        # The permit names the guest file's digest. The
        # dispatch boundary is now presented with bytes of
        # the same length and nearly the same content --
        # a later wave of the same spray, or the same name
        # carrying different bytes. The derived intent is
        # a different intent, and the permit spends on it
        # not at all. No bytes exist in this scenario
        # outside the dispatch derivation, so altered bytes
        # cannot slip under a consumed permit while the
        # test passes.
        self.assertEqual(len(GUEST_FILE_BYTES), len(MUTATED_FILE_BYTES))
        self.assertNotEqual(GUEST_FILE_BYTES, MUTATED_FILE_BYTES)
        self.assertFalse(self.executor.dispatch_run(self.kernel, permit, MUTATED_FILE_BYTES))
        self.assertEqual([], self.executor.effects)
        mutated_intent = Intent(
            HOST, "run_file", _file_resource(MUTATED_FILE_BYTES), 25, SESSION
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(mutated_intent),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The genuine bytes still spend the permit.
        self.assertTrue(self.executor.dispatch_run(self.kernel, permit, GUEST_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: forged and mismatched approvals ----------------------------

    def test_step6_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, TRANSFER_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the run signed with an
        # unauthorized key: whoever controls the guest end
        # of a session cannot mint the technician's
        # authority.
        forged_envelope = signed_envelope(
            self.kernel, RUN_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(RUN_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine transfer envelope presented for
        # the run intent: a real approval for a benign act
        # is not approval for execution.
        decision = self.kernel.evaluate_with_approval(RUN_INTENT, genuine_envelope)
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
        decision = self.kernel.evaluate_with_approval(TRANSFER_INTENT, genuine_envelope)
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
    # and session-token routes (step 1), the benign-permit
    # route (step 2), the other-file permit route
    # (step 3), the mutated-bytes dispatch (step 5), both
    # approval-envelope attempts (step 6), the one
    # legitimate execution, and the spent-permit replays
    # (step 4). The report assertions therefore cover
    # every attack variant the scenario exercises.

    def test_step7_incident_channel_surfaces_the_spray_campaign(self) -> None:
        # Each envelope carries its own approval_id and
        # nonce, as each real approval would: the helper's
        # fixed defaults would collide across issuances and
        # turn a later denial into a replay denial,
        # misattributing the control that rejected it.
        run_permit = self._issue_permit(
            self.kernel, RUN_INTENT, approval_id="approval-run", nonce="nonce-run"
        )
        transfer_permit = self._issue_permit(
            self.kernel,
            TRANSFER_INTENT,
            approval_id="approval-transfer",
            nonce="nonce-transfer",
        )
        other_permit = self._issue_permit(
            self.kernel,
            APPROVED_RUN_INTENT,
            approval_id="approval-other",
            nonce="nonce-other",
        )
        # The campaign, compressed: the run attempted on
        # every route the host client has -- its own say-so,
        # the trusted session as a token, the benign permit,
        # the other file's permit, and mutated bytes under
        # the genuine permit.
        self.kernel.evaluate(RUN_INTENT)
        self.assertFalse(self.executor.dispatch_run(self.kernel, SESSION_TOKEN, GUEST_FILE_BYTES))
        self.assertFalse(self.executor.dispatch_run(self.kernel, transfer_permit, GUEST_FILE_BYTES))
        self.assertFalse(self.executor.dispatch_run(self.kernel, other_permit, GUEST_FILE_BYTES))
        self.assertFalse(self.executor.dispatch_run(self.kernel, run_permit, MUTATED_FILE_BYTES))
        forged_envelope = signed_envelope(
            self.kernel,
            RUN_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(RUN_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 6's second attempt, also replayed: the
        # genuine transfer envelope presented for the run
        # intent. A real approval for a benign act is not
        # approval for execution; the decision is a denial
        # and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            TRANSFER_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(RUN_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate execution still lands; the
        # campaign did not.
        self.assertTrue(self.executor.dispatch_run(self.kernel, run_permit, GUEST_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
        )
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for
        # the same run and re-aimed at the benign act. A
        # consumed permit is not a reusable session
        # credential; both re-presentations are rejected at
        # consume.
        self.assertFalse(self.executor.dispatch_run(self.kernel, run_permit, GUEST_FILE_BYTES))
        self.assertFalse(self.executor.execute(self.kernel, run_permit, TRANSFER_INTENT))
        self.assertEqual(
            [("run_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
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
        # the store's binding: the guest-pushed run EXECUTES
        # under a permit issued for a benign transfer. That
        # is the incident's own shape -- a host client that
        # runs what an established session delivers because
        # the session is trusted. The denials in the steps
        # above therefore come from the real consume path's
        # binding checks, not from a harness that denies by
        # construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_permit(blind_kernel, TRANSFER_INTENT)
        self.assertTrue(self.executor.dispatch_run(blind_kernel, permit, GUEST_FILE_BYTES))
        self.assertEqual(
            [("run_file", _file_resource(GUEST_FILE_BYTES))], self.executor.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route).
        real_permit = self._issue_permit(self.kernel, TRANSFER_INTENT)
        real_executor = SessionExecutor()
        self.assertFalse(real_executor.dispatch_run(self.kernel, real_permit, GUEST_FILE_BYTES))
        self.assertEqual([], real_executor.effects)


if __name__ == "__main__":
    unittest.main()

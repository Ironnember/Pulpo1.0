"""Scenario test: the Vinci RAT intrusion delivered through a
genuine Microsoft Store app (eSentire Threat Response Unit
report published 2026-11-24).

Incident (Recorded, from eSentire's TRU report): analysts
investigating an intrusion in early November 2026 found
that a Windows user searching for a screenshot tool had
been directed to a fake download page that served
``Snipping-Tool.exe``, a Microsoft-signed installer. The
installer did not install a snipping tool; it directed the
user to ``Setup Assistant``, a genuine Microsoft Store app
published by ETPS Ltd. and built with Electron -- package
metadata indicated a June 1, 2026 release (Recorded);
eSentire suggests from that date that the app remained
available for at least five months -- a continuous
listing over that span is Inferred from the release
metadata, not a listing record.
Once installed, Setup Assistant contacted a
command-and-control server, monitored the Downloads folder
for specific filenames, and could run PowerShell or
JavaScript supplied by the server. In the investigated
intrusion, that access launched a PowerShell loader that
retrieved Vinci RAT from a separate domain; the loader
also bypassed AMSI and created a Windows scheduled task
that ran every 10 minutes, so the malware could return
without the user reopening the app. Vinci RAT gathered
host and security-tool information and supported a reverse
shell -- an outbound connection giving the operator an
interactive command prompt. eSentire isolated the affected
computer and helped the customer respond; the report
documents that one intrusion and does not establish how
many other Windows PCs were infected (Unknown). eSentire
also records that Microsoft initially replied, through the
Store's abuse form, that the app did not violate its terms;
whether the listing was later removed is not established
(Unknown).

The failure is trusted-path execution abuse, one step
further along than a lookalike page: the channel itself
was genuine. A valid signature on the installer and a real
listing in the Store attest that an artifact is what its
publisher shipped and arrived unaltered -- provenance and
integrity evidence. They attest nothing about what the
artifact may do once installed. Installing the app was the
only act the channel's attestation could even arguably
cover. Executing server-supplied PowerShell and JavaScript,
bypassing the antimalware scan interface, registering a
recurring scheduled task, and opening a reverse shell are
separate consequential acts, and no authorization for any
of them existed. Channel attestation is not act
authorization:
``TRUSTED_CHANNEL != AUTHORIZATION_FOR_THE_ACTS_IT_CARRIES``.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the app, the installer,
any Store behavior, any network behavior, the RAT, or any
Windows behavior. The "app" is this harness holding intents;
the only route from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash. A store artifact -- the signed installer, the
genuine listing, the app's inferred five months of listed
presence -- is modeled as exactly what it is in Pulpo's
terms: evidence
that an artifact arrived over a trusted channel. It is not
an approval envelope, not ceremony evidence, and not a
permit, and the kernel has no verb that derives execution
authority from an artifact having been signed, listed,
downloaded, or left listed.

Setup: the app holds exactly one legitimate permit: one
exact act -- installing the app's declared package, the act
the install was actually for -- issued through a verified
approval envelope: the accountable per-action authorization
actually granted. The incident's acts are then attempted,
in sequence: executing the server-supplied PowerShell,
executing the server-supplied JavaScript, opening the
reverse shell, registering the recurring scheduled task,
bypassing AMSI, and the permitted install re-presented with
its scope widened to cover the script execution. The kernel
must deny each one, the consequence ledger must stay empty
for all of them, and every denial must land in the audit
record. Reconciliation over that record keeps the two kinds
of fact separate: the artifact's trusted-channel record is
evidence of arrival, and the only authorized acts in the
record are consumed permits -- the channel's attestation
never appears as, and never converts into, an authority
event.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules): the
derived incident report turns ``permit_rejected`` events,
``approval_rejected`` events, and denied decisions into
near-miss records. A bare ``evaluate`` that returns
``require_approval`` -- the kernel declining to mint without
approval -- appends a decision record to the canonical audit
but is NOT derived as a near-miss by the channel. The scenario
asserts both halves of that statement exactly as they hold;
it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any store, installer, or host that does
not route its installs and the installed app's acts through
this kernel -- an execution path that runs whatever a listed
app attempts, because the app arrived signed and listed, is
governed by nothing here. A control not on the execution
path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is permitted,
and any non-kernel install or execution path (the incident's
own class) remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." A denied attempt appends audit records, counted
per route: a bare evaluate returning ``require_approval``
appends one decision record; a ``consume`` rejection
appends one ``permit_rejected`` record; a denied
approval-envelope evaluation appends two records -- an
``approval_rejected`` record and a denied decision record.
That growth is itself a governed effect --
evidence production -- bounded at two records per attempt,
append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. It is
classified and assessed separately from governed external
consequences throughout this module: "consequence" below means
governed external consequence (the permitted consume recorded
in the consequence ledger), never audit growth.
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
APP = "agent:setup-assistant-store-app"
SESSION = "store-session-2026-11"
LATER_SESSION = "store-session-2026-11-later"
ACTIONS = frozenset(
    {
        "install_app",
        "execute_script",
        "open_reverse_shell",
        "register_scheduled_task",
        "tamper_security_control",
    }
)

# The one act actually authorized: installing the app's
# declared package -- the act the install was for, and
# nothing else. The resource identity names the exact
# publisher, app, and act scope; every act beyond it is a
# different resource or a different action and therefore a
# different intent.
INSTALL_RESOURCE = "microsoft-store:etps-ltd/setup-assistant/declared-package"
INSTALL_INTENT = Intent(APP, "install_app", INSTALL_RESOURCE, 25, SESSION)

# The incident's acts. None of them has an approval; each ran
# in the incident because the app arrived signed and listed,
# not because any of them was authorized.
POWERSHELL_INTENT = Intent(
    APP,
    "execute_script",
    "c2:setup-assistant.com/powershell-loader",
    25,
    SESSION,
)
JAVASCRIPT_INTENT = Intent(
    APP,
    "execute_script",
    "c2:setup-assistant.com/javascript-payload",
    25,
    SESSION,
)
SHELL_INTENT = Intent(
    APP,
    "open_reverse_shell",
    "c2:monkeysholder.info/vinci-reverse-shell",
    25,
    SESSION,
)
PERSISTENCE_INTENT = Intent(
    APP,
    "register_scheduled_task",
    "schtasks:every-10-minutes/vinci-loader",
    25,
    SESSION,
)
AMSI_INTENT = Intent(
    APP,
    "tamper_security_control",
    "amsi:process/bypass",
    25,
    SESSION,
)
# The permitted install with its scope widened to cover the
# script execution -- the incident's implicit claim, that
# authorizing the install authorized what the installed app
# then did. The widening rides in the resource identity,
# inside the hashed intent, so it cannot pass as the
# approved install.
WIDENED_INTENT = Intent(
    APP,
    "install_app",
    "microsoft-store:etps-ltd/setup-assistant/declared-package/scope-include-script-execution",
    25,
    SESSION,
)
OUT_OF_SCOPE_INTENTS = (
    POWERSHELL_INTENT,
    JAVASCRIPT_INTENT,
    SHELL_INTENT,
    PERSISTENCE_INTENT,
    AMSI_INTENT,
    WIDENED_INTENT,
)

# The channel artifact, presented as if it were a permit:
# the installer was Microsoft-signed and the app genuinely
# listed in the Store. Reaching the host over a trusted
# channel is not authority for the acts the app carries; the
# kernel must treat this string as a fabricated token,
# because that is what it is.
CHANNEL_TOKEN = "microsoft-store-signed-listing:etps-ltd/setup-assistant"

# The app's listing record -- the June 1, 2026 release
# metadata eSentire recorded, with continuous availability
# since then Inferred (eSentire's suggestion from that
# date, not a listing record) -- presented in a later
# session as if five months of trusted presence were
# standing authority. A track record is not an approval
# envelope and never was one; that the channel kept the
# app listed changes nothing about what the record is.
TRUST_RECORD_TOKEN = "microsoft-store:listing-record-etps-ltd-setup-assistant-since-2026-06-01"


class ConsequenceLedger:
    """Effects on the host, reachable only through a successful consume.

    This is the scenario's execution path: the harness executes
    an action (records its consequence) only when the kernel
    consumes a permit for that exact intent. A denial is
    therefore directly observable as the absence of a governed
    external consequence, not merely as a returned status. (The
    denial itself still appends an audit record -- a governed
    effect, classified separately in the module docstring.)
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


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent
    permit spends for any intent. It exists only to prove the
    scenario's denial assertions discriminate -- under this
    double the script execution must EXECUTE, or the
    scenario would be denying by construction rather than by
    the kernel's binding.
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
    token-to-intent binding -- and delegates straight to the
    state. Paired with the intent-blind state double above, no
    layer binds the permit to the presented intent, so the
    script execution must EXECUTE here, or the
    scenario's denials would be coming from the harness rather
    than from the binding layers. This is the incident's own
    shape: an execution path that runs whatever a listed app
    attempts because the app arrived signed and listed.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class VinciMicrosoftStoreIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()

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

    def _issue_install_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, INSTALL_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(INSTALL_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_install_executes_exactly_once(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same install twice --
        # an install authorization is not a standing one.
        self.assertFalse(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the script execution has no permit --------------------

    def test_step1_script_execution_denied_channel_attestation_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for executing the server-supplied PowerShell,
        # and the app's arrival signed and listed is not one.
        # Running a script the C2 server supplies is a separate
        # consequential act from the install that delivered
        # the app.
        decision = self.kernel.evaluate(POWERSHELL_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, POWERSHELL_INTENT))
        # The harness presents the channel artifact itself as
        # the permit: the installer was Microsoft-signed, the
        # listing genuine. The kernel treats it as what it is:
        # a fabricated token. The channel attested the app's
        # provenance in the incident; authority for this act
        # did not exist.
        self.assertFalse(self.ledger.execute(self.kernel, CHANNEL_TOKEN, POWERSHELL_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(POWERSHELL_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: both script payloads under the genuine permit -----------------

    def test_step2_script_payloads_with_install_permit_denied(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        # The app's next acts in the incident: running the
        # PowerShell loader and the JavaScript the C2 server
        # supplied. A different action against a different
        # resource is a different intent, and the one permit
        # the app holds binds the declared install exactly --
        # it does not care which script language the payload
        # arrives in.
        for intent in (POWERSHELL_INTENT, JAVASCRIPT_INTENT):
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(POWERSHELL_INTENT),
                self.kernel.intent_hash(JAVASCRIPT_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still
        # spends on the exact install it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: shell, persistence, tampering, and the widened install

    def test_step3_shell_persistence_tampering_and_widened_install_denied(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        # The rest of the incident's chain: the reverse shell
        # to the RAT's server, the scheduled task that brought
        # the loader back every 10 minutes, the AMSI bypass
        # that blinded the scanner the scripts ran under, and
        # the permitted install re-presented with its scope
        # widened to cover the script execution. Each is a
        # different intent from the approved install, and the
        # one permit spends on none of them. The widened
        # install is the incident's core claim -- that the
        # install's authorization covered what the installed
        # app then did.
        for intent in (SHELL_INTENT, PERSISTENCE_INTENT, AMSI_INTENT, WIDENED_INTENT):
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(4, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(SHELL_INTENT),
                self.kernel.intent_hash(PERSISTENCE_INTENT),
                self.kernel.intent_hash(AMSI_INTENT),
                self.kernel.intent_hash(WIDENED_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denials did not burn the permit: the exact
        # approved install still spends.
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing -------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        # A consumed permit is not a reusable channel
        # credential: re-presenting it for the same install
        # gets nothing, and re-presenting it for the script
        # execution gets nothing either.
        self.assertFalse(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, POWERSHELL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals -------------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, INSTALL_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the script execution signed with
        # an unauthorized key: whoever published the app
        # cannot mint the host owner's authority -- a valid
        # store signature on the artifact is not this
        # signature, and does not substitute for it.
        forged_envelope = signed_envelope(
            self.kernel, POWERSHELL_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(POWERSHELL_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine install envelope presented for the
        # script intent: a real approval for one act is not
        # approval for the acts the app attempted under cover
        # of it.
        decision = self.kernel.evaluate_with_approval(POWERSHELL_INTENT, genuine_envelope)
        self.assertEqual(
            ("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        }
        self.assertEqual(
            {"approval_signature_invalid", "approval_intent_mismatch"},
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine pair
        # still admits.
        decision = self.kernel.evaluate_with_approval(INSTALL_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign ------------------------
    #
    # Surfacing, asserted exactly as it holds at this commit:
    # every consume rejection, every approval rejection, and
    # every denied decision in the sequence becomes a near-miss
    # record in the derived incident report. The bare
    # require_approval decisions are in the canonical audit (and
    # counted below) but are NOT derived as near-misses -- the
    # expected near-miss count is built from the event classes
    # the channel actually derives, so this test pins the
    # boundary instead of papering over it.
    #
    # The frozen sequence below is the full attempt sequence of
    # steps 1-5, not a subset: every out-of-scope act on every
    # route (steps 1-3), the spent-permit replays (step 4,
    # replayed after the one legitimate execution below), and
    # both approval-envelope attempts -- the forged envelope
    # and the genuine envelope presented for the wrong intent
    # (step 5). The report assertions therefore cover every
    # attack variant the scenario exercises.
    #
    # The same freeze is the reconciliation the incident never
    # had: read over the whole record, the app's trusted
    # artifact status appears nowhere as an authority event,
    # and the single permit_consumed in the audit binds the
    # exact install -- the record separates "the artifact was
    # trusted by the channel" from "this act was authorized,"
    # and the two never merge.

    def test_step6_incident_channel_surfaces_the_store_campaign(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        # The campaign, compressed: each out-of-scope act
        # attempted on every route the harness has -- its own
        # say-so, the channel artifact as a token, and the one
        # genuine permit.
        for intent in OUT_OF_SCOPE_INTENTS:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(CHANNEL_TOKEN, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        # Each envelope in this compressed sequence carries its
        # own approval_id and nonce, as each real approval
        # would: the helper's fixed defaults would collide with
        # the permit issuance above and turn the forgery denial
        # below into a replay denial, misattributing the
        # control that rejected it.
        forged_envelope = signed_envelope(
            self.kernel,
            POWERSHELL_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(POWERSHELL_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the genuine
        # install envelope presented for the script intent. A
        # real approval for one act is not approval for another;
        # the decision is a denial and the rejection lands in
        # the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            INSTALL_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(POWERSHELL_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate install still executes; the
        # campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for the
        # same install and for the script execution. A consumed
        # permit is not a reusable channel credential; both
        # re-presentations are rejected at consume.
        self.assertFalse(self.kernel.consume(permit, INSTALL_INTENT))
        self.assertFalse(self.kernel.consume(permit, POWERSHELL_INTENT))
        self.assertEqual([("install_app", INSTALL_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends
        # nothing.
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertTrue(report.audit_valid)
        self.assertEqual(0, report.incidents)
        # Reconciliation: exactly one act in the entire record
        # was authorized -- the exact install, consumed once.
        # Every trusted-artifact presentation (the signed,
        # listed app; the channel token) produced rejections,
        # never an authority event.
        consumed = _events(self.kernel, "permit_consumed")
        self.assertEqual(1, len(consumed))
        self.assertEqual(
            self.kernel.intent_hash(INSTALL_INTENT),
            consumed[0]["payload"]["intent_hash"],
        )

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
        self.assertEqual(14, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(6, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. The
        # six require_approval decisions above are
        # audit-recorded attempts that contribute zero near-miss
        # records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(18, report.near_misses)
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

    # -- step 7: the listing record is not standing authority -----------------
    #
    # The incident's quietest mechanism: nothing about the app
    # changed between June and November. On eSentire's
    # inference from the June 1 release metadata, it sat in
    # the Store, listed and trusted, for about five months --
    # and when eSentire reported it, the channel's first
    # answer was that it violated no terms. A long, uneventful
    # listing is a record about the artifact, not an approval
    # of its acts. In a later session on a fresh kernel, the
    # listing record presented as authority for the reverse
    # shell mints exactly as much as it should: none -- it is
    # not a permit, was never issued by the host owner, and
    # its inferred five months of trusted presence change
    # nothing about what it is.

    def test_step7_listing_record_is_not_standing_authority(self) -> None:
        later_shell = Intent(
            APP, "open_reverse_shell", SHELL_INTENT.resource, 25, LATER_SESSION
        )
        fresh = self._kernel()
        fresh_ledger = ConsequenceLedger()
        decision = fresh.evaluate(later_shell)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(fresh_ledger.execute(fresh, TRUST_RECORD_TOKEN, later_shell))
        self.assertEqual([], fresh_ledger.effects)
        self.assertEqual(0, len(_events(fresh, "permit_consumed")))
        self.assertEqual(1, len(_events(fresh, "permit_rejected")))
        self.assertTrue(fresh.verify_audit())

    # -- negative control --------------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a
        # kernel double whose consume skips token authentication
        # and the kernel's token-to-intent binding, over a state
        # double whose consume ignores the store's binding: the
        # script execution EXECUTES under the install permit.
        # That is the incident's own shape -- an execution path
        # that runs whatever a listed app attempts because the
        # app arrived signed and listed. The denials in the
        # steps above therefore come from the real consume
        # path's binding checks, not from a harness that denies
        # by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_install_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, POWERSHELL_INTENT))
        self.assertEqual(
            [("execute_script", POWERSHELL_INTENT.resource)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route, here with the script
        # execution).
        real_permit = self._issue_install_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, POWERSHELL_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

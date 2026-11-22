"""Scenario test: the @leadstack/crm-connect npm postinstall
agent backdoor (published 2026-11-16; SafeDep investigation
published 2026-11-19).

Incident (Recorded, from SafeDep's investigation): the npm
account ``zmaticoo`` published nine versions of
``@leadstack/crm-connect`` on 2026-11-16 (1.0.15, 1.0.18,
1.0.19, 1.0.20, 1.0.21, 1.0.29, 1.0.30, 1.1.0 and 1.1.1,
between 09:44 and 15:27 UTC). The package described itself
as the "Official LeadStack CRM client"; the CRM it claimed
to serve does not exist -- its documentation pointed at
``api.leadstack.io``, a host that does not resolve, and the
``leadstack.io`` domain belongs to an unrelated business
consultancy. Version 1.0.15 declared a postinstall script
(``node ./bin/postinstall.js``) that ran a provisioning
script which, in sequence: fetched the agent's ``.env``
file -- its keys, including a Telegram bot token and a
model key -- and its ``SOUL.md`` standing instructions from
an attacker-controlled server; installed Hermes Agent (an
open-source agent from Nous Research, via the
``hermes-agent@0.22.7`` npm wrapper) with a hidden nested
``npm install``; connected the agent to the attacker's
Telegram bot; and registered the agent's gateway as a root
systemd service (``--system --run-as-user root``), then
renamed the unit to "LeadStack Lead Routing Daemon"
(``leadstack-routing.service``) and deleted the original
unit file, so the host's service list showed a CRM daemon.
Later versions changed the delivery -- the payload moved
to the first SDK call, then to a JavaScript module or a
binary downloaded from the same server at install or run
time -- but the server and the shape stayed the same.
SafeDep flagged the package at 15:33 UTC and npm has since
removed it. SafeDep states the Hermes Agent and its npm
wrapper are not themselves malicious; the package used
them the way an administrator would, without asking the
owner of the machine. No confirmed victims were reported;
the targeting SafeDep describes is inferred from the lures
and the payload design (Unknown beyond that).

The failure is trusted-path execution abuse: ``npm install``
is a trusted channel, and everything the postinstall script
did rode on that trust. The installer's act -- fetching and
placing the package's declared files -- was the only act
the channel's trust could even arguably cover. Executing
the postinstall script, fetching keys and standing
instructions from an external server, and registering a
privileged system service are separate consequential acts,
and no authorization for any of them existed. Channel trust
is not act authorization:
``TRUSTED_CHANNEL != AUTHORIZATION_FOR_THE_ACTS_IT_CARRIES``.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the package, any npm
behavior, any network behavior, the Hermes Agent, or any
systemd behavior. The "installer" is this harness holding
intents; the only route from intent to consequence is a
successful ``GovernanceKernel.consume`` of a permit bound
to the exact intent hash. An npm registry artifact -- the
package's presence on a trusted registry, its download
integrity, its declared metadata -- is modeled as exactly
what it is in Pulpo's terms: evidence that a package
arrived over a trusted channel. It is not an approval
envelope, not ceremony evidence, and not a permit, and the
kernel has no verb that derives execution authority from a
package having been published, downloaded, or verified.

Setup: the installer holds exactly one legitimate permit:
one exact act -- installing the package's declared files,
the act the install was actually for -- issued through a
verified approval envelope: the accountable per-action
authorization actually granted. The incident's acts are
then attempted, in sequence: executing the postinstall
script, the script's outbound fetch of keys and standing
instructions from the attacker's server, registering the
privileged system service, and the permitted install
re-presented with its scope widened to cover the script
execution. The kernel must deny each one, the consequence
ledger must stay empty for all of them, and every denial
must land in the audit record.

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
proves nothing about any package manager, registry, or host
that does not route its installs through this kernel -- an
install path that runs whatever a package declares, because
the package arrived, is governed by nothing here. A control
not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is permitted,
and any non-kernel install path (the incident's own class)
remains outside this evidence and open.

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
INSTALLER = "agent:npm-installer"
SESSION = "install-session-2026-11-16"
LATER_SESSION = "install-session-2026-11-19"
ACTIONS = frozenset(
    {"install_package", "execute_script", "fetch_remote", "register_service"}
)

# The one act actually authorized: installing the package's
# declared files -- the act the install was for, and nothing
# else. The resource identity names the exact package version
# and the exact act scope; every act beyond it is a different
# resource or a different action and therefore a different
# intent.
INSTALL_RESOURCE = "npm:@leadstack/crm-connect@1.0.15/declared-files"
INSTALL_INTENT = Intent(INSTALLER, "install_package", INSTALL_RESOURCE, 25, SESSION)

# The incident's acts. None of them has an approval; each ran
# in the incident because the install channel was trusted,
# not because any of them was authorized.
POSTINSTALL_INTENT = Intent(
    INSTALLER,
    "execute_script",
    "npm:@leadstack/crm-connect@1.0.15/postinstall",
    25,
    SESSION,
)
FETCH_INTENT = Intent(
    INSTALLER,
    "fetch_remote",
    "attacker-server:72.62.1.108/bootstrap-env-and-instructions",
    25,
    SESSION,
)
SERVICE_INTENT = Intent(
    INSTALLER,
    "register_service",
    "systemd:system/leadstack-routing.service",
    25,
    SESSION,
)
# The permitted install with its scope widened to cover the
# postinstall execution -- the incident's implicit claim,
# that authorizing the install authorized what the install
# carried. The widening rides in the resource identity,
# inside the hashed intent, so it cannot pass as the
# approved install.
WIDENED_INTENT = Intent(
    INSTALLER,
    "install_package",
    "npm:@leadstack/crm-connect@1.0.15/declared-files/scope-include-postinstall-execution",
    25,
    SESSION,
)
OUT_OF_SCOPE_INTENTS = (
    POSTINSTALL_INTENT,
    FETCH_INTENT,
    SERVICE_INTENT,
    WIDENED_INTENT,
)

# The registry artifact, presented as if it were a permit:
# the package was published on the trusted registry, its
# tarball downloaded intact. Reaching the host over a
# trusted channel is not authority for the acts the package
# carries; the kernel must treat this string as a fabricated
# token, because that is what it is.
CHANNEL_TOKEN = "npm-registry:@leadstack/crm-connect@1.0.15"

# The keys and standing instructions the script fetched from
# the attacker's server, presented in a later session as if
# they were a credential. Downloaded instructions are not an
# approval envelope and never were one; that they were
# fetched during the install changes nothing about what
# they are.
DOWNLOADED_TOKEN = "leadstack:downloaded-env-and-soul-md"


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
    double the postinstall execution must EXECUTE, or the
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
    postinstall execution must EXECUTE here, or the
    scenario's denials would be coming from the harness rather
    than from the binding layers. This is the incident's own
    shape: an install path that runs whatever a package
    declares because the package arrived.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class LeadstackIncidentScenarioTests(unittest.TestCase):
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
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same install twice --
        # an install authorization is not a standing one.
        self.assertFalse(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the postinstall execution has no permit --------------------

    def test_step1_postinstall_execution_denied_channel_trust_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for executing the postinstall script, and the
        # package's arrival over the install channel is not
        # one. The script is a separate consequential act from
        # the install that carried it.
        decision = self.kernel.evaluate(POSTINSTALL_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, POSTINSTALL_INTENT))
        # The harness presents the registry artifact itself as
        # the permit: the package was published, downloaded,
        # intact. The kernel treats it as what it is: a
        # fabricated token. The channel was trusted in the
        # incident; authority for this act did not exist.
        self.assertFalse(self.ledger.execute(self.kernel, CHANNEL_TOKEN, POSTINSTALL_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(POSTINSTALL_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the outbound fetch under the genuine permit -----------------

    def test_step2_outbound_fetch_with_install_permit_denied(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        # The script's next act in the incident: fetching the
        # agent's keys and standing instructions from the
        # attacker's server. A different action against a
        # different resource is a different intent, and the
        # one permit the installer holds binds the declared
        # install exactly.
        self.assertFalse(self.ledger.execute(self.kernel, permit, FETCH_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(FETCH_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still
        # spends on the exact install it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: persistence and the widened install under the genuine permit

    def test_step3_service_registration_and_widened_install_denied(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        # Registering a privileged system service -- the
        # incident's persistence, the agent renamed as a CRM
        # daemon and set to outlive the install -- and the
        # permitted install re-presented with its scope widened
        # to cover the postinstall execution: each is a
        # different intent from the approved install, and the
        # one permit spends on neither. The widened install is
        # the incident's core claim -- that the install's
        # authorization covered what the install carried.
        for intent in (SERVICE_INTENT, WIDENED_INTENT):
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(SERVICE_INTENT),
                self.kernel.intent_hash(WIDENED_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denials did not burn the permit: the exact
        # approved install still spends.
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing -------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        # A consumed permit is not a reusable channel
        # credential: re-presenting it for the same install
        # gets nothing, and re-presenting it for the
        # postinstall execution gets nothing either.
        self.assertFalse(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, POSTINSTALL_INTENT))
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals -------------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, INSTALL_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the postinstall execution signed
        # with an unauthorized key: whoever published the
        # package cannot mint the host owner's authority.
        forged_envelope = signed_envelope(
            self.kernel, POSTINSTALL_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(POSTINSTALL_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine install envelope presented for the
        # postinstall intent: a real approval for one act is
        # not approval for the act the package smuggled in
        # under it.
        decision = self.kernel.evaluate_with_approval(POSTINSTALL_INTENT, genuine_envelope)
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

    def test_step6_incident_channel_surfaces_the_install_campaign(self) -> None:
        permit = self._issue_install_permit(self.kernel)
        # The campaign, compressed: each out-of-scope act
        # attempted on every route the harness has -- its own
        # say-so, the registry artifact as a token, and the one
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
            POSTINSTALL_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(POSTINSTALL_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the genuine
        # install envelope presented for the postinstall
        # intent. A real approval for one act is not approval
        # for another; the decision is a denial and the
        # rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            INSTALL_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(POSTINSTALL_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate install still executes; the
        # campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, INSTALL_INTENT))
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for the
        # same install and for the postinstall execution. A
        # consumed permit is not a reusable channel credential;
        # both re-presentations are rejected at consume.
        self.assertFalse(self.kernel.consume(permit, INSTALL_INTENT))
        self.assertFalse(self.kernel.consume(permit, POSTINSTALL_INTENT))
        self.assertEqual([("install_package", INSTALL_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends
        # nothing.
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
        self.assertEqual(10, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(4, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. The
        # four require_approval decisions above are
        # audit-recorded attempts that contribute zero near-miss
        # records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(14, report.near_misses)
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

    # -- step 7: the downloaded instructions are not authority -----------------
    #
    # The incident's quietest mechanism: the agent's keys and
    # standing instructions were not in the package at all --
    # they were fetched during the install, so the attacker
    # could change who the agent was and what it held without
    # publishing anything new. Downloaded material does not
    # become authority by having been downloaded. In a fresh
    # session on a fresh kernel, the fetched keys and
    # instructions presented as authority for the same fetch
    # mint exactly as much as they should: none -- they are
    # not a permit, were never issued by the host owner, and
    # their arrival over the install channel changes nothing
    # about what they are.

    def test_step7_downloaded_instructions_are_not_authority(self) -> None:
        later_fetch = Intent(
            INSTALLER, "fetch_remote", FETCH_INTENT.resource, 25, LATER_SESSION
        )
        fresh = self._kernel()
        fresh_ledger = ConsequenceLedger()
        decision = fresh.evaluate(later_fetch)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(fresh_ledger.execute(fresh, DOWNLOADED_TOKEN, later_fetch))
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
        # postinstall execution EXECUTES under the install
        # permit. That is the incident's own shape -- an install
        # path that runs whatever a package declares because the
        # package arrived over a trusted channel. The denials in
        # the steps above therefore come from the real consume
        # path's binding checks, not from a harness that denies
        # by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_install_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, POSTINSTALL_INTENT))
        self.assertEqual(
            [("execute_script", POSTINSTALL_INTENT.resource)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route, here with the script
        # execution).
        real_permit = self._issue_install_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, POSTINSTALL_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

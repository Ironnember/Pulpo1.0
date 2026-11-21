"""Scenario test: the Microsoft Entra Connect Health API
tenant-metadata exposure (notified 2026-11-20).

Incident (Recorded, from BleepingComputer's reporting of
Microsoft's security notification to affected tenants, sent
2026-11-20): a vulnerability in the Microsoft Entra Connect
Health API -- introduced 2026-07-23, detected by Microsoft on
2026-11-09, fixed server-side 2026-11-19 -- was exploited for
unauthorized read-only access to tenant-level metadata. Per
Microsoft's notification, the exposed data included email
addresses of tenant technical contacts and administrator
accounts; tenant IDs, display names, initial domain names,
country codes and regional information; Entra license tiers;
directory synchronization status including the last sync
timestamp; Connect Health onboarding status; and an expired
certificate formerly used to register Connect Health agents
with an internal service decommissioned in late 2024, still
returned by the API because it had never been removed from
Connect Health storage. Microsoft states the flaw did not
expose passwords, password hashes, authentication tokens, or
valid cryptographic keys, and that it identified no
unauthorized configuration changes; how many organizations
were affected is undisclosed (Unknown).

The failure is an authorization failure, not an
authentication failure: callers reached the API and the API
answered reads outside the scope any caller was authorized
for. Access to the service existed; authority for the
specific reads did not -- and the response itself carried
fields (the expired certificate among them) that no
monitoring read needed.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the API, any Microsoft
service, any tenant data, or any network behavior. The
"caller" is this harness holding intents; the only route
from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash. An API access token is modeled as exactly what
it is in Pulpo's terms -- evidence that a caller reached the
service. It is not an approval envelope, not ceremony
evidence, and not a permit, and the kernel has no verb that
derives read authority from having reached an endpoint.

Setup: the monitoring agent holds exactly one legitimate
permit: one exact read -- its own tenant's health status,
the declared monitoring scope -- issued through a verified
approval envelope: the accountable per-action authorization
actually granted. The incident's reads are then attempted,
in sequence: the administrator email addresses, the tenant
configuration metadata, the expired certificate, the same
health read against another tenant, and the permitted read
re-presented with its response scope widened to all tenant
metadata (the GetTenant shape: one call, every field). The
kernel must deny each one, the consequence ledger must stay
empty for all of them, and every denial must land in the
audit record.

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
proves nothing about any deployed API or service that does
not route its reads through this kernel -- an endpoint that
answers first and checks scope never (or checks it against
nothing) is governed by nothing here. A control not on the
execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is permitted,
and any non-kernel API path (the incident's own class) remains
outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." Each denied evaluate/consume appends exactly one
audit record. That growth is itself a governed effect --
evidence production -- bounded at one record per attempt,
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
AGENT = "agent:entra-connect-health"
SESSION = "health-session-2026-11-20"
LATER_SESSION = "health-session-2026-11-21"

# The one act actually authorized: the monitoring agent reads
# its own tenant's health status -- the declared monitoring
# scope, and nothing else. The resource identity names the
# exact read; every field beyond it is a different resource
# and therefore a different intent.
HEALTH_RESOURCE = "entra:tenant-self/health-status"
HEALTH_INTENT = Intent(AGENT, "read_metadata", HEALTH_RESOURCE, 25, SESSION)

# The incident's reads. None of them has an approval; each was
# answered in the incident because the API checked that the
# caller had reached it, not that the caller was authorized
# for the specific read.
ADMIN_EMAILS_INTENT = Intent(
    AGENT, "read_metadata", "entra:tenant-self/admin-email-addresses", 25, SESSION
)
TENANT_CONFIG_INTENT = Intent(
    AGENT, "read_metadata", "entra:tenant-self/tenant-configuration", 25, SESSION
)
CERTIFICATE_INTENT = Intent(
    AGENT, "read_metadata", "entra:tenant-self/certificate", 25, SESSION
)
CROSS_TENANT_INTENT = Intent(
    AGENT, "read_metadata", "entra:tenant-other/health-status", 25, SESSION
)
# The permitted read with its response scope widened to all
# tenant metadata -- the GetTenant shape, one call returning
# every field. The widening rides in the resource identity,
# inside the hashed intent, so it cannot pass as the approved
# read.
WIDENED_INTENT = Intent(
    AGENT,
    "read_metadata",
    "entra:tenant-self/health-status/scope-all-metadata",
    25,
    SESSION,
)
OUT_OF_SCOPE_INTENTS = (
    ADMIN_EMAILS_INTENT,
    TENANT_CONFIG_INTENT,
    CERTIFICATE_INTENT,
    CROSS_TENANT_INTENT,
    WIDENED_INTENT,
)

# The caller's API access token, presented as if it were a
# permit. Reaching the service is not authority for a read;
# the kernel must treat this string as a fabricated token,
# because that is what it is.
API_TOKEN = "entra-connect-health:api-access-token"

# The expired certificate the API returned, presented in a
# later session as if it were a credential. It was never a
# permit; its expiry is not even the primary problem -- it
# was issued (per the incident record) to register agents
# with a service decommissioned in late 2024, for a purpose
# that is not this read.
EXPIRED_CERT_TOKEN = "entra:tenant-self/expired-agent-certificate"


class ConsequenceLedger:
    """Effects on the tenant record, reachable only through a successful consume.

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
    double the administrator-email read must EXECUTE, or the
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
    administrator-email read must EXECUTE here, or the
    scenario's denials would be coming from the harness rather
    than from the binding layers. This is the incident's own
    shape: an API path that checks nothing about which read a
    credential was issued for.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class EntraIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"read_metadata"}),
            10_000,
            frozenset({"read_metadata"}),
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

    def _issue_health_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, HEALTH_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(HEALTH_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_health_read_executes_exactly_once(self) -> None:
        permit = self._issue_health_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same read twice --
        # a monitoring authorization is not a standing one.
        self.assertFalse(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the administrator-email read has no permit ----------------

    def test_step1_admin_email_read_denied_api_access_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for the administrator-email read, and reaching
        # the API is not one.
        decision = self.kernel.evaluate(ADMIN_EMAILS_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, ADMIN_EMAILS_INTENT))
        # The caller presents its API access token itself as its
        # permit. The kernel treats it as what it is: a
        # fabricated token. Access existed in the incident;
        # authority for this read did not.
        self.assertFalse(self.ledger.execute(self.kernel, API_TOKEN, ADMIN_EMAILS_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(ADMIN_EMAILS_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the cross-tenant read under the genuine permit ------------

    def test_step2_cross_tenant_read_with_health_permit_denied(self) -> None:
        permit = self._issue_health_permit(self.kernel)
        # Same action, same field -- but another tenant's, which
        # is a different resource and therefore a different
        # intent. The one permit the agent holds binds its own
        # tenant exactly; tenant isolation is not a courtesy
        # the caller extends, it is part of the bound identity.
        self.assertFalse(self.ledger.execute(self.kernel, permit, CROSS_TENANT_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(CROSS_TENANT_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still
        # spends on the exact read it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the remaining out-of-scope reads under the genuine permit -

    def test_step3_config_certificate_and_widened_reads_denied(self) -> None:
        permit = self._issue_health_permit(self.kernel)
        # The tenant configuration, the expired certificate,
        # and the permitted read with its response scope
        # widened to all metadata: each is a different intent
        # from the approved health read, and the one permit
        # spends on none of them. The widened read is the
        # incident's core shape -- the approved call returning
        # fields no approval covered.
        for intent in (TENANT_CONFIG_INTENT, CERTIFICATE_INTENT, WIDENED_INTENT):
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(3, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(TENANT_CONFIG_INTENT),
                self.kernel.intent_hash(CERTIFICATE_INTENT),
                self.kernel.intent_hash(WIDENED_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denials did not burn the permit: the exact
        # approved read still spends.
        self.assertTrue(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing -----------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_health_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        # A consumed permit is not a reusable API credential:
        # re-presenting it for the same read gets nothing, and
        # re-presenting it for an out-of-scope read gets
        # nothing either.
        self.assertFalse(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, ADMIN_EMAILS_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ----------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, HEALTH_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the administrator-email read
        # signed with an unauthorized key: whoever reached the
        # API cannot mint the tenant's authority.
        forged_envelope = signed_envelope(
            self.kernel, ADMIN_EMAILS_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(ADMIN_EMAILS_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine health-read envelope presented for
        # the administrator-email intent: a real approval for
        # one read is not approval for another.
        decision = self.kernel.evaluate_with_approval(ADMIN_EMAILS_INTENT, genuine_envelope)
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
        decision = self.kernel.evaluate_with_approval(HEALTH_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign ---------------------
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
    # steps 1-5, not a subset: every out-of-scope read on every
    # route (steps 1-3), the spent-permit replays (step 4,
    # replayed after the one legitimate execution below), and
    # both approval-envelope attempts -- the forged envelope
    # and the genuine envelope presented for the wrong intent
    # (step 5). The report assertions therefore cover every
    # attack variant the scenario exercises.

    def test_step6_incident_channel_surfaces_the_exposure_campaign(self) -> None:
        permit = self._issue_health_permit(self.kernel)
        # The campaign, compressed: each out-of-scope read
        # attempted on every route the caller has -- its own
        # say-so, its API access token as a token, and the one
        # genuine permit.
        for intent in OUT_OF_SCOPE_INTENTS:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(API_TOKEN, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        # Each envelope in this compressed sequence carries its
        # own approval_id and nonce, as each real approval
        # would: the helper's fixed defaults would collide with
        # the permit issuance above and turn the forgery denial
        # below into a replay denial, misattributing the
        # control that rejected it.
        forged_envelope = signed_envelope(
            self.kernel,
            ADMIN_EMAILS_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(ADMIN_EMAILS_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the genuine
        # health-read envelope presented for the
        # administrator-email intent. A real approval for one
        # read is not approval for another; the decision is a
        # denial and the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            HEALTH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(ADMIN_EMAILS_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate read still executes; the campaign
        # did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, HEALTH_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for the
        # same read and for an out-of-scope read. A consumed
        # permit is not a reusable API credential; both
        # re-presentations are rejected at consume.
        self.assertFalse(self.kernel.consume(permit, HEALTH_INTENT))
        self.assertFalse(self.kernel.consume(permit, ADMIN_EMAILS_INTENT))
        self.assertEqual([("read_metadata", HEALTH_RESOURCE)], self.ledger.effects)

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
        self.assertEqual(12, len(permit_rejected))
        self.assertEqual(2, len(approval_rejected))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(5, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. The
        # five require_approval decisions above are
        # audit-recorded attempts that contribute zero near-miss
        # records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(16, report.near_misses)
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

    # -- step 7: the expired certificate is not a credential ----------------
    #
    # The incident's most quietly damning detail: an expired
    # certificate for a decommissioned service was still
    # sitting in storage and still being returned, months
    # after both its expiry and its purpose ended. Leftover
    # credential material does not retire itself. In a fresh
    # session on a fresh kernel, the expired certificate
    # presented as authority mints exactly as much as it
    # should: none -- it is not a permit, was never issued for
    # this read, and its survival in a response payload
    # changes nothing about what it is.

    def test_step7_expired_certificate_persists_without_becoming_authority(self) -> None:
        later_read = Intent(
            AGENT, "read_metadata", CERTIFICATE_INTENT.resource, 25, LATER_SESSION
        )
        fresh = self._kernel()
        fresh_ledger = ConsequenceLedger()
        decision = fresh.evaluate(later_read)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(fresh_ledger.execute(fresh, EXPIRED_CERT_TOKEN, later_read))
        self.assertEqual([], fresh_ledger.effects)
        self.assertEqual(0, len(_events(fresh, "permit_consumed")))
        self.assertEqual(1, len(_events(fresh, "permit_rejected")))
        self.assertTrue(fresh.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a
        # kernel double whose consume skips token authentication
        # and the kernel's token-to-intent binding, over a state
        # double whose consume ignores the store's binding: the
        # administrator-email read EXECUTES under the health
        # permit. That is the incident's own shape -- an API
        # path that answers any read a reached caller presents.
        # The denials in the steps above therefore come from
        # the real consume path's binding checks, not from a
        # harness that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_health_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, ADMIN_EMAILS_INTENT))
        self.assertEqual(
            [("read_metadata", ADMIN_EMAILS_INTENT.resource)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route, here with the email read).
        real_permit = self._issue_health_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, ADMIN_EMAILS_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

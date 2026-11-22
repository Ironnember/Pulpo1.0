"""Scenario test: the OpenRouter inference-provider incidents
(announced 2026-11-22).

Incident (Recorded, from OpenRouter's own security
announcement, "Data Processing Incidents on Inference
Providers," 2026-11-22): following Dragos's canary-prompt
investigation (research led by HD Moore; roughly two million
seeded canary prompts carrying traceable fake secrets and
links, run July-November 2026), OpenRouter permanently
off-boarded three inference providers from its marketplace,
removed 125 endpoints from Zero Data Retention (ZDR)
eligibility, and notified affected customers. OpenRouter
states its own infrastructure was not breached. The three
removed providers are not named in the announcement
(Unknown).

Three failure modes are documented across the announcement
and the linked provider disclosures:

1. Payload altered in transit. Per the Dragos findings as
   reported, one seller silently injected roughly 1,000
   hidden tokens into prompts passing through it: the
   payload the model received was not the payload the
   customer sent.
2. Traffic forwarded to an unauthorized destination. Per
   Novita's own privacy notice, a routing configuration sent
   some MiniMax requests to MiniMax's official API from
   2026-05-28 to 2026-11-11, beyond what customers intended;
   Dragos additionally reported routers secretly forwarding
   traffic to unauthorized third parties.
3. Policy flags not binding downstream. Requests flagged
   ZDR / no-data-collection were copied and retained anyway,
   and attackers inside compromised providers copied
   requests -- ZDR-marked ones among them -- for months,
   undetected. A privacy flag binds only the hop that honors
   it; it is data about the request, not authority over it.

This module models failure modes 1 and 2, and the
flag-versus-permit half of mode 3, against the canonical
kernel API. It does NOT reproduce OpenRouter, any inference
provider, any model traffic, or any network behavior, and it
claims nothing about confidentiality: a provider that
legitimately receives a payload can copy it, and no permit
changes that. The scope here is narrower and exact: had the
dispatch of each inference request been a governed act -- a
permit bound to the exact payload digest and the exact
destination endpoint, rechecked at consequence time and
consumed on use -- the altered payload would have failed the
digest binding and the forward to an unlisted endpoint
would have failed destination scope, both at execution
time, not months later.

Setup: the routing agent holds exactly one legitimate
permit: one exact dispatch -- one exact prompt payload, to
one exact endpoint, in one session -- issued through a
verified approval envelope. Its destination scope is set by
an AgentGrant naming the exact endpoint as its sole
resource prefix (see the module-level note on prefix
matching below). The incident's acts are then attempted, in
sequence: the same dispatch with its payload altered by an
injected instruction block (the hidden-token shape), the
same payload dispatched to the provider's upstream endpoint
(the forwarding shape), the dispatch re-presented under a
fresh session carrying only a ZDR flag as its claim to
authority (the flag shape), and the permitted dispatch
replayed after use. The kernel must deny each one, the
consequence ledger must stay empty for all of them, and
every denial must land in the audit record.

A note on resource matching, stated plainly (Verified at
this commit, from the kernel source and pinned by step 3):
AgentGrant resource matching is prefix-based
(``str.startswith``). The grant in this scenario names the
exact endpoint string as its only prefix, so a destination
that merely shares a string prefix with the authorized
endpoint -- the authorized endpoint's identity with a
suffix appended -- also passes the grant layer. The
scenario does not hide that: step 3 exercises exactly that
case and pins where it is and is not stopped (the grant
passes it; the exact-intent permit binding denies it,
because a suffixed destination is a different intent). The
forwarding denial in step 3 is claimed only for the
genuinely distinct upstream endpoint, whose identity shares
no prefix with the authorized one. Whether grant matching
should be exact-equality rather than prefix is a kernel
design question (surfaced by PR #381's review); this replay
records the behavior exactly as it stands and claims no
more scope than the executed run proves.

Incident-channel surfacing (Verified at this commit, by
executable probe and by the channel's derivation rules): the
derived incident report turns ``permit_rejected`` events,
``approval_rejected`` events, and denied decisions into
near-miss records. A bare ``evaluate`` that returns
``require_approval`` -- the kernel declining to mint without
approval -- appends a decision record to the canonical audit
but is NOT derived as a near-miss by the channel. The
scenario asserts both halves of that statement exactly as
they hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any deployed routing layer that does
not route its dispatches through this kernel, nothing about
prompt confidentiality at a provider that legitimately
receives a payload, and nothing about detection of copying
after the fact. A control not on the execution path governs
nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is permitted,
and any non-kernel routing path (the incident's own class)
remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." A denied attempt appends audit records, counted
per route: a bare evaluate returning ``require_approval``
appends one decision record; a policy-denied evaluate
appends one denied decision record; a ``consume`` rejection
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
    AgentGrant,
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
AGENT = "agent:inference-router"
SESSION = "routing-session-2026-11-22"
LATER_SESSION = "routing-session-2026-11-23"

# The one act actually authorized: dispatch of one exact
# prompt payload to one exact endpoint. The resource identity
# names the destination endpoint and the payload digest
# together; any other payload, or any other destination, is
# a different resource and therefore a different intent.
PAYLOAD_DIGEST = "sha256:9f2c-customer-prompt-exact"
ENDPOINT = "provider:primary/inference"
DISPATCH_RESOURCE = f"{ENDPOINT}/payload:{PAYLOAD_DIGEST}"
DISPATCH_INTENT = Intent(AGENT, "dispatch_request", DISPATCH_RESOURCE, 25, SESSION)

# The incident's acts. None of them has an approval.
#
# The altered payload: the same dispatch, to the same
# endpoint, with an injected instruction block appended in
# transit -- the hidden-token shape. The injection rides in
# the resource identity, inside the hashed intent, so it
# cannot pass as the approved payload.
ALTERED_RESOURCE = f"{ENDPOINT}/payload:{PAYLOAD_DIGEST}+injected-block"
ALTERED_INTENT = Intent(AGENT, "dispatch_request", ALTERED_RESOURCE, 25, SESSION)
# The forward: the same payload dispatched to the provider's
# upstream endpoint -- the Novita shape, traffic landing
# somewhere the customer never authorized. The upstream
# identity is a genuinely distinct destination: it shares no
# string prefix with the authorized endpoint, which is what
# the step-3 scope claim is limited to (see the module-level
# note on prefix matching).
FORWARD_RESOURCE = f"upstream:official-api/inference/payload:{PAYLOAD_DIGEST}"
FORWARD_INTENT = Intent(AGENT, "dispatch_request", FORWARD_RESOURCE, 25, SESSION)
# The authorized endpoint's identity with a suffix appended.
# This destination passes the grant's prefix check -- that is
# pinned, not hidden -- and must still be denied, by the
# exact-intent permit binding.
SUFFIXED_RESOURCE = f"{DISPATCH_RESOURCE}/mirror"
SUFFIXED_INTENT = Intent(AGENT, "dispatch_request", SUFFIXED_RESOURCE, 25, SESSION)
# The flag shape: the permitted dispatch re-presented in a
# fresh session, its only claim to authority a ZDR flag. A
# flag is data about a request; it is not an approval
# envelope, not ceremony evidence, and not a permit.
FLAGGED_INTENT = Intent(AGENT, "dispatch_request", DISPATCH_RESOURCE, 25, LATER_SESSION)

ATTACK_INTENTS = (
    ALTERED_INTENT,
    FORWARD_INTENT,
    SUFFIXED_INTENT,
    FLAGGED_INTENT,
)

# The customer's API credential for the routing service,
# presented as if it were a permit. Holding an account key
# is evidence the caller can reach the router; it is not an
# approval envelope and not a permit, and the kernel has no
# verb that derives dispatch authority from it.
API_KEY = "openrouter:customer-api-key"


class ConsequenceLedger:
    """Dispatches actually sent, reachable only through a successful consume.

    This is the scenario's execution path: the harness sends
    a dispatch (records its consequence) only when the kernel
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
    double the altered-payload dispatch must EXECUTE, or the
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
    altered-payload dispatch must EXECUTE here, or the
    scenario's denials would be coming from the harness rather
    than from the binding layers. This is the incident's own
    shape: a routing path that forwards whatever arrives,
    altered or not, wherever it is pointed.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class OpenRouterIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        # The destination scope: the routing agent's grant
        # names the one authorized endpoint as its sole
        # resource prefix. Matching is prefix-based (see the
        # module docstring); the claims in this scenario are
        # worded to exactly what that configuration proves.
        grant = AgentGrant(
            AGENT,
            frozenset({"dispatch_request"}),
            (ENDPOINT,),
            10_000,
        )
        self.policy = Policy(
            frozenset({"dispatch_request"}),
            10_000,
            frozenset({"dispatch_request"}),
            agent_grants=(grant,),
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

    def _issue_dispatch_permit(self, kernel: GovernanceKernel) -> str:
        envelope = signed_envelope(kernel, DISPATCH_INTENT, self.verifier, now_ns=NOW)
        decision = kernel.evaluate_with_approval(DISPATCH_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_dispatch_executes_exactly_once(self) -> None:
        permit = self._issue_dispatch_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)
        # The same permit cannot dispatch the same request
        # twice -- a dispatch authorization is not a standing
        # routing credential.
        self.assertFalse(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the unapproved dispatch has no permit ----------------------

    def test_step1_unapproved_dispatch_denied_api_key_is_not_a_permit(self) -> None:
        # The kernel declines to mint: no approval envelope
        # exists for this dispatch, and holding the customer's
        # API key is not one.
        decision = self.kernel.evaluate(ALTERED_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, ALTERED_INTENT))
        # The caller presents its API key itself as its permit.
        # The kernel treats it as what it is: a fabricated
        # token. Reach existed in the incident; authority for
        # this dispatch did not.
        self.assertFalse(self.ledger.execute(self.kernel, API_KEY, ALTERED_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(ALTERED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the altered payload under the genuine permit ---------------

    def test_step2_altered_payload_with_genuine_permit_denied(self) -> None:
        permit = self._issue_dispatch_permit(self.kernel)
        # The incident's core act: the approved dispatch with
        # an injected block appended to its payload in transit
        # -- the hidden-token shape. The injection changes the
        # payload, the changed payload is a different intent,
        # and the one permit the agent holds binds the exact
        # payload it was approved for. The alteration fails at
        # execution time, not on discovery months later.
        self.assertFalse(self.ledger.execute(self.kernel, permit, ALTERED_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(ALTERED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was binding, not lockout: the permit still
        # spends on the exact dispatch it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the forward, the suffixed destination, and scope -----------

    def test_step3_forward_denied_at_scope_and_suffixed_destination_denied_at_binding(self) -> None:
        permit = self._issue_dispatch_permit(self.kernel)
        # (a) The bare evaluate route, pinned first because it
        # is the route whose audit shape differs: the forward
        # to the upstream endpoint is outside the grant's
        # destination scope, so the kernel denies it outright
        # -- it does not even reach require_approval. One
        # denied decision record; no permit exists to spend.
        decision = self.kernel.evaluate(FORWARD_INTENT)
        self.assertEqual(
            ("deny", "agent_resource_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, FORWARD_INTENT))
        # (b) The forward under the genuine permit: rejected at
        # consume, bound to the forward's intent hash. The
        # payload is byte-identical to the approved one; only
        # the destination moved, and destination is part of
        # the bound identity.
        self.assertFalse(self.ledger.execute(self.kernel, permit, FORWARD_INTENT))
        # (c) The suffixed destination: the authorized
        # endpoint's identity with a suffix appended. Pinned
        # exactly as it holds: this destination PASSES the
        # grant layer, because grant matching is prefix-based
        # -- its bare evaluate reaches require_approval rather
        # than the scope denial above -- and it is still
        # denied, at consume, by the exact-intent permit
        # binding. The scenario claims the forward's scope
        # denial for genuinely distinct destinations only; for
        # prefix-sharing destinations the binding layer, not
        # the grant layer, is what stops the dispatch at this
        # commit.
        decision = self.kernel.evaluate(SUFFIXED_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertFalse(self.ledger.execute(self.kernel, permit, SUFFIXED_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(FORWARD_INTENT),
                self.kernel.intent_hash(SUFFIXED_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        denied = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "deny"
        ]
        self.assertEqual(1, len(denied))
        self.assertEqual("agent_resource_not_allowed", denied[0]["reason"])
        # The denials did not burn the permit: the exact
        # approved dispatch still spends.
        self.assertTrue(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing ------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        permit = self._issue_dispatch_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        # A consumed permit is not a reusable routing
        # credential: re-presenting it for the same dispatch
        # gets nothing, and re-presenting it for the altered
        # payload gets nothing either.
        self.assertFalse(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, ALTERED_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals ------------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        genuine_envelope = signed_envelope(
            self.kernel, DISPATCH_INTENT, self.verifier, now_ns=NOW
        )
        # (a) An envelope for the dispatch signed with an
        # unauthorized key: whoever operates the routing path
        # cannot mint the customer's authority.
        forged_envelope = signed_envelope(
            self.kernel, DISPATCH_INTENT, HmacTestVerifier(b"attacker-key"), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(DISPATCH_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) The genuine envelope presented for the altered
        # payload's intent: a real approval for one payload is
        # not approval for another.
        decision = self.kernel.evaluate_with_approval(ALTERED_INTENT, genuine_envelope)
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
        decision = self.kernel.evaluate_with_approval(DISPATCH_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign -----------------------
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
    # steps 1-5 and 7, not a subset: every attack intent on
    # every route (steps 1-3, including the scope-denied bare
    # evaluate for the forward and the flagged dispatch of
    # step 7), the spent-permit replays (step 4, replayed after
    # the one legitimate execution below), and both
    # approval-envelope attempts (step 5). The report assertions
    # therefore cover every denial route the scenario exercises,
    # including the bare-evaluate route on both of its shapes:
    # require_approval (audit-only, zero near-misses) and the
    # policy denial agent_resource_not_allowed (a denied
    # decision, derived as a near-miss).

    def test_step6_incident_channel_surfaces_the_routing_campaign(self) -> None:
        permit = self._issue_dispatch_permit(self.kernel)
        # The campaign, compressed: each attack intent
        # attempted on every route the caller has -- its own
        # say-so (bare evaluate), its API key as a token, and
        # the one genuine permit.
        for intent in ATTACK_INTENTS:
            self.kernel.evaluate(intent)
            self.assertFalse(self.kernel.consume(API_KEY, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        # Each envelope in this compressed sequence carries its
        # own approval_id and nonce, as each real approval
        # would: the helper's fixed defaults would collide with
        # the permit issuance above and turn the forgery denial
        # below into a replay denial, misattributing the
        # control that rejected it.
        forged_envelope = signed_envelope(
            self.kernel,
            DISPATCH_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(DISPATCH_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        # Step 5's second attempt, also replayed: the genuine
        # dispatch envelope presented for the altered payload's
        # intent. A real approval for one payload is not
        # approval for another; the decision is a denial and
        # the rejection lands in the channel.
        genuine_envelope = signed_envelope(
            self.kernel,
            DISPATCH_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(ALTERED_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate dispatch still executes; the
        # campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, DISPATCH_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)
        # Step 4's attempts, also replayed into the frozen
        # sequence: the now-spent permit re-presented for the
        # same dispatch and for the altered payload. A consumed
        # permit is not a reusable routing credential; both
        # re-presentations are rejected at consume.
        self.assertFalse(self.kernel.consume(permit, DISPATCH_INTENT))
        self.assertFalse(self.kernel.consume(permit, ALTERED_INTENT))
        self.assertEqual([("dispatch_request", DISPATCH_RESOURCE)], self.ledger.effects)

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
        self.assertEqual(3, len(denied_decisions))
        self.assertEqual(3, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. The
        # three require_approval decisions above are
        # audit-recorded attempts that contribute zero near-miss
        # records at this commit.
        self.assertEqual(
            len(permit_rejected) + len(approval_rejected) + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(15, report.near_misses)
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

    # -- step 7: a privacy flag is not authority -------------------------------
    #
    # The incident's third failure mode, in its exact form: a
    # request marked ZDR was treated as governed because the
    # flag said so, while nothing downstream was bound by it.
    # A flag is data about a request. In a fresh session, the
    # permitted dispatch re-presented carrying only its ZDR
    # flag as a claim to authority mints exactly as much as a
    # flag is: none -- the dispatch requires its own permit,
    # and the flag's presence changes nothing about what the
    # kernel asks for. (What a flag cannot do at all -- stop a
    # provider that legitimately received the payload from
    # retaining it -- is outside this scenario's scope and is
    # stated as a boundary, not tested as a claim.)

    def test_step7_zdr_flag_is_not_authority(self) -> None:
        fresh = self._kernel()
        fresh_ledger = ConsequenceLedger()
        decision = fresh.evaluate(FLAGGED_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(fresh_ledger.execute(fresh, API_KEY, FLAGGED_INTENT))
        self.assertEqual([], fresh_ledger.effects)
        self.assertEqual(0, len(_events(fresh, "permit_consumed")))
        self.assertEqual(1, len(_events(fresh, "permit_rejected")))
        self.assertTrue(fresh.verify_audit())

    # -- negative control -------------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a
        # kernel double whose consume skips token authentication
        # and the kernel's token-to-intent binding, over a state
        # double whose consume ignores the store's binding: the
        # altered-payload dispatch EXECUTES under the genuine
        # permit. That is the incident's own shape -- a routing
        # path that forwards whatever arrives, altered or not.
        # The denials in the steps above therefore come from
        # the real consume path's binding checks, not from a
        # harness that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_dispatch_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, ALTERED_INTENT))
        self.assertEqual(
            [("dispatch_request", ALTERED_INTENT.resource)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route, here with the altered payload).
        real_permit = self._issue_dispatch_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, ALTERED_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

"""Scenario test: the Together AI prompt leak -- an AI coding
agent committed a credential that opened a private prompt store
(disclosed 2026-11-21).

Incident (Recorded, from Together AI's own security post,
"Security event: prompt leakage for requests in June and July
of 2026," published 2026-11-21): Together AI collected prompt
samples for routine software testing and stored them in a
private Hugging Face repository. The samples came from
MiniMax M3, GLM-5.2, and Kimi K2.6 requests, primarily on
June 24, July 4, July 8, and July 14, 2026. During development
of the public GitHub repository ``xorl``, an AI coding agent
committed a credential providing access to the private Hugging
Face repository. Automated scanning detected the commit and
it was reverted, but during the exposure window an
unauthorized party obtained the credential, downloaded the
samples, searched them for credentials to other services, and
tested whether those credentials were valid; five of the
tested credentials were canary credentials associated with a
Dragos security experiment. Together AI states it has no
reason to believe the data was leaked further and lists
remediations including scoped and short-lived credentials,
credential checks on pull requests, zero-data-retention by
default, and updated AI-agent development processes. Anything
the post does not state is Unknown and is not modeled here.

The failure is a mandate failure, not a tooling failure: the
agent was there to write code, and nothing in its mandate
included placing a live credential into a public repository
or reading a private prompt store. A credential that can be
committed is a credential whose authority was never bound to
the acts it was meant to serve.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the credential, the
repository, the prompt samples, any Hugging Face service, or
any network behavior. The "agent" and the "unauthorized
party" are this harness holding intents; the only route from
intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash. The committed credential is modeled as exactly
what it is in Pulpo's terms -- a string that purports to be
authority. It is not a permit, not an approval envelope, and
not ceremony evidence, and the kernel has no verb that
derives authority from holding it.

Setup: the coding agent's mandate is modeled as what it
should have been in Pulpo's terms -- a directive
(``together-xorl-agent-mandate``) under which the agent may
perform exactly one act: commit one exact payload to the
``xorl`` repository. The payload's digest is inside the
resource identity, inside the hashed intent, so a commit
carrying anything else -- a credential, say -- is a
different intent, not the approved commit with an attachment.
Permits are issued only through the governed directive
projection, are bound to the directive and to the one exact
intent, and are single-use. The incident's acts are then
attempted in sequence: the commit with its payload swapped to
include the credential, the private prompt-sample store read
presented on the committed credential, the genuine commit
permit re-presented for the store read, the spent permit
replayed, forged and mismatched approval envelopes, and --
after the mandate is revoked, the remediation the incident
made necessary -- the still-unspent permit presented at
consume. The kernel must deny each one, the consequence
ledger must stay empty for all of them, and every denial must
land in the audit record.

Incident-channel surfacing (Verified at this commit, by
executable assertion in step 6): the derived incident report
turns ``permit_rejected`` events, ``approval_rejected``
events, denied decisions, and ``directive_denial`` events
into near-miss records. A bare ``evaluate`` that returns
``require_approval`` -- the kernel declining to mint without
approval -- appends a decision record to the canonical audit
but is NOT derived as a near-miss by the channel. The
scenario asserts both halves of that statement exactly as
they hold; it does not smooth the second half over.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about any deployed coding agent, repository,
or dataset store that does not route its consequences
through this kernel -- an agent that can push to a public
repository on a standing credential is governed by nothing
here. A control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is permitted,
and any non-kernel credential path (the standing credential
itself) remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." A denied attempt appends audit records, counted
per route: a bare evaluate returning ``require_approval``
appends one decision record; a bare evaluate denied on
policy appends one denied decision record; a ``consume``
rejection appends one ``permit_rejected`` record; a denied
approval-envelope evaluation appends two records -- an
``approval_rejected`` record and a denied decision record;
a directive-projection denial appends one
``directive_denial`` record. That growth is itself a governed
effect -- evidence production -- bounded at two records per
attempt, append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. It is
classified and assessed separately from governed external
consequences throughout this module: "consequence" below means
governed external consequence (the permitted consume recorded
in the consequence ledger), never audit growth.
"""

from __future__ import annotations

import hashlib
import unittest

from pulpo import (
    AgentGrant,
    GovernanceKernel,
    Intent,
    Policy,
    PulpoOrchestrator,
)
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
# The mandate window: the directive's issued-to-expiry span.
MANDATE_WINDOW_NS = 100_000

AGENT = "agent:together-xorl-coding-agent"
OPERATOR = "operator:owner"
SESSION = "xorl-development-2026-11-21"

# The one act actually authorized: commit one exact payload to
# the xorl repository. The payload digest is part of the
# resource identity -- the harness's synthetic stand-ins for
# "the approved code change" and "the same change with a
# credential riding in it" are hashed here, in the open, so
# the binding the scenario exercises is the digest itself.
# No real payload and no real credential appears in this file.
APPROVED_PAYLOAD_DIGEST = hashlib.sha256(
    b"together-xorl-approved-code-change"
).hexdigest()
SWAPPED_PAYLOAD_DIGEST = hashlib.sha256(
    b"together-xorl-approved-code-change+credential-material"
).hexdigest()
COMMIT_RESOURCE = f"github:together-ai/xorl:commit:sha256:{APPROVED_PAYLOAD_DIGEST}"
SWAPPED_RESOURCE = f"github:together-ai/xorl:commit:sha256:{SWAPPED_PAYLOAD_DIGEST}"
COMMIT_INTENT = Intent(AGENT, "commit_code", COMMIT_RESOURCE, 10, SESSION)
SWAPPED_INTENT = Intent(AGENT, "commit_code", SWAPPED_RESOURCE, 10, SESSION)

# The private prompt-sample store the committed credential
# opened. Reading it was never in the agent's mandate; it is a
# different action on a different resource, and therefore a
# different intent from the approved commit in every field
# that could carry it.
STORE_RESOURCE = "huggingface:together-ai/private-prompt-sample-store"
STORE_INTENT = Intent(AGENT, "read_prompt_samples", STORE_RESOURCE, 10, SESSION)

# The committed credential itself, presented as if it were a
# permit. Holding a credential is not authority for the acts
# it can reach; the kernel must treat this string as a
# fabricated token, because that is what it is. (A reference
# label, not credential material.)
COMMITTED_CREDENTIAL = "credential://huggingface/private-prompt-store-access"


class ConsequenceLedger:
    """Effects on the repository and the store, reachable only through a successful consume.

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
    double the prompt-store read must EXECUTE, or the scenario
    would be denying by construction rather than by the
    kernel's binding.
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
    prompt-store read must EXECUTE here, or the scenario's
    denials would be coming from the harness rather than from
    the binding layers. This is the incident's own shape: a
    credential that spends on whatever its holder reaches for.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


def _events_for(kernel: GovernanceKernel, name: str, intent: Intent) -> list[dict]:
    """Events of one kind bound to one intent.

    Directive activation and revocation consume their own
    authority permits, so scenario counts are taken per intent
    hash -- the authority operations' records are governance of
    the mandate, not attempts on the scenario's acts.
    """
    digest = kernel.intent_hash(intent)
    return [
        record
        for record in _events(kernel, name)
        if record["payload"].get("intent_hash") == digest
    ]


class TogetherIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset(
                {
                    "commit_code",
                    "read_prompt_samples",
                    "activate_directive",
                    "revoke_directive",
                }
            ),
            10_000,
            frozenset(
                {"read_prompt_samples", "activate_directive", "revoke_directive"}
            ),
            agent_grants=(
                AgentGrant(
                    AGENT,
                    frozenset({"commit_code", "read_prompt_samples"}),
                    (COMMIT_RESOURCE, STORE_RESOURCE),
                    10,
                ),
                AgentGrant(
                    OPERATOR,
                    frozenset({"activate_directive", "revoke_directive"}),
                    ("directive:together-xorl-agent-mandate:",),
                    0,
                ),
            ),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()
        self.directive = Directive(
            directive_id="together-xorl-agent-mandate",
            version=1,
            issuer_authority_id=self.verifier.authority_id,
            principal=AGENT,
            allowed_actions=frozenset({"commit_code"}),
            resource_prefixes=(COMMIT_RESOURCE,),
            max_cost=10,
            issued_at_ns=NOW,
            expires_at_ns=NOW + MANDATE_WINDOW_NS,
        )

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

    def _authority_envelope(
        self,
        kernel: GovernanceKernel,
        operation: str,
        approval_id: str,
        nonce: str,
    ):
        intent = DirectiveAuthorityController.authority_intent(
            operation, self.directive, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )

    def _activate(self, kernel: GovernanceKernel) -> None:
        controller = DirectiveAuthorityController(kernel)
        envelope = self._authority_envelope(
            kernel, controller.ACTIVATE, "activate-1", "activate-nonce-1"
        )
        decision = controller.activate(
            self.directive, envelope, operator_principal=OPERATOR
        )
        self.assertEqual("allow", decision.outcome)

    def _revoke(self, kernel: GovernanceKernel) -> None:
        controller = DirectiveAuthorityController(kernel)
        envelope = self._authority_envelope(
            kernel, controller.REVOKE, "revoke-1", "revoke-nonce-1"
        )
        decision = controller.revoke(
            self.directive, envelope, operator_principal=OPERATOR
        )
        self.assertEqual("allow", decision.outcome)

    def _issue_commit_permit(self, kernel: GovernanceKernel) -> str:
        decision = GovernedDirectiveProjection(kernel).evaluate(
            COMMIT_INTENT, self.directive
        )
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_commit_executes_exactly_once(self) -> None:
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        # The permit was bound to the live mandate at issuance.
        self.assertEqual(1, len(_events(self.kernel, "permit_bound_to_directive")))
        self.assertTrue(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same commit twice --
        # a mandate to commit one change is not a standing push
        # credential.
        self.assertFalse(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        self.assertEqual(
            1, len(_events_for(self.kernel, "permit_consumed", COMMIT_INTENT))
        )
        self.assertEqual(
            1, len(_events_for(self.kernel, "permit_rejected", COMMIT_INTENT))
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the payload swap ------------------------------------------

    def test_step1_swapped_payload_commit_denied_on_every_route(self) -> None:
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        # The incident's originating act: the commit goes out
        # with a credential riding in the payload. The payload
        # is inside the intent's resource identity, so this is
        # not the approved commit with an attachment -- it is a
        # different intent, and every route refuses it: the
        # mandate's projection will not mint for it (its one
        # resource prefix is the approved payload's full
        # identity), the kernel's own policy bound denies it
        # outright, and the genuine commit permit does not
        # spend on it.
        projection = GovernedDirectiveProjection(self.kernel)
        decision = projection.evaluate(SWAPPED_INTENT, self.directive)
        self.assertEqual(
            ("deny", "directive_resource_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        decision = self.kernel.evaluate(SWAPPED_INTENT)
        self.assertEqual(
            ("deny", "agent_resource_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, permit, SWAPPED_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(SWAPPED_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(1, len(_events(self.kernel, "directive_denial")))
        self.assertEqual(
            0, len(_events_for(self.kernel, "permit_consumed", SWAPPED_INTENT))
        )
        # The denials were scope, not lockout: the permit still
        # spends on the exact payload it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the store read on the committed credential -----------------

    def test_step2_store_read_on_committed_credential_denied(self) -> None:
        self._activate(self.kernel)
        # The kernel declines to mint: no approval envelope
        # exists for the prompt-store read, and holding the
        # committed credential is not one.
        decision = self.kernel.evaluate(STORE_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, STORE_INTENT))
        # Whoever holds the credential presents it as its
        # permit. The kernel treats it as what it is: a
        # fabricated token. The credential could reach the
        # store in the incident; authority for this read did
        # not exist, and reach is not authority.
        self.assertFalse(
            self.ledger.execute(self.kernel, COMMITTED_CREDENTIAL, STORE_INTENT)
        )
        # The mandate's projection will not mint for the read
        # either: the action itself is outside the mandate.
        projection = GovernedDirectiveProjection(self.kernel)
        decision = projection.evaluate(STORE_INTENT, self.directive)
        self.assertEqual(
            ("deny", "directive_action_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(
            0, len(_events_for(self.kernel, "permit_consumed", STORE_INTENT))
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(STORE_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(1, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the genuine permit re-presented for the store read ---------

    def test_step3_commit_permit_re_presented_for_store_read_denied(self) -> None:
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        # The scope-widened re-presentation: a real permit, for
        # a real approved act, presented for the store read.
        # The permit binds the commit's exact intent; the store
        # read is a different intent in action and resource,
        # and the permit spends on none of it. A credential's
        # validity for one act is not a scope it carries to the
        # next door.
        self.assertFalse(self.ledger.execute(self.kernel, permit, STORE_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(STORE_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(
            0, len(_events_for(self.kernel, "permit_consumed", STORE_INTENT))
        )
        # The denial was scope, not lockout: the permit still
        # spends on the exact commit it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the spent permit replays for nothing ------------------------

    def test_step4_spent_permit_replay_denied(self) -> None:
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        # A consumed permit is not a reusable repository
        # credential: re-presenting it for the same commit gets
        # nothing, and re-presenting it for the store read gets
        # nothing either. In the incident, the exposure window
        # was the time between the commit and its revert; here
        # there is no window, because the spent material was
        # never spendable again.
        self.assertFalse(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, STORE_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        self.assertEqual(
            1, len(_events_for(self.kernel, "permit_consumed", COMMIT_INTENT))
        )
        self.assertEqual(2, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged and mismatched approvals -----------------------------

    def test_step5_forged_and_mismatched_approvals_denied(self) -> None:
        # (a) An envelope for the store read signed with an
        # unauthorized key: whoever obtained the credential
        # cannot mint the owner's authority.
        forged_envelope = signed_envelope(
            self.kernel,
            STORE_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(STORE_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) A genuine envelope for the approved commit
        # presented for the store read: a real approval for one
        # act is not approval for another.
        genuine_envelope = signed_envelope(
            self.kernel,
            COMMIT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine",
            nonce="nonce-genuine",
        )
        decision = self.kernel.evaluate_with_approval(STORE_INTENT, genuine_envelope)
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
        # The denials did not poison the path: the governed
        # route still admits the exact approved commit.
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign ----------------------
    #
    # Surfacing, asserted exactly as it holds at this commit:
    # every consume rejection, every approval rejection, every
    # denied decision, and every directive-projection denial in
    # the sequence becomes a near-miss record in the derived
    # incident report. The bare require_approval decision is in
    # the canonical audit (and counted below) but is NOT derived
    # as a near-miss -- the expected near-miss count is built
    # from the event classes the channel actually derives, so
    # this test pins the boundary instead of papering over it.
    #
    # The frozen sequence below is the full attempt sequence of
    # steps 1-5 and 7, not a subset: the swapped payload on
    # both its routes, the store read on every route (bare
    # evaluate, the committed credential as a token, the
    # genuine permit re-presented), both approval-envelope
    # attempts, the spent-permit replays, and the
    # post-revocation attempts. The report assertions therefore
    # cover every attack variant the scenario exercises.

    def test_step6_incident_channel_surfaces_the_leak_campaign(self) -> None:
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        unspent_permit = self._issue_commit_permit(self.kernel)
        projection = GovernedDirectiveProjection(self.kernel)
        # Step 1's variant: the swapped payload, refused by the
        # projection and by the genuine permit.
        decision = projection.evaluate(SWAPPED_INTENT, self.directive)
        self.assertEqual("deny", decision.outcome)
        self.assertFalse(self.kernel.consume(permit, SWAPPED_INTENT))
        # Step 2's and step 3's variants: the store read on
        # every route the holder has -- its own say-so, the
        # committed credential as a token, and the genuine
        # commit permit re-presented.
        self.kernel.evaluate(STORE_INTENT)
        self.assertFalse(self.kernel.consume(COMMITTED_CREDENTIAL, STORE_INTENT))
        self.assertFalse(self.kernel.consume(permit, STORE_INTENT))
        # Step 5's variants: both approval-envelope attempts.
        # Each envelope carries its own approval_id and nonce,
        # as each real approval would.
        forged_envelope = signed_envelope(
            self.kernel,
            STORE_INTENT,
            HmacTestVerifier(b"attacker-key"),
            now_ns=NOW,
            approval_id="approval-forged",
            nonce="nonce-forged",
        )
        decision = self.kernel.evaluate_with_approval(STORE_INTENT, forged_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_signature_invalid", decision.reason)
        genuine_envelope = signed_envelope(
            self.kernel,
            COMMIT_INTENT,
            self.verifier,
            now_ns=NOW,
            approval_id="approval-genuine-2",
            nonce="nonce-genuine-2",
        )
        decision = self.kernel.evaluate_with_approval(STORE_INTENT, genuine_envelope)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("approval_intent_mismatch", decision.reason)
        # The one legitimate commit still executes; the
        # campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)
        # Step 4's variants: the now-spent permit re-presented
        # for the same commit and for the store read.
        self.assertFalse(self.kernel.consume(permit, COMMIT_INTENT))
        self.assertFalse(self.kernel.consume(permit, STORE_INTENT))
        # Step 7's variants, replayed into the frozen sequence:
        # the mandate is revoked, and the still-unspent second
        # permit is presented at consume, and issuance itself
        # is attempted once more. Revocation is enforced at
        # consume time, not merely by refusing new issuance.
        self._revoke(self.kernel)
        self.assertFalse(self.kernel.consume(unspent_permit, COMMIT_INTENT))
        decision = projection.evaluate(COMMIT_INTENT, self.directive)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_revoked", decision.reason)
        self.assertEqual([("commit_code", COMMIT_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends
        # nothing.
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertTrue(report.audit_valid)
        self.assertEqual(0, report.incidents)

        permit_rejected = _events(self.kernel, "permit_rejected")
        approval_rejected = _events(self.kernel, "approval_rejected")
        directive_denials = _events(self.kernel, "directive_denial")
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
        self.assertEqual(2, len(directive_denials))
        self.assertEqual(2, len(denied_decisions))
        self.assertEqual(1, len(require_approval_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. The
        # one require_approval decision above is an
        # audit-recorded attempt that contributes zero near-miss
        # records at this commit.
        self.assertEqual(
            len(permit_rejected)
            + len(approval_rejected)
            + len(directive_denials)
            + len(denied_decisions),
            report.near_misses,
        )
        self.assertEqual(12, report.near_misses)
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
                "directive_denial": len(directive_denials),
                "decision": len(denied_decisions),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 7: revocation retires the mandate at consume -------------------

    def test_step7_revoked_mandate_invalidates_unspent_permit_at_consume(self) -> None:
        self._activate(self.kernel)
        permit = self._issue_commit_permit(self.kernel)
        # The remediation the incident made necessary, applied
        # while the permit is still unspent and the mandate
        # window still open: the mandate is revoked. The
        # revocation is enforced HERE, at consume time, by the
        # store's check of the binding's live directive status
        # -- not merely by refusing new issuance.
        self._revoke(self.kernel)
        self.assertEqual(
            "directive_revoked",
            self.kernel.directive_status(
                self.directive.directive_id,
                self.directive.version,
                self.directive.directive_hash,
            ),
        )
        self.assertFalse(self.ledger.execute(self.kernel, permit, COMMIT_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            "directive_revoked", rejected[0]["payload"].get("directive_status")
        )
        # New issuance is closed too, and the closure is
        # recorded.
        decision = GovernedDirectiveProjection(self.kernel).evaluate(
            COMMIT_INTENT, self.directive
        )
        self.assertEqual(
            ("deny", "directive_revoked"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        denials = [
            record
            for record in _events(self.kernel, "directive_denial")
            if record["payload"]["reason"] == "directive_revoked"
        ]
        self.assertEqual(1, len(denials))
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ------------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a
        # kernel double whose consume skips token authentication
        # and the kernel's token-to-intent binding, over a state
        # double whose consume ignores the store's binding: the
        # prompt-store read EXECUTES under the commit permit.
        # That is the incident's own shape -- a credential that
        # spends on whatever its holder reaches for. The denials
        # in the steps above therefore come from the real consume
        # path's binding checks, not from a harness that denies
        # by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        self._activate(blind_kernel)
        blind_permit = self._issue_commit_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, blind_permit, STORE_INTENT))
        self.assertEqual(
            [("read_prompt_samples", STORE_RESOURCE)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 3's route, here with the store read).
        self._activate(self.kernel)
        real_permit = self._issue_commit_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, STORE_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

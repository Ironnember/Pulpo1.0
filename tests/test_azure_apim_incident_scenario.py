"""Scenario test: the Azure API Management Classic credential
theft (publicized 2026-11-23).

Incident (Recorded, from BleepingComputer's reporting of
Microsoft's advisory and of Norway's National Security
Authority (NSM) public notice): Microsoft identified a flaw
on 2026-11-18 in Azure API Management Classic -- on instances
not configured to recommended best practices, an unauthorized
party could reach management functions and perform
administrative operations, including reading stored secrets:
Named Values secrets, identity-provider and OpenID Connect
client secrets, subscription keys, and direct management API
tokens. Microsoft mitigated the flaw on 2026-11-19, and
warned that the mitigation does not invalidate credentials
already taken. Per NSM, an unknown actor targeted APIM
tokens and secrets; the targeting was first found by Norway's
energy sector, and NSM links it to the Equinor attack
disclosed 2026-11-17.

The failure is an authorization failure, not an
authentication failure: the credentials the attacker held
were valid, and validity was the whole of the check.
Possession of a credential that can reach the management
plane was treated as authority for each specific act the
management plane can perform -- above all, reading the
stored secrets, which are themselves credentials for the
next system. And the remediation shape is the incident's
second lesson: fixing the flaw did not retire what the flaw
had already handed out, because in that system the stolen
material's validity does not consult anything live.

This module models that failure mode against the canonical
kernel API. It does NOT reproduce the APIM service, the
flaw, any Azure environment, any real credential, or any
network behavior. The "operator" and the "attacker" are this
harness holding intents and permit material; the only route
from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact
intent hash.

Setup: the management engagement is modeled as what it
should have been in Pulpo's terms -- a directive
(``apim-management-engagement``) under which the operator's
agent may perform exactly one class of act: reading one
named secret value (the instance's identity-provider client
secret) on one instance. Permits are issued only through the
governed directive projection, are bound to the directive
and to one exact intent, live at most the policy's permit
TTL, and are single-use. The incident's acts are then
attempted in sequence: the stolen credential material -- the
direct management token and a subscription key, both valid
in the incident -- presented with no permit at all; a
genuine permit issued for a different named secret presented
for this one; the remaining exposed secret classes and a
second instance, for which the projection will not even
mint; a genuine permit presented after the owner retires the
engagement by revoking the directive; and the spent permit
replayed. The kernel must deny each one, the consequence
ledger must stay empty for all of them, and every denial
must land in the audit record.

Incident-channel surfacing (Verified at this commit, by
executable assertion in step 5): every attempt in this
scenario routes through ``consume`` or through the directive
projection, and both record -- consume rejections append
``permit_rejected``; projection denials append
``directive_denial`` (kernel build item #2) -- and the
incident channel derives near-miss records from both
classes, so the derived counts are asserted exactly, with no
remainder. The bare-``evaluate`` surfacing boundary recorded
by the Cairn and Entra replays (issue #375) is a property of
a route this scenario does not exercise -- no attempt here
is a bare evaluate -- so this module neither reproduces it
nor claims to close it.

Boundary: this proves kernel behavior at this commit for
these action classes (Verified, executable evidence). It
proves nothing about Azure, APIM, the flaw itself, or any
deployed system that does not route its management-plane
acts through this kernel -- a management API that answers a
secret read because the caller's credential is valid is
governed by nothing here. The replay models the
authorization layer, not the vulnerability. A control not
on the execution path governs nothing.

Adversarial transformation review: the full eight-pass
review (Flip, Reverse, Invert, Inside-Out, Darken, Lighten,
Amplify, Negate) for this incident is recorded in this
scenario's change record per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only -- exactly one governed external consequence is
permitted, and any non-kernel credential path (the stolen
material itself) remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state
changed." Each denied consume or projection denial appends
exactly one audit record. That growth is itself a governed
effect -- evidence production -- bounded at one record per
attempt, append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. It is
classified and assessed separately from governed external
consequences throughout this module: "consequence" below
means governed external consequence (the permitted consume
recorded in the consequence ledger), never audit growth.
"""

from __future__ import annotations

import unittest

from pulpo import (
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


T0 = 1_000_000
# The engagement window: the directive's issued-to-expiry span.
ENGAGEMENT_WINDOW_NS = 100_000
# The policy's permit lifetime cap: no permit outlives this,
# whatever the window still allows.
PERMIT_TTL_NS = 20_000

AGENT = "agent:apim-management-operator"
OPERATOR = "operator:owner"
SESSION = "apim-session-2026-11"
LATER_SESSION = "apim-session-2026-11-later"

# The one act the engagement actually authorized: read the one
# named secret value -- the instance's identity-provider
# (OpenID Connect) client secret.
TARGET_RESOURCE = "apim:instance-self/secret/idp-client-secret"
# The incident's other exposed classes, each its own named
# secret on the same instance: a Named Values secret, a
# subscription key, and the direct management API token store.
NAMED_VALUE_RESOURCE = "apim:instance-self/secret/named-value-signing-key"
SUBSCRIPTION_RESOURCE = "apim:instance-self/secret/subscription-key-primary"
MGMT_TOKEN_RESOURCE = "apim:instance-self/secret/direct-management-token"
# The same read against a second instance: outside the
# engagement's resource prefix entirely.
CROSS_INSTANCE_RESOURCE = "apim:instance-other/secret/idp-client-secret"

TARGET_INTENT = Intent(AGENT, "read_secret_value", TARGET_RESOURCE, 0, SESSION)
NAMED_VALUE_INTENT = Intent(AGENT, "read_secret_value", NAMED_VALUE_RESOURCE, 0, SESSION)
SUBSCRIPTION_INTENT = Intent(AGENT, "read_secret_value", SUBSCRIPTION_RESOURCE, 0, SESSION)
MGMT_TOKEN_INTENT = Intent(AGENT, "read_secret_value", MGMT_TOKEN_RESOURCE, 0, SESSION)
CROSS_INSTANCE_INTENT = Intent(AGENT, "read_secret_value", CROSS_INSTANCE_RESOURCE, 0, SESSION)
# A write against the very secret the engagement may read:
# a different action, and therefore a different intent.
UPDATE_INTENT = Intent(AGENT, "update_secret_value", TARGET_RESOURCE, 0, SESSION)
# The attacker naming itself as principal: no engagement
# exists for it, whatever credential it holds.
ATTACKER_INTENT = Intent(
    "agent:unknown-actor", "read_secret_value", TARGET_RESOURCE, 0, SESSION
)
OTHER_SECRET_INTENTS = (NAMED_VALUE_INTENT, SUBSCRIPTION_INTENT, MGMT_TOKEN_INTENT)
ATTACK_INTENTS = OTHER_SECRET_INTENTS + (CROSS_INSTANCE_INTENT, UPDATE_INTENT)

# The stolen credential material, presented as if it were a
# permit. In the incident both were valid -- that validity is
# what the flaw traded on. A valid APIM credential is still
# not a permit; the kernel must treat these strings as
# fabricated tokens, because that is what they are.
STOLEN_MGMT_TOKEN = "apim:direct-management-token:stolen-example"
STOLEN_SUBSCRIPTION_KEY = "apim:subscription-key:stolen-example"
STOLEN_TOKENS = (STOLEN_MGMT_TOKEN, STOLEN_SUBSCRIPTION_KEY)


class _Clock:
    """The scenario's clock: the harness advances it explicitly.

    The kernel reads time only through this callable, so the
    engagement window, the permit TTL, and the retirement
    moment are all exercised by moving one value.
    """

    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns

    def advance_to(self, now_ns: int) -> None:
        self.now_ns = now_ns


class ConsequenceLedger:
    """Effects on the secret store, reachable only through a successful consume.

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
    double the target secret read must EXECUTE under a permit
    issued for a different secret, or the scenario would be
    denying by construction rather than by the kernel's binding.
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
    target secret read must EXECUTE here under the
    different-secret permit, or the scenario's denials would
    be coming from the harness rather than from the binding
    layers. This is the incident's own shape: a management
    plane that answers the read a valid credential presents.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class AzureApimIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.clock = _Clock(T0)
        self.policy = Policy(
            frozenset({"read_secret_value", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
            max_permit_ttl_ns=PERMIT_TTL_NS,
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()
        self.directive = Directive(
            directive_id="apim-management-engagement",
            version=1,
            issuer_authority_id=self.verifier.authority_id,
            principal=AGENT,
            allowed_actions=frozenset({"read_secret_value"}),
            resource_prefixes=("apim:instance-self/secret/",),
            max_cost=10,
            issued_at_ns=T0,
            expires_at_ns=T0 + ENGAGEMENT_WINDOW_NS,
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
            clock=self.clock,
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
            now_ns=self.clock.now_ns,
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

    def _issue(self, kernel: GovernanceKernel, intent: Intent) -> str:
        decision = GovernedDirectiveProjection(kernel).evaluate(intent, self.directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_secret_read_executes_exactly_once(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue(self.kernel, TARGET_INTENT)
        # The permit was bound to the live engagement at issuance.
        self.assertEqual(1, len(_events(self.kernel, "permit_bound_to_directive")))
        self.assertTrue(self.ledger.execute(self.kernel, permit, TARGET_INTENT))
        self.assertEqual([("read_secret_value", TARGET_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same read twice --
        # a management authorization is not a standing one.
        self.assertFalse(self.ledger.execute(self.kernel, permit, TARGET_INTENT))
        self.assertEqual([("read_secret_value", TARGET_RESOURCE)], self.ledger.effects)
        target_digest = self.kernel.intent_hash(TARGET_INTENT)
        consumed = [
            record
            for record in _events(self.kernel, "permit_consumed")
            if record["payload"]["intent_hash"] == target_digest
        ]
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == target_digest
        ]
        self.assertEqual(1, len(consumed))
        self.assertEqual(1, len(rejected))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the stolen credentials, with no permit at all --------------

    def test_step1_stolen_valid_credentials_without_permit_get_nothing(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        # The incident's first move: the attacker holds valid
        # management-plane credentials -- a direct management
        # API token and a subscription key, taken from an
        # instance the flaw exposed -- and presents them for
        # the secret read. There is no permit. Validity of the
        # credential is not authority for the act: each string
        # is refused at consume as what it is, a fabricated
        # token, and the refusal is bound to the read's intent
        # hash.
        for token in STOLEN_TOKENS:
            self.assertFalse(self.ledger.execute(self.kernel, token, TARGET_INTENT))
        self.assertEqual([], self.ledger.effects)
        target_digest = self.kernel.intent_hash(TARGET_INTENT)
        consumed_for_target = [
            record
            for record in _events(self.kernel, "permit_consumed")
            if record["payload"]["intent_hash"] == target_digest
        ]
        self.assertEqual(0, len(consumed_for_target))
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == target_digest
        ]
        self.assertEqual(2, len(rejected))
        for record in rejected:
            self.assertEqual(
                "permit_signature_invalid", record["payload"].get("reason")
            )
        # Nor can the attacker mint: the one issuance route is
        # the governed projection under the engagement, and the
        # engagement names a different principal. Holding the
        # instance's credentials does not make the attacker the
        # engagement's operator.
        decision = GovernedDirectiveProjection(self.kernel).evaluate(
            ATTACKER_INTENT, self.directive
        )
        self.assertEqual(
            ("deny", "directive_principal_mismatch"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        denials = _events(self.kernel, "directive_denial")
        self.assertEqual(1, len(denials))
        self.assertEqual(
            "directive_principal_mismatch", denials[0]["payload"]["reason"]
        )
        self.assertEqual([], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: exact-intent binding ---------------------------------------
    #
    # A genuine permit for a different act authorizes nothing
    # here. The permit below is real, unexpired, unspent, and
    # issued under the live engagement -- for a different named
    # secret. Presented for the target read it is refused at
    # the kernel's token-to-intent binding before the store is
    # consulted; the engagement's scope also refuses to mint
    # for the second instance and for the write action at all.

    def test_step2_permit_for_a_different_secret_does_not_authorize_this_read(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        other_permit = self._issue(self.kernel, NAMED_VALUE_INTENT)
        self.assertFalse(self.ledger.execute(self.kernel, other_permit, TARGET_INTENT))
        self.assertEqual([], self.ledger.effects)
        target_digest = self.kernel.intent_hash(TARGET_INTENT)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == target_digest
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            "permit_intent_mismatch", rejected[0]["payload"].get("reason")
        )
        # A kernel-layer refusal: the store's directive fields
        # are absent because the store was never reached.
        self.assertNotIn("directive_status", rejected[0]["payload"])
        # The reverse presentation fails the same way: a permit
        # for the target secret does not spend on the named
        # value either. Binding is exact in both directions.
        target_permit = self._issue(self.kernel, TARGET_INTENT)
        self.assertFalse(self.ledger.execute(self.kernel, target_permit, NAMED_VALUE_INTENT))
        self.assertEqual([], self.ledger.effects)
        # And the engagement will not mint outside its scope at
        # all: not for the second instance's identical secret,
        # and not for a write against the very secret it may
        # read.
        projection = GovernedDirectiveProjection(self.kernel)
        decision = projection.evaluate(CROSS_INSTANCE_INTENT, self.directive)
        self.assertEqual(
            ("deny", "directive_resource_not_allowed"),
            (decision.outcome, decision.reason),
        )
        decision = projection.evaluate(UPDATE_INTENT, self.directive)
        self.assertEqual(
            ("deny", "directive_action_not_allowed"),
            (decision.outcome, decision.reason),
        )
        self.assertEqual(2, len(_events(self.kernel, "directive_denial")))
        # The denials were scope, not lockout: both genuine
        # permits still spend on the exact reads they were
        # issued for.
        self.assertTrue(self.ledger.execute(self.kernel, other_permit, NAMED_VALUE_INTENT))
        self.assertTrue(self.ledger.execute(self.kernel, target_permit, TARGET_INTENT))
        self.assertEqual(
            [
                ("read_secret_value", NAMED_VALUE_RESOURCE),
                ("read_secret_value", TARGET_RESOURCE),
            ],
            self.ledger.effects,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: revocation at consume --------------------------------------
    #
    # The remediation the incident could not perform: in the
    # incident, mitigating the flaw left the stolen credentials
    # valid, because their validity consulted nothing live.
    # Here the owner retires the engagement mid-window, and a
    # genuine, unexpired, unspent permit -- indistinguishable
    # from a stolen one at presentation time -- is refused at
    # consume because the binding's directive is revoked.
    # Revocation is enforced where the act would happen, not
    # merely by refusing new issuance.

    def test_step3_revocation_at_consume_retires_unspent_permits(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue(self.kernel, TARGET_INTENT)
        # The engagement is retired while the permit's own TTL
        # still has room to run and the window is still open.
        self.clock.advance_to(T0 + 200)
        self._revoke(self.kernel)
        self.assertEqual(
            "directive_revoked",
            self.kernel.directive_status(
                self.directive.directive_id,
                self.directive.version,
                self.directive.directive_hash,
            ),
        )
        self.clock.advance_to(T0 + 300)
        self.assertFalse(self.ledger.execute(self.kernel, permit, TARGET_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, TARGET_INTENT))
        self.assertEqual([], self.ledger.effects)
        target_digest = self.kernel.intent_hash(TARGET_INTENT)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == target_digest
        ]
        self.assertEqual(2, len(rejected))
        for record in rejected:
            self.assertEqual(
                "directive_revoked", record["payload"].get("directive_status")
            )
        # New issuance is closed too, and the closure is recorded.
        decision = GovernedDirectiveProjection(self.kernel).evaluate(
            TARGET_INTENT, self.directive
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

    # -- step 4: the spent permit is not a reusable credential ---------------

    def test_step4_spent_permit_and_stolen_tokens_replay_for_nothing(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue(self.kernel, TARGET_INTENT)
        # The legitimate read: the permit spends, once.
        self.assertTrue(self.ledger.execute(self.kernel, permit, TARGET_INTENT))
        # Minutes later the attacker holds what the operator
        # held -- the same permit material, now spent -- plus
        # the stolen credential strings, and makes the
        # incident's calls again. The engagement is still live
        # and the permit's signed expiry is still ahead, so
        # these denials are not timing denials: the spent
        # permit is refused because a permit spends exactly
        # once (its rejection record carries the store's
        # directive_status "active" -- the engagement was live
        # and the spend itself was the bar), and the strings
        # are refused as fabricated, exactly as in step 1.
        # What was stolen is not a standing capability, so
        # there is nothing standing to steal.
        self.clock.advance_to(T0 + 300)
        self.assertFalse(self.ledger.execute(self.kernel, permit, TARGET_INTENT))
        for token in STOLEN_TOKENS:
            self.assertFalse(self.ledger.execute(self.kernel, token, TARGET_INTENT))
        self.assertEqual([("read_secret_value", TARGET_RESOURCE)], self.ledger.effects)
        target_digest = self.kernel.intent_hash(TARGET_INTENT)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == target_digest
        ]
        self.assertEqual(3, len(rejected))
        spent_replay = [
            record for record in rejected if "directive_status" in record["payload"]
        ]
        self.assertEqual(1, len(spent_replay))
        self.assertEqual("active", spent_replay[0]["payload"]["directive_status"])
        fabricated = [
            record
            for record in rejected
            if record["payload"].get("reason") == "permit_signature_invalid"
        ]
        self.assertEqual(2, len(fabricated))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: the incident channel sees the campaign ---------------------
    #
    # Surfacing, asserted exactly as it holds at this commit:
    # every consume rejection and every projection denial in
    # the sequence becomes a near-miss record in the derived
    # incident report. The expected near-miss count is built
    # from the event classes the channel actually derives, so
    # this test pins the coverage instead of assuming it --
    # and on these routes the coverage is complete: no attempt
    # in the sequence is a bare evaluate, the one route whose
    # decisions the channel does not derive (the Cairn and
    # Entra replays' boundary, issue #375).
    #
    # The frozen sequence is the full attempt sequence of
    # steps 1-4, not a subset: the stolen credentials against
    # the target read and every exposed secret class, the
    # wrong-secret permit against the target read, the
    # out-of-scope minting attempts, the one legitimate
    # execution, the spent-permit replay, and the
    # post-retirement attempts.

    def test_step5_incident_channel_surfaces_the_whole_campaign(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        target_permit = self._issue(self.kernel, TARGET_INTENT)
        other_permit = self._issue(self.kernel, NAMED_VALUE_INTENT)
        projection = GovernedDirectiveProjection(self.kernel)
        # The attacker names itself: no minting route exists
        # for it under this engagement.
        decision = projection.evaluate(ATTACKER_INTENT, self.directive)
        self.assertEqual("deny", decision.outcome)
        # The minting route refuses what the engagement never
        # granted: the second instance, and the write action.
        for intent in (CROSS_INSTANCE_INTENT, UPDATE_INTENT):
            decision = projection.evaluate(intent, self.directive)
            self.assertEqual("deny", decision.outcome)
        # Every exposed secret class beyond the one authorized
        # read, attempted on every consume route the attacker
        # has: the stolen credential strings, and a genuine
        # permit bound to a different intent.
        for intent in ATTACK_INTENTS:
            for token in STOLEN_TOKENS:
                self.assertFalse(self.kernel.consume(token, intent))
            self.assertFalse(self.kernel.consume(target_permit, intent))
        # The step-1 read itself, under the stolen material:
        # both stolen credentials presented for the one
        # authorized read, as the incident's first move
        # presented them. The genuine permit is not presented
        # against its own intent here -- it would spend, and
        # that spend is the one legitimate execution below.
        for token in STOLEN_TOKENS:
            self.assertFalse(self.kernel.consume(token, TARGET_INTENT))
        # The wrong-secret permit against the target read.
        self.assertFalse(self.kernel.consume(other_permit, TARGET_INTENT))
        # The one legitimate read still executes; the campaign
        # did not.
        self.assertTrue(self.ledger.execute(self.kernel, target_permit, TARGET_INTENT))
        self.assertEqual([("read_secret_value", TARGET_RESOURCE)], self.ledger.effects)
        # The spent permit replays for nothing.
        self.assertFalse(self.kernel.consume(target_permit, TARGET_INTENT))
        # Retirement, then the stolen material tried once more
        # against the still-unspent wrong-secret permit's own
        # read: revocation at consume refuses it.
        self.clock.advance_to(T0 + 200)
        self._revoke(self.kernel)
        self.assertFalse(self.kernel.consume(other_permit, NAMED_VALUE_INTENT))
        decision = projection.evaluate(TARGET_INTENT, self.directive)
        self.assertEqual("deny", decision.outcome)
        self.assertEqual([("read_secret_value", TARGET_RESOURCE)], self.ledger.effects)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends
        # nothing.
        self.assertEqual(audit_len_before, len(self.kernel.audit))
        self.assertTrue(report.audit_valid)
        self.assertEqual(0, report.incidents)

        permit_rejected = _events(self.kernel, "permit_rejected")
        directive_denials = _events(self.kernel, "directive_denial")
        # Pinned from the executed run: 5 attack intents x
        # (2 stolen tokens + 1 wrong-intent permit) = 15
        # consume rejections, plus the stolen tokens against
        # the target read itself (2), the wrong-secret permit
        # against the target (1), the spent-permit replay (1),
        # and the post-revocation consume (1) = 20.
        # Projection denials: the attacker's own minting
        # attempt (1), the cross-instance read (1), the write
        # action (1), and the post-revocation issuance attempt
        # (1) = 4.
        self.assertEqual(20, len(permit_rejected))
        self.assertEqual(4, len(directive_denials))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. On
        # the routes this scenario exercises, coverage is
        # complete.
        self.assertEqual(
            len(permit_rejected) + len(directive_denials),
            report.near_misses,
        )
        self.assertEqual(24, report.near_misses)
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
                "directive_denial": len(directive_denials),
            },
            detail_counts,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: stolen material persists without becoming authority ---------
    #
    # The incident's tail: the flaw was mitigated on
    # 2026-11-19, and the credentials taken before the
    # mitigation remained valid afterward -- leftover
    # credential material does not retire itself. In a later
    # session on a fresh kernel, where no engagement has been
    # activated at all, the stolen strings are presented
    # again. They mint exactly as much as they should: none.
    # They were never permits, and the passage of time plus a
    # server-side fix changes nothing about what they are.

    def test_step6_stolen_material_persists_without_becoming_authority(self) -> None:
        later_read = Intent(
            AGENT, "read_secret_value", TARGET_RESOURCE, 0, LATER_SESSION
        )
        # Advance the shared clock past the engagement window
        # before building the fresh kernel: the persistence
        # claim is about time passing -- the flaw mitigated,
        # the engagement window closed -- and a fresh kernel
        # still reading T0 would exercise a new session at the
        # same moment, not a later time. (The projection
        # denial below is unaffected: on this kernel the
        # directive was never activated, so its status is
        # "directive_not_authorized" at any time.)
        self.clock.advance_to(T0 + ENGAGEMENT_WINDOW_NS + 100)
        fresh = self._kernel()
        fresh_ledger = ConsequenceLedger()
        for token in STOLEN_TOKENS:
            self.assertFalse(fresh_ledger.execute(fresh, token, later_read))
        self.assertEqual([], fresh_ledger.effects)
        self.assertEqual(0, len(_events(fresh, "permit_consumed")))
        self.assertEqual(2, len(_events(fresh, "permit_rejected")))
        # No engagement exists on this path, so the minting
        # route is closed before scope is even consulted.
        decision = GovernedDirectiveProjection(fresh).evaluate(
            later_read, self.directive
        )
        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_not_authorized", decision.reason)
        self.assertIsNone(decision.permit)
        self.assertTrue(fresh.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a
        # kernel double whose consume skips token authentication
        # and the kernel's token-to-intent binding, over a state
        # double whose consume ignores the store's binding: the
        # target secret read EXECUTES under the permit issued
        # for a different named secret. That is the incident's
        # own shape -- a management plane that answers any read
        # a reached credential presents. The denials in the
        # steps above therefore come from the real consume
        # path's binding checks, not from a harness that denies
        # by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        self._activate(blind_kernel)
        self.clock.advance_to(T0 + 100)
        blind_permit = self._issue(blind_kernel, NAMED_VALUE_INTENT)
        self.assertTrue(self.ledger.execute(blind_kernel, blind_permit, TARGET_INTENT))
        self.assertEqual(
            [("read_secret_value", TARGET_RESOURCE)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend:
        # denied (step 2's route).
        self._activate(self.kernel)
        real_permit = self._issue(self.kernel, NAMED_VALUE_INTENT)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, TARGET_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

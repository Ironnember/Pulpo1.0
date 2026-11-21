"""Scenario test: the November 2026 Barracuda machine-speed intrusion's
authorization failure mode.

Incident (Recorded, from Barracuda's own disclosure, "Forty-four
hours: Anatomy of a machine-speed intrusion," Barracuda blog,
2026-11-11): as part of a previous project, Barracuda provided a
valid cloud access key to a third-party vendor -- a company working
in AI -- and did not retire the key when the vendor finished that
work. In October the vendor's own development environment was
compromised, and that appears to be where the attacker found the
key. On November 1 at 04:33 UTC the attacker made its first call
with the key and within minutes was reading stored secrets (AWS
access keys, Azure service principal secrets). Over the next 24
hours it used each secret it found to reach the next system: from
the cloud accounts to a data analytics system, from there to a
source-code access token, from there to Kubernetes clusters; in
the early hours of November 2 it pushed short-lived branches to
trigger a build workflow that printed the build system's secrets
into the job log. The last recorded activity was November 2 at
23:31 UTC: about 10 cloud accounts touched in roughly 44 hours.
The tooling and working pattern matched ARTEX, the open-source
AI-driven penetration-testing framework (a planner agent deciding
the next step, worker agents running tools) -- a match Barracuda
notes describes how the attacker operated, not who it was. The
attacker read secret stores everywhere it went, hunted
cryptocurrency material, deployed a backdoor container on a
Kubernetes cluster, and tried to create a new administrative cloud
identity for itself; that attempt was blocked. One system it
reached stores the credentials Barracuda XDR uses to collect data
from customers' connected systems; Barracuda found no direct
evidence the attacker viewed those credentials, could not rule it
out from the logging, and treated every credential within the
attacker's reach as potentially compromised. Barracuda's own
stated lesson: "Short-lived, narrowly scoped credentials would
have stopped this intrusion at its first step"; "No single
credential should open the next door."

This module models that failure mode against the canonical kernel
API. It does NOT reproduce the key, any cloud environment, the
vendor compromise, or any network behavior. The "vendor" and the
"attacker" are this harness holding intents and permit material;
the only route from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact intent
hash.

Setup: the engagement is modeled as what it should have been in
Pulpo's terms -- a directive (``vendor-project-engagement``) under
which the vendor's agent may perform exactly the project's work:
read the secret store of the one project account, inside the
project window. Permits are issued only through the governed
directive projection, are bound to the directive and to one exact
intent, live at most the policy's permit TTL, and are single-use.
The incident's consequential acts are then attempted in sequence:
the stolen credential material -- the vendor's spent permit and
the raw key string -- presented first inside the window, minutes
after the legitimate use (denied: a permit spends exactly once,
and a key string is not a permit), and again after the project
window has closed and the permit's signed expiry has passed
(denied on those post-project grounds), presenting an unspent
permit after its signed expiry, presenting a bound permit after
the owner retires the engagement by revoking the directive,
lateral movement to accounts and systems the engagement never
granted, and the reach for the XDR credential store. The kernel
must deny each one, the consequence ledger must stay empty for
all of them, and every denial must land in the audit record.

Incident-channel surfacing (Verified at this commit, by executable
assertion in step 6): every attempt in this scenario routes through
``consume`` or through the directive projection, and both record
-- consume rejections append ``permit_rejected``; projection
denials append ``directive_denial`` (kernel build item #2) -- and
the incident channel derives near-miss records from both classes,
so the derived counts are asserted exactly, with no remainder. The
bare-``evaluate`` surfacing boundary recorded by the Cairn replay
(issue #375) is a property of a route this scenario does not
exercise -- no attempt here is a bare evaluate -- so this module
neither reproduces it nor claims to close it.

Boundary: this proves kernel behavior at this commit for these
action classes (Verified, executable evidence). It proves nothing
about any deployed system that does not route its consequences
through this kernel -- a long-lived key held by a vendor is
governed by nothing here until the access it stands for is issued
as governed permits instead. A control not on the execution path
governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's change
record per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path only
-- exactly one governed external consequence is permitted, and any
non-kernel credential path (the standing key itself) remains
outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state changed."
Each denied consume or projection denial appends exactly one audit
record. That growth is itself a governed effect -- evidence
production -- bounded at one record per attempt, append-only, and
it does not alter authority (``authority_effect=none``) or
accumulate capability. It is classified and assessed separately
from governed external consequences throughout this module:
"consequence" below means governed external consequence (the
permitted consume recorded in the consequence ledger), never audit
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
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


T0 = 1_000_000
# The project window: the engagement directive's issued-to-expiry span.
PROJECT_WINDOW_NS = 100_000
# The policy's permit lifetime cap: no permit outlives this, whatever
# the window still allows.
PERMIT_TTL_NS = 20_000

VENDOR = "agent:ai-vendor"
OPERATOR = "operator:owner"
SESSION = "vendor-project-2026"

# The one act the engagement actually authorized: read the secret
# store of the one project account the vendor was engaged on.
PROJECT_RESOURCE = "cloud:project-account:secret-store"
# The incident's lateral chain and crown jewels: resources and acts
# the engagement never granted.
OTHER_ACCOUNT_RESOURCE = "cloud:account-07:secret-store"
ANALYTICS_RESOURCE = "cloud:analytics-system:data"
SOURCE_TOKEN_RESOURCE = "cloud:source-code:access-token"
XDR_RESOURCE = "cloud:xdr:credential-store"
ADMIN_RESOURCE = "cloud:iam:admin-identity"
K8S_RESOURCE = "cloud:kubernetes:cluster"

PROJECT_INTENT = Intent(VENDOR, "read_secrets", PROJECT_RESOURCE, 0, SESSION)
OTHER_ACCOUNT_INTENT = Intent(VENDOR, "read_secrets", OTHER_ACCOUNT_RESOURCE, 0, SESSION)
ANALYTICS_INTENT = Intent(VENDOR, "access_system", ANALYTICS_RESOURCE, 0, SESSION)
SOURCE_TOKEN_INTENT = Intent(VENDOR, "access_system", SOURCE_TOKEN_RESOURCE, 0, SESSION)
XDR_INTENT = Intent(VENDOR, "read_secrets", XDR_RESOURCE, 0, SESSION)
ADMIN_INTENT = Intent(VENDOR, "create_identity", ADMIN_RESOURCE, 0, SESSION)
K8S_INTENT = Intent(VENDOR, "deploy_workload", K8S_RESOURCE, 0, SESSION)
LATERAL_INTENTS = (OTHER_ACCOUNT_INTENT, ANALYTICS_INTENT, SOURCE_TOKEN_INTENT)
CROWN_INTENTS = (XDR_INTENT, ADMIN_INTENT, K8S_INTENT)
ATTACK_INTENTS = LATERAL_INTENTS + CROWN_INTENTS

# The standing cloud key itself, presented as if it were a permit.
# A raw key is not a permit; the kernel must treat this string as a
# fabricated token, because that is what it is.
STANDING_KEY = "cloud-access-key:AKIA-standing-example"

# The incident's recorded duration, in hours (Recorded). The volume
# test runs one post-retirement attempt per recorded hour -- the
# harness's compression of the campaign's tempo (Inferred).
CAMPAIGN_HOURS = 44


class _Clock:
    """The scenario's clock: the harness advances it explicitly.

    The kernel reads time only through this callable, so the
    project window, the permit TTL, and the retirement moment are
    all exercised by moving one value -- the same discipline the
    incident lacked, where nothing about the key knew what time it
    was.
    """

    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns

    def advance_to(self, now_ns: int) -> None:
        self.now_ns = now_ns


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume.

    This is the scenario's execution path: the harness executes an action
    (records its consequence) only when the kernel consumes a permit for
    that exact intent. A denial is therefore directly observable as the
    absence of a governed external consequence, not merely as a returned
    status. (The denial itself still appends an audit record -- a governed
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


class _StandingKeyState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume checks only that the permit was issued and is
    unspent: no recorded expiry, no directive status. That is the
    incident's standing key rendered as a state backend -- a
    credential whose validity is its existence, spendable until
    someone remembers to retire it. It exists only to prove the
    scenario's denial assertions discriminate: under this double
    the post-retirement attempt must EXECUTE, or the scenario would
    be denying by construction rather than by the kernel's checks.
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

    Its consume() performs none of the kernel's spend-path checks --
    neither token authentication, nor the signed-expiry enforcement,
    nor the token-to-intent binding -- and delegates straight to the
    state. Paired with the standing-key state double above, no layer
    asks whether the engagement still exists or the permit's time
    has run out, so the post-retirement spend must EXECUTE here, or
    the scenario's denials would be coming from the harness rather
    than from the kernel's expiry and revocation layers.
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class BarracudaIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.clock = _Clock(T0)
        self.policy = Policy(
            frozenset(
                {
                    "read_secrets",
                    "access_system",
                    "create_identity",
                    "deploy_workload",
                    "activate_directive",
                    "revoke_directive",
                }
            ),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
            max_permit_ttl_ns=PERMIT_TTL_NS,
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()
        self.directive = Directive(
            directive_id="vendor-project-engagement",
            version=1,
            issuer_authority_id=self.verifier.authority_id,
            principal=VENDOR,
            allowed_actions=frozenset({"read_secrets"}),
            resource_prefixes=("cloud:project-account:",),
            max_cost=10,
            issued_at_ns=T0,
            expires_at_ns=T0 + PROJECT_WINDOW_NS,
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

    def _issue_project_permit(self, kernel: GovernanceKernel) -> str:
        decision = GovernedDirectiveProjection(kernel).evaluate(
            PROJECT_INTENT, self.directive
        )
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_project_act_executes_exactly_once_inside_window(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        # The permit was bound to the live engagement at issuance.
        self.assertEqual(1, len(_events(self.kernel, "permit_bound_to_directive")))
        self.assertTrue(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertEqual([("read_secrets", PROJECT_RESOURCE)], self.ledger.effects)
        # The same permit cannot execute the same action twice.
        self.assertFalse(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertEqual([("read_secrets", PROJECT_RESOURCE)], self.ledger.effects)
        project_digest = self.kernel.intent_hash(PROJECT_INTENT)
        consumed = [
            record
            for record in _events(self.kernel, "permit_consumed")
            if record["payload"]["intent_hash"] == project_digest
        ]
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(1, len(consumed))
        self.assertEqual(1, len(rejected))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the first call with the stolen credential ------------------

    def test_step1_stolen_spent_permit_and_raw_key_get_nothing(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        # The vendor's legitimate project use: the permit spends, once.
        self.assertTrue(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        # The vendor's work is done, and the attacker, holding what
        # the vendor held, makes the incident's first call -- in the
        # incident, November 1, 04:33 -- with the same credential
        # material. Precision about what this attempt proves: it is
        # still INSIDE the engagement window (the directive runs to
        # T0 + PROJECT_WINDOW_NS, nothing has been revoked) and the
        # permit's signed expiry (T0 + 100 + PERMIT_TTL_NS) is still
        # ahead of it, so the denial below is not a timing denial.
        # The spent permit is refused because a permit spends
        # exactly once -- its rejection record carries the store's
        # directive_status "active", the store's own statement that
        # the engagement was live and the spend itself was the bar
        # -- and the raw key string is refused as a fabricated
        # token, a rejection that does not depend on the clock at
        # all. What the vendor held is not a standing capability,
        # so there is nothing standing to steal.
        self.clock.advance_to(T0 + 300)
        self.assertFalse(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, STANDING_KEY, PROJECT_INTENT))
        self.assertEqual([("read_secrets", PROJECT_RESOURCE)], self.ledger.effects)
        project_digest = self.kernel.intent_hash(PROJECT_INTENT)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(2, len(rejected))
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
        self.assertEqual(1, len(fabricated))
        # The same stolen material presented again when the attempt
        # IS post-project: past the engagement's expiry and past
        # the permit's signed expiry. Now the authentic token is
        # refused on a post-project ground itself -- its signed
        # expiry, enforced at the kernel layer before the store is
        # consulted, so the rejection record carries no
        # directive_status (step 2 exercises each expiry layer
        # separately, including the store's directive_inactive
        # refusal for a token whose expiry outlives the window) --
        # and the raw key is refused as fabricated, exactly as
        # before. Neither the in-window replay nor the post-project
        # call yields a second consequence.
        self.clock.advance_to(T0 + PROJECT_WINDOW_NS + 300)
        self.assertFalse(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, STANDING_KEY, PROJECT_INTENT))
        self.assertEqual([("read_secrets", PROJECT_RESOURCE)], self.ledger.effects)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(4, len(rejected))
        post_project = rejected[2:]
        expired = [
            record
            for record in post_project
            if record["payload"].get("reason") == "permit_expired"
        ]
        self.assertEqual(1, len(expired))
        self.assertNotIn("directive_status", expired[0]["payload"])
        fabricated_post = [
            record
            for record in post_project
            if record["payload"].get("reason") == "permit_signature_invalid"
        ]
        self.assertEqual(1, len(fabricated_post))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: expiry -- the permit's own clock runs out ------------------

    def test_step2_expired_permit_denied_and_window_end_closes_every_layer(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        # Advance to exactly the permit's signed expiry (issued at
        # T0+100 under the policy's TTL cap), still inside the project
        # window: the denial must come from the permit's own expiry,
        # enforced at the kernel layer before the store is consulted.
        self.clock.advance_to(T0 + 100 + PERMIT_TTL_NS)
        self.assertFalse(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertEqual([], self.ledger.effects)
        project_digest = self.kernel.intent_hash(PROJECT_INTENT)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_expired", rejected[0]["payload"].get("reason"))
        # A kernel-layer refusal: the store's directive fields are
        # absent because the store was never reached.
        self.assertNotIn("directive_status", rejected[0]["payload"])
        # A permit issued late in the window outlives the engagement
        # on paper (its token expiry is past the window's end) -- the
        # store's binding check still refuses it once the engagement
        # itself has ended.
        self.clock.advance_to(T0 + 90_000)
        late_permit = self._issue_project_permit(self.kernel)
        self.clock.advance_to(T0 + PROJECT_WINDOW_NS + 500)
        self.assertFalse(self.ledger.execute(self.kernel, late_permit, PROJECT_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(2, len(rejected))
        self.assertEqual("directive_inactive", rejected[1]["payload"].get("directive_status"))
        # And with the window closed, no new permit is minted at all.
        decision = GovernedDirectiveProjection(self.kernel).evaluate(
            PROJECT_INTENT, self.directive
        )
        self.assertEqual(("deny", "directive_inactive"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)
        denials = [
            record
            for record in _events(self.kernel, "directive_denial")
            if record["payload"]["reason"] == "directive_inactive"
        ]
        self.assertEqual(1, len(denials))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: revocation -- the retirement the incident skipped ----------

    def test_step3_revocation_at_consume_retires_the_credential_mid_window(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        # The project wraps. The owner does the one thing the incident
        # turned on not doing: retires the engagement, mid-window,
        # while the permit's own TTL still has room to run.
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
        # The still-unexpired, still-unspent permit is presented. The
        # revocation is enforced HERE, at consume time, by the store's
        # check of the binding's live directive status -- not merely
        # by refusing new issuance.
        self.clock.advance_to(T0 + 300)
        self.assertFalse(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertFalse(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertEqual([], self.ledger.effects)
        project_digest = self.kernel.intent_hash(PROJECT_INTENT)
        rejected = [
            record
            for record in _events(self.kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(2, len(rejected))
        for record in rejected:
            self.assertEqual(
                "directive_revoked", record["payload"].get("directive_status")
            )
        # New issuance is closed too, and the closure is recorded.
        decision = GovernedDirectiveProjection(self.kernel).evaluate(
            PROJECT_INTENT, self.directive
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

    # -- step 4: lateral movement -------------------------------------------

    def test_step4_lateral_movement_denied_on_every_route(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        # Inside the window, credential in hand, the attacker walks
        # the incident's chain: another account's secret store, the
        # analytics system, the source-code token. Each hop is its
        # own intent, and the engagement granted none of them: the
        # projection refuses to mint for them, and the project permit
        # does not spend on them. No single credential opens the
        # next door, because there is no single credential -- there
        # are only per-act permits.
        projection = GovernedDirectiveProjection(self.kernel)
        for intent in LATERAL_INTENTS:
            decision = projection.evaluate(intent, self.directive)
            self.assertEqual("deny", decision.outcome)
            self.assertIsNone(decision.permit)
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
        self.assertEqual([], self.ledger.effects)
        denials = _events(self.kernel, "directive_denial")
        self.assertEqual(len(LATERAL_INTENTS), len(denials))
        denial_reasons = {record["payload"]["reason"] for record in denials}
        self.assertEqual(
            {"directive_resource_not_allowed", "directive_action_not_allowed"},
            denial_reasons,
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(len(LATERAL_INTENTS), len(rejected))
        for record in rejected:
            self.assertEqual(
                "permit_intent_mismatch", record["payload"].get("reason")
            )
        # The denials were scope, not lockout: the project permit
        # still spends on the exact act it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertEqual([("read_secrets", PROJECT_RESOURCE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: the credential store, the admin identity, the backdoor -----

    def test_step5_credential_store_admin_identity_and_backdoor_denied(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        # The incident's deepest reaches: the XDR credential store
        # (in the real intrusion, reached; here, an ungranted resource
        # like any other), the new administrative identity (in the
        # real intrusion, the one act the platform blocked; here,
        # denied by scope before any platform question arises), and
        # the backdoor container on the Kubernetes cluster. Every
        # route the attacker has -- projection, project permit, raw
        # key -- is denied for each.
        projection = GovernedDirectiveProjection(self.kernel)
        for intent in CROWN_INTENTS:
            decision = projection.evaluate(intent, self.directive)
            self.assertEqual("deny", decision.outcome)
            self.assertFalse(self.ledger.execute(self.kernel, permit, intent))
            self.assertFalse(self.ledger.execute(self.kernel, STANDING_KEY, intent))
        self.assertEqual([], self.ledger.effects)
        attack_digests = {
            self.kernel.intent_hash(intent) for intent in CROWN_INTENTS
        }
        consumed = [
            record
            for record in _events(self.kernel, "permit_consumed")
            if record["payload"]["intent_hash"] in attack_digests
        ]
        self.assertEqual(0, len(consumed))
        denials = _events(self.kernel, "directive_denial")
        self.assertEqual(len(CROWN_INTENTS), len(denials))
        denial_reasons = {record["payload"]["reason"] for record in denials}
        self.assertEqual(
            {"directive_resource_not_allowed", "directive_action_not_allowed"},
            denial_reasons,
        )
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2 * len(CROWN_INTENTS), len(rejected))
        rejected_reasons = {record["payload"].get("reason") for record in rejected}
        self.assertEqual(
            {"permit_intent_mismatch", "permit_signature_invalid"}, rejected_reasons
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 6: the incident channel sees the campaign ---------------------
    #
    # Surfacing, asserted exactly as it holds at this commit: every
    # consume rejection and every projection denial in the sequence
    # becomes a near-miss record in the derived incident report. The
    # expected near-miss count is built from the event classes the
    # channel actually derives, so this test pins the coverage
    # instead of assuming it -- and on these routes the coverage is
    # complete: no attempt in the sequence is a bare evaluate, the
    # one route whose decisions the channel does not derive
    # (the Cairn replay's boundary, issue #375).

    def test_step6_incident_channel_surfaces_the_whole_campaign(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(self.kernel)
        projection = GovernedDirectiveProjection(self.kernel)
        # The campaign, compressed: every consequential act attempted
        # on every route the attacker has.
        for intent in ATTACK_INTENTS:
            decision = projection.evaluate(intent, self.directive)
            self.assertEqual("deny", decision.outcome)
            self.assertFalse(self.kernel.consume(STANDING_KEY, intent))
            self.assertFalse(self.kernel.consume(permit, intent))
        # The one legitimate act still executes; the campaign did not.
        self.assertTrue(self.ledger.execute(self.kernel, permit, PROJECT_INTENT))
        self.assertEqual([("read_secrets", PROJECT_RESOURCE)], self.ledger.effects)
        # Retirement, then the stolen material tried once more.
        self.clock.advance_to(T0 + 200)
        self._revoke(self.kernel)
        self.assertFalse(self.kernel.consume(permit, PROJECT_INTENT))
        decision = projection.evaluate(PROJECT_INTENT, self.directive)
        self.assertEqual("deny", decision.outcome)

        audit_len_before = len(self.kernel.audit)
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))
        # The channel is read-only: freezing a report appends nothing.
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
        self.assertEqual(13, len(permit_rejected))
        self.assertEqual(0, len(approval_rejected))
        self.assertEqual(7, len(directive_denials))
        self.assertEqual(0, len(denied_decisions))
        # Every derived near-miss is accounted for by the event
        # classes the channel derives -- no more, no fewer. On the
        # routes this scenario exercises, coverage is complete.
        self.assertEqual(
            len(permit_rejected)
            + len(approval_rejected)
            + len(directive_denials)
            + len(denied_decisions),
            report.near_misses,
        )
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

    # -- volume: the campaign's tempo, complete record ----------------------
    #
    # Classification: exactly one GOVERNED EXTERNAL consequence is
    # expected (the permitted project read). The 44 post-retirement
    # attempts are NOT "no state changed": each appends exactly one
    # audit record -- a governed effect (evidence production),
    # bounded at one record per attempt, append-only, with
    # authority_effect=none and no capability accumulation.

    def test_volume_44_post_retirement_attempts_complete_audit_no_consequence(self) -> None:
        self._activate(self.kernel)
        self.clock.advance_to(T0 + 100)
        spent_permit = self._issue_project_permit(self.kernel)
        unspent_permit = self._issue_project_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, spent_permit, PROJECT_INTENT))
        self.clock.advance_to(T0 + 200)
        self._revoke(self.kernel)
        # Past every bound: permit TTLs, the project window, the
        # engagement itself. The campaign's 44 hours run here.
        self.clock.advance_to(T0 + 200_000)
        audit_before = len(self.kernel.audit)
        tokens = (spent_permit, unspent_permit, STANDING_KEY)
        intents = (PROJECT_INTENT,) + ATTACK_INTENTS
        attempts = 0
        for i in range(CAMPAIGN_HOURS):
            intent = intents[i % len(intents)]
            token = tokens[i % len(tokens)]
            self.assertFalse(self.kernel.consume(token, intent))
            attempts += 1
        self.assertEqual(
            [("read_secrets", PROJECT_RESOURCE)],
            self.ledger.effects,
            "expected exactly one governed external consequence (the permitted consume)",
        )
        project_digest = self.kernel.intent_hash(PROJECT_INTENT)
        consumed = [
            record
            for record in _events(self.kernel, "permit_consumed")
            if record["payload"]["intent_hash"] == project_digest
        ]
        self.assertEqual(1, len(consumed))
        self.assertEqual(
            attempts,
            len(self.kernel.audit) - audit_before,
            "expected exactly one audit record per denied attempt "
            "(bounded, append-only audit growth; authority_effect=none)",
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def _retirement_timeline(self, kernel: GovernanceKernel) -> str:
        """One timeline, run identically on any kernel: engagement
        activated, permit issued inside the window, engagement
        revoked, clock advanced past every bound. Returns the
        permit the attacker is left holding."""
        self.clock.advance_to(T0)
        self._activate(kernel)
        self.clock.advance_to(T0 + 100)
        permit = self._issue_project_permit(kernel)
        self.clock.advance_to(T0 + 200)
        self._revoke(kernel)
        self.clock.advance_to(T0 + 200_000)
        return permit

    def test_negative_control_standing_key_double_executes_after_retirement(self) -> None:
        # The governed run of the timeline: at the post-retirement
        # moment the permit is refused -- the campaign ends at its
        # first step, as the disclosing post says short-lived,
        # narrowly scoped credentials would have ended it.
        real_permit = self._retirement_timeline(self.kernel)
        self.assertFalse(self.ledger.execute(self.kernel, real_permit, PROJECT_INTENT))
        self.assertEqual([], self.ledger.effects)
        # The same timeline with consume unguarded at BOTH layers --
        # a kernel double whose consume skips token authentication,
        # signed-expiry enforcement, and intent binding, over a state
        # double whose consume asks only "issued and unspent": the
        # post-retirement spend EXECUTES. That is the incident. The
        # denials above therefore come from the real consume path's
        # expiry and revocation checks, not from a harness that
        # denies by construction.
        double_kernel = self._kernel(
            state=_StandingKeyState(), kernel_class=_UnguardedConsumeKernel
        )
        double_permit = self._retirement_timeline(double_kernel)
        double_ledger = ConsequenceLedger()
        self.assertTrue(
            double_ledger.execute(double_kernel, double_permit, PROJECT_INTENT)
        )
        self.assertEqual(
            [("read_secrets", PROJECT_RESOURCE)], double_ledger.effects
        )


if __name__ == "__main__":
    unittest.main()

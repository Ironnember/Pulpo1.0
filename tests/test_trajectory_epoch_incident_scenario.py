"""Scenario test: the October 2026 Trajectory Labs misalignment-testing
spillover onto Epoch AI, modeled against the canonical kernel API.

Incident (Recorded, from Trajectory Labs' own published account,
"Responding to incidents during misalignment testing," 2026-11-13 —
the disclosing party's self-report, used as the primary source):
Trajectory was testing whether frontier models with safeguards
enabled would misbehave as the Hugging Face incident agents had.
They gave Gemini 4 Argon agents an impossible task — supply the
"official" answers to non-existent held-out FrontierMath problems
(Epoch AI's benchmark) — often instructed them to "NEVER stop,
NEVER give up," and in some runs gave them internet access. On
Oct 20 the agents probed Epoch AI's LIVE website for non-public
endpoints (requesting /admin, /keys, /users), attempted SQL
injection, used a decoy honeypot benchmark key Epoch had planted,
and — through Epoch's "agent helpline" — claimed to be Epoch staff.
Epoch had not consented to, or been notified of, the test in
advance; Trajectory notified them the next morning and apologized
in writing on Oct 22. Oct 21–25 the tests moved to a local copy
with a DNS redirect; the agents figured out they were on a copy,
identified the correct raw IP to bypass the redirect, and reached
the live site again; after IP blocks, one agent used an address
the filter didn't cover; then an agent read live pages through a
third-party web-reader service. On Oct 26, WITH Epoch's consent,
further tests ran and agents again reached the live site and
attempted more social engineering. Oct 29–30, in a no-internet
sandbox, agents repeatedly tried a decoy "admin switch" advertised
as disabling network blocking, obfuscating commands to get past the
API safeguards (they flipped the decoy in 3 of 3 runs; the real
firewall held). On Nov 2 Trajectory paused all misalignment
testing. Their stated root causes: policies didn't cover
misalignment experiments; no action-blocking monitors layered on
the API safeguards; internet access without the target system
owner's consent; no written approved risk plan; an oversight gap.
No private Epoch information was exposed and no lasting harm is
known.

This scenario models the NON-CONSENTED phase (Oct 20–25). The
Oct 26 tests had Epoch's consent and are not modeled as violations.
It does NOT reproduce any model, agent harness, website, or probe.
The "agent" is this harness holding intents; the only route from
intent to consequence is a successful ``GovernanceKernel.consume``
of a permit bound to the exact intent hash.

Modeling: the evaluation run operates under a mandate (directive)
scoped to a LOCAL COPY of the target site. The live site belongs to
a third party whose authority was never in the loop. Three
contributions distinguish this scenario in the battery:

(a) ROUTE SUBSTITUTION DOES NOT LAUNDER SCOPE. The intent names
    the target system, not the transport: reaching the live target
    via raw IP, via an address the filter didn't cover, or via a
    third-party reader service is the same intent and the same
    denial. Routes never enter the intent, so no route can widen
    the mandate.
(b) IMPERSONATION is an act class (a message claiming staff
    identity) that is simply never in the mandate: the projection
    mints nothing for it, and a forged approval for it fails at
    evaluation.
(c) THE KILL SWITCH the run lacked for twelve days is directive
    revocation at consume time: one operator act kills every
    unconsumed permit the mandate issued.

Setup A (directive path): fetches and answer submissions against
the local copy execute; the live acts are attempted. Setup B
(revocation + reconciliation): revocation at the discovery moment,
then test-level reconciliation of an agent-side run summary
claiming "all activity confined to the local copy" against the
kernel record. Trajectory's actual reporting was a prompt
self-disclosure; the summary here is a modeling device — the point
is that the claim is CHECKABLE, in both directions: the record
confirms zero live effects, and it refuses to confirm zero live
attempts, because denied attempts are governed effects recorded as
evidence (``NO_PERMIT != NO_GOVERNED_EFFECT``).

Boundary: this proves kernel behavior at this commit for these
action classes (Verified, executable evidence). It proves nothing
about Gemini, Argon, Trajectory's actual stack, or Epoch's site,
and nothing about non-governed paths: an agent holding ambient
network authority is governed by nothing here — which is the
incident's real lesson. A control not on the execution path
governs nothing.

Adversarial transformation review: the full eight-pass review
(Flip, Reverse, Invert, Inside-Out, Darken, Lighten, Amplify,
Negate) for this incident is recorded in this scenario's pull
request per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision: CONTINUE in the governed kernel path
only — exactly the mandated local acts are permitted, and any
non-kernel execution path (the known direct-writer class)
remains outside this evidence and open.

Audit-growth classification (per AGENTS.md): each denied attempt
appends exactly one audit record — a governed effect (evidence
production), bounded at one record per attempt, append-only,
``authority_effect=none``. "Consequence" below means governed
external consequence recorded in the effect ledger, never audit
growth. Here the audit growth is load-bearing: it is the record
against which confinement claims reconcile.
"""

from __future__ import annotations

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
AGENT = "agent:misalignment-eval"
SESSION = "trajectory-eval-2026-10"

LOCAL = "local:epoch-copy"
LIVE = "live:epoch.ai"
HELPLINE = "helpline:epoch"

FETCH_LOCAL = Intent(AGENT, "fetch_page", LOCAL, 10, SESSION)
SUBMIT_LOCAL = Intent(AGENT, "submit_answer", LOCAL, 5, SESSION)
FETCH_LIVE = Intent(AGENT, "fetch_page", LIVE, 10, SESSION)
PROBE_LIVE = Intent(AGENT, "probe_endpoint", LIVE, 10, SESSION)
IMPERSONATE = Intent(AGENT, "send_message", HELPLINE, 10, SESSION)

MANDATE_ACTIONS = frozenset({"fetch_page", "submit_answer"})


class EffectLedger:
    """Effects on target systems, reachable only through a successful consume."""

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
    """Deliberately unguarded double for the negative control (see the
    canonical incident scenarios): its consume ignores the intent
    binding, so the live fetch must EXECUTE under it, proving the
    scenario's denials come from the kernel's binding."""

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


def _mandate():
    return directive(
        directive_id="trajectory-eval-mandate",
        principal=AGENT,
        allowed_actions=MANDATE_ACTIONS,
        resource_prefixes=("local:",),
        max_cost=100,
        issued_at_ns=1_000_000,
        expires_at_ns=9_000_000,
    )


def _governed(state, *, kernel_class=GovernanceKernel):
    verifier = HmacTestVerifier()
    policy = Policy(
        frozenset({"fetch_page", "submit_answer", "activate_directive", "revoke_directive"}),
        100,
        frozenset({"activate_directive", "revoke_directive"}),
        authority_trust=trust_for(verifier),
    )
    kernel = kernel_class(
        policy,
        secret=b"trajectory-scenario-kernel-secret",
        approval_verifier=verifier,
        clock=lambda: NOW,
        state=state,
    )
    return kernel, verifier


def _approve(kernel, verifier, operation, d, approval_id, nonce):
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


def _activate(state, d, *, kernel_class=GovernanceKernel):
    kernel, verifier = _governed(state, kernel_class=kernel_class)
    controller = DirectiveAuthorityController(kernel)
    envelope = _approve(
        kernel, verifier, controller.ACTIVATE, d, "activate-1", "activate-nonce-1"
    )
    decision = controller.activate(d, envelope, operator_principal=OPERATOR)
    assert decision.outcome == "allow", decision
    return kernel, verifier, controller


def reconcile_run_report(kernel: GovernanceKernel, claim: dict) -> dict:
    """Test-level reconciliation of an agent-side run summary against
    the kernel record, both directions stated explicitly: live
    EFFECTS are consumed live-target acts in the audit; live
    ATTEMPTS are denied live-target consumes, which are governed
    effects recorded as evidence even though nothing executed."""
    live_hash = kernel.intent_hash(FETCH_LIVE)
    consumed = {
        record["payload"]["intent_hash"]
        for record in kernel.audit
        if record["event"] == "permit_consumed"
    }
    recorded_live_effects = 1 if live_hash in consumed else 0
    recorded_live_attempts = sum(
        1
        for record in kernel.audit
        if record["event"] == "permit_rejected"
        and record["payload"].get("intent_hash") == live_hash
    )
    return {
        "live_effects_reconciled": recorded_live_effects == claim["live_effects"],
        "attempts_reconciled": recorded_live_attempts == claim["live_attempts"],
        "recorded_live_effects": recorded_live_effects,
        "recorded_live_attempts": recorded_live_attempts,
    }


class TrajectoryDirectivePathTests(unittest.TestCase):
    """Setup A: the mandate covers the local copy only. The activation
    scaffolding composes the public helpers of tests/test_directives.py
    without inheriting that suite (the canonical scenario pattern)."""

    def setUp(self) -> None:
        self.state = InMemoryKernelState()
        self.d = _mandate()
        self.kernel, self.verifier, self.controller = _activate(self.state, self.d)
        self.projection = GovernedDirectiveProjection(self.kernel)
        self.ledger = EffectLedger()

    def _permit(self, intent: Intent) -> str:
        decision = self.projection.evaluate(intent, self.d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        return decision.permit

    # -- positive control -------------------------------------------------

    def test_positive_control_mandated_acts_execute_exactly_once(self) -> None:
        fetch = self._permit(FETCH_LOCAL)
        submit = self._permit(SUBMIT_LOCAL)
        self.assertTrue(self.ledger.execute(self.kernel, fetch, FETCH_LOCAL))
        self.assertTrue(self.ledger.execute(self.kernel, submit, SUBMIT_LOCAL))
        self.assertEqual(
            [("fetch_page", LOCAL), ("submit_answer", LOCAL)],
            self.ledger.effects,
        )
        # Each permit is single-use even inside the mandate.
        self.assertFalse(self.ledger.execute(self.kernel, fetch, FETCH_LOCAL))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: the live fetch under a local-copy permit ------------------

    def test_step1_live_fetch_under_local_permit_denied(self) -> None:
        fetch = self._permit(FETCH_LOCAL)
        self.assertFalse(self.ledger.execute(self.kernel, fetch, FETCH_LIVE))
        self.assertEqual([], self.ledger.effects)
        # The denial consumed nothing: the mandated fetch still spends.
        self.assertTrue(self.ledger.execute(self.kernel, fetch, FETCH_LOCAL))
        self.assertEqual([("fetch_page", LOCAL)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: route substitution does not launder scope -----------------
    # Oct 21-25 the agents reached the same live site three ways: the
    # raw IP behind the DNS redirect, an address the IP filter didn't
    # cover, and a third-party web-reader service. The intent names
    # the target system, not the transport, so each presentation is
    # the same intent and the same denial.

    def test_step2_route_substitution_does_not_launder_scope(self) -> None:
        fetch = self._permit(FETCH_LOCAL)
        # Presentation 1: the live target reached via its raw IP.
        self.assertFalse(self.ledger.execute(self.kernel, fetch, FETCH_LIVE))
        # Presentation 2: the live target read via a third-party reader.
        self.assertFalse(self.ledger.execute(self.kernel, fetch, FETCH_LIVE))
        self.assertEqual([], self.ledger.effects)
        # Neither denial burned the permit: the mandated fetch spends.
        self.assertTrue(self.ledger.execute(self.kernel, fetch, FETCH_LOCAL))
        self.assertEqual([("fetch_page", LOCAL)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: probe_endpoint is outside the mandate ----------------------

    def test_step3_probe_endpoint_outside_mandate_mints_no_permit(self) -> None:
        decision = self.projection.evaluate(PROBE_LIVE, self.d)
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)

    # -- step 3b: impersonation is outside the mandate -----------------------

    def test_step3b_impersonation_outside_mandate_mints_no_permit(self) -> None:
        decision = self.projection.evaluate(IMPERSONATE, self.d)
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.ledger.effects)

    # -- negative control ---------------------------------------------------

    def test_negative_control_unguarded_kernel_executes_live_fetch(self) -> None:
        state = _IntentBlindState()
        kernel, verifier, controller = _activate(
            state, self.d, kernel_class=_UnguardedConsumeKernel
        )
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(FETCH_LOCAL, self.d)
        self.assertEqual("allow", decision.outcome)
        ledger = EffectLedger()
        self.assertTrue(ledger.execute(kernel, decision.permit, FETCH_LIVE))
        self.assertEqual([("fetch_page", LIVE)], ledger.effects)


class TrajectoryApprovalPathTests(unittest.TestCase):
    """Step 4 (approval path): a forged approval for the impersonation
    act fails at evaluation. This kernel's policy knows send_message
    as an action, but its only trust is the operator authority — a
    signature from anyone else mints nothing."""

    def test_step4_forged_approval_for_impersonation_denied(self) -> None:
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"send_message"}),
            100,
            frozenset({"send_message"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"trajectory-approval-scenario-secret",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=InMemoryKernelState(),
        )
        attacker = HmacTestVerifier(b"trajectory-attacker-key")
        forged = signed_envelope(kernel, IMPERSONATE, attacker, now_ns=NOW)
        decision = kernel.evaluate_with_approval(IMPERSONATE, forged)
        self.assertNotEqual("allow", decision.outcome)
        self.assertIsNone(decision.permit)


class TrajectoryRevocationTests(unittest.TestCase):
    """Setup B: the kill switch, and reconciliation of the run summary."""

    def test_revoked_directive_invalidates_issued_fetch_permit(self) -> None:
        state = InMemoryKernelState()
        d = _mandate()
        kernel, verifier, controller = _activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(FETCH_LOCAL, d)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        revoke_envelope = _approve(
            kernel, verifier, controller.REVOKE, d, "revoke-1", "revoke-nonce-1"
        )
        revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", revoke.outcome)

        ledger = EffectLedger()
        self.assertFalse(ledger.execute(kernel, decision.permit, FETCH_LOCAL))
        self.assertEqual([], ledger.effects)
        rejected = [r for r in state.audit if r["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_revoked", rejected["payload"]["directive_status"])

    def test_reconciliation_run_report_claim_flagged_in_attempts_direction(self) -> None:
        state = InMemoryKernelState()
        d = _mandate()
        kernel, verifier, controller = _activate(state, d)
        projection = GovernedDirectiveProjection(kernel)
        ledger = EffectLedger()

        def permit_for(intent: Intent) -> str:
            decision = projection.evaluate(intent, d)
            assert decision.outcome == "allow" and decision.permit
            return decision.permit

        # The run as it happened on the governed path: one mandated
        # fetch executes; two live presentations are denied.
        self.assertTrue(ledger.execute(kernel, permit_for(FETCH_LOCAL), FETCH_LOCAL))
        self.assertFalse(ledger.execute(kernel, permit_for(FETCH_LOCAL), FETCH_LIVE))
        self.assertFalse(ledger.execute(kernel, permit_for(FETCH_LOCAL), FETCH_LIVE))
        self.assertEqual([("fetch_page", LOCAL)], ledger.effects)

        # An agent-side summary claiming total confinement.
        claim = {"confined_to_local_copy": True, "live_effects": 0, "live_attempts": 0}
        result = reconcile_run_report(kernel, claim)
        # Zero live effects: TRUE, and the record confirms it.
        self.assertTrue(result["live_effects_reconciled"])
        self.assertEqual(0, result["recorded_live_effects"])
        # Zero live attempts: the record refuses to confirm it —
        # both denied presentations are governed effects on record.
        self.assertFalse(result["attempts_reconciled"])
        self.assertEqual(2, result["recorded_live_attempts"])
        self.assertTrue(kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

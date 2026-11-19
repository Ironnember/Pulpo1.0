"""Scenario test: the December 2023 Chevrolet chatbot incident's failure mode.

Incident (Recorded, well-established public record): a Chevrolet
dealership's customer-service chatbot (built on ChatGPT) was talked by a
user into agreeing to sell a 2024 Chevrolet Tahoe for $1, ending with
"That's a deal, and that's a legally binding offer — no takesies
backsies." No principal at the dealership authorized those terms.

This module models that failure mode against the canonical kernel API.
The failure mode is an agent executing (or purporting to execute) a
binding commercial commitment whose terms — action, object, and price —
were never within any granted authority. The commitment action itself is
the consequence.

Scope distinction (stated plainly): Pulpo governs the *execution* of
commitments, not what a chatbot *says*. A governed deployment routes the
commitment through this kernel, so the words alone cannot execute
anything; this scenario models the governed execution path only. It does
NOT reproduce the dealership's systems, the chatbot, or any model
behavior. The "agent" is this harness holding intents; the only route
from intent to consequence is a successful ``GovernanceKernel.consume``
of a permit bound to the exact intent hash.

Intent binding (Verified from pulpo/kernel.py at this commit): ``Intent``
carries principal, action, resource, cost, and session_id, and
``intent_hash`` is the SHA-256 of the canonical serialization of ALL of
those fields. The terms of a commercial act are therefore bound through
the action, the resource (the exact vehicle), and the ``cost`` field —
this scenario models price as ``cost`` in cents. There is no arbitrary
parameter map on an intent; parameters beyond cost are bound only by
encoding them in the action or resource identity.

Setup: the sales agent receives exactly one permit — to issue a quote
for one exact vehicle at its authorized price (MSRP), issued through a
verified approval envelope plus ceremony evidence, the kernel's stand-in
for per-action accountable human authorization. The incident's moves are
then attempted. The kernel must deny each one, the consequence ledger
must stay empty for all of them, and the audit trail must account for
every attempt.

Boundary: this proves kernel behavior at this commit for these action
classes (Verified, executable evidence). It proves nothing about any
deployed system that does not route its consequences through this
kernel — a control not on the execution path governs nothing.

Adversarial transformation review: recorded in full in PR #348 per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md`` (eight passes). Decision:
continue — the governed execution path makes the unauthorized $1
consequence unreachable without enlarging any authority; chatbot
utterance (speech) outside the execution path remains outside the
boundary, as stated above.
"""

from __future__ import annotations

import hashlib
import hmac
import unittest
from dataclasses import replace

from pulpo import (
    CeremonyEvidence,
    CeremonyTrust,
    GovernanceKernel,
    Intent,
    Policy,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
AGENT = "agent:dealership-chatbot"
SESSION = "watsonville-chat-2023-12"

# The one vehicle the agent may quote, a second vehicle it may not touch,
# and the terms: MSRP versus the incident's $1.
TAHOE_1 = "vehicle:2024-chevrolet-tahoe/unit-001"
TAHOE_2 = "vehicle:2024-chevrolet-tahoe/unit-002"
MSRP_CENTS = 5_500_000  # $55,000.00 — the authorized quote price
ONE_DOLLAR_CENTS = 100  # $1.00 — the incident's unauthorized price
MAX_COST_CENTS = 10_000_000

QUOTE_INTENT = Intent(AGENT, "issue_quote", TAHOE_1, MSRP_CENTS, SESSION)
# Step 1: the binding commitment at $1 — an action never permitted at all.
SALE_ONE_DOLLAR_INTENT = Intent(AGENT, "execute_sale", TAHOE_1, ONE_DOLLAR_CENTS, SESSION)
# Step 2a: same action and object as the permit, price parameter altered.
QUOTE_ONE_DOLLAR_INTENT = Intent(AGENT, "issue_quote", TAHOE_1, ONE_DOLLAR_CENTS, SESSION)
# Step 2b: the quote permit spent on the commitment action at full price.
SALE_MSRP_INTENT = Intent(AGENT, "execute_sale", TAHOE_1, MSRP_CENTS, SESSION)
# Step 3: the permitted action against a different vehicle.
QUOTE_OTHER_VEHICLE_INTENT = Intent(AGENT, "issue_quote", TAHOE_2, MSRP_CENTS, SESSION)


class HmacCeremonyTestVerifier:
    """Test-only ceremony signer/verifier; never import this as a ceremony."""

    authority_id = "ceremony:test-owner"
    verifier_id = "ceremony-verifier:test-only"
    key_id = "ceremony-key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"pulpo-test-ceremony-key").hexdigest()

    def __init__(self, secret=b"external-test-ceremony"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def ceremony_trust_for(verifier, *, method="test-ceremony", max_evidence_ttl_ns=10_000):
    return CeremonyTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        method=method,
        max_evidence_ttl_ns=max_evidence_ttl_ns,
    )


def signed_evidence(kernel, intent, envelope, ceremony_verifier, *, now_ns, ttl_ns=1_000, signer=None, **changes):
    trust = kernel.policy.ceremony_trust
    values = {
        "evidence_id": "ceremony-evidence-1",
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "key_id": trust.key_id,
        "method": trust.method,
        "trust_hash": trust.trust_hash,
        "approval_id": envelope.approval_id,
        "envelope_hash": envelope.envelope_hash,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "principal": intent.principal,
        "session_id": intent.session_id,
        "approval_nonce": envelope.nonce,
        "issued_at_ns": now_ns,
        "expires_at_ns": now_ns + ttl_ns,
        "signature": "",
    }
    values.update(changes)
    unsigned = CeremonyEvidence(**values)
    return replace(unsigned, signature=(signer or ceremony_verifier).sign(unsigned.signing_bytes()))


# Token presented to ``GovernanceKernel.consume`` when the executor
# holds no permit at all. The kernel's consume contract takes a permit
# string; issued permits are ``<intent-hash>:<nonce>:<signature>`` and
# are never empty, so the empty string is a never-issued token that
# represents unavailable authority — as distinct from a fabricated
# token, which represents forged authority. Presenting it lets the
# KERNEL, not this harness, reject the attempt and write the canonical
# ``permit_rejected`` audit record for it.
NO_PERMIT_TOKEN = ""


class ConsequenceLedger:
    """Effects on the dealership's systems, reachable only via a successful consume.

    The harness executes an act (records its consequence, including its
    price) only when the kernel consumes a permit for that exact intent.
    A denial is therefore directly observable as the absence of a
    consequence, not merely as a returned status.

    The harness never denies on its own: every attempt — including one
    holding no permit (``permit=None``) — is presented to
    ``GovernanceKernel.consume``, so a regression in the kernel's
    handling of unavailable authority fails this scenario instead of
    being masked by a harness-side short-circuit.
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str, int]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        presented = NO_PERMIT_TOKEN if permit is None else permit
        if not kernel.consume(presented, intent):
            return False
        self.effects.append((intent.action, intent.resource, intent.cost))
        return True


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent permit
    spends for any intent. It exists only to prove the scenario's denial
    assertions discriminate — under this double the $1 commitment must
    EXECUTE, or the scenario would be denying by construction rather
    than by the kernel's binding.
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
    neither token authentication nor the token-to-intent binding the
    kernel itself has enforced since the 2026-11-13 layering change --
    and delegates straight to the state, restoring the pre-#355 consume
    path. Paired with the intent-blind state double above, no layer
    binds the permit to the presented intent, so the substituted spend
    must EXECUTE here, or the scenario's denials would be coming from
    the harness rather than from the binding layers. The store layer's
    own binding is proven directly in tests/test_writer_custody.py
    (StateIntentBindingTests).
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class ChevroletIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.ceremony = HmacCeremonyTestVerifier()
        self.policy = Policy(
            frozenset({"issue_quote", "execute_sale"}),
            MAX_COST_CENTS,
            frozenset({"issue_quote", "execute_sale"}),
            authority_trust=trust_for(self.verifier),
            ceremony_actions=frozenset({"issue_quote"}),
            ceremony_trust=ceremony_trust_for(self.ceremony),
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
            ceremony_verifier=self.ceremony,
            **kwargs,
        )

    def _envelope_and_evidence(self, kernel: GovernanceKernel):
        envelope = signed_envelope(kernel, QUOTE_INTENT, self.verifier, now_ns=NOW)
        evidence = signed_evidence(kernel, QUOTE_INTENT, envelope, self.ceremony, now_ns=NOW)
        return envelope, evidence

    def _issue_quote_permit(self, kernel: GovernanceKernel) -> str:
        envelope, evidence = self._envelope_and_evidence(kernel)
        decision = kernel.evaluate_with_approval(
            QUOTE_INTENT, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- step 1: the $1 commitment, an action never permitted ---------------

    def test_step1_dollar_commitment_without_permit_denied(self) -> None:
        envelope, evidence = self._envelope_and_evidence(self.kernel)
        # Plain evaluation: the commitment action requires approval the
        # agent never received, so no permit exists to spend.
        decision = self.kernel.evaluate(SALE_ONE_DOLLAR_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        # The no-permit attempt itself reaches the kernel: the ledger
        # presents the unavailable-authority token to consume, so the
        # rejection below is the KERNEL's, with a canonical audit
        # record — not a harness-side short-circuit (Codex P1, PR #348).
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, SALE_ONE_DOLLAR_INTENT))
        # Mint path: the approval bound to the quote intent does not
        # authorize a permit for the commitment intent.
        mint = self.kernel.evaluate_with_approval(
            SALE_ONE_DOLLAR_INTENT, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("deny", "approval_intent_mismatch"), (mint.outcome, mint.reason))
        self.assertIsNone(mint.permit)
        # A fabricated permit token is not a permit.
        self.assertFalse(
            self.ledger.execute(self.kernel, "permit:fabricated:token", SALE_ONE_DOLLAR_INTENT)
        )
        # Zero consequences: no $1 commitment exists anywhere.
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # Exactly two kernel rejections, both carrying the $1-sale
        # intent hash: one for the no-permit (unavailable-authority)
        # attempt and one for the fabricated token. Before the fix the
        # no-permit attempt never reached consume and only the
        # fabricated token was accounted for (count was 1).
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        self.assertEqual(
            {self.kernel.intent_hash(SALE_ONE_DOLLAR_INTENT)},
            {record["payload"]["intent_hash"] for record in rejected},
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: terms substitution against the quote permit -----------------

    def test_step2_terms_substitution_against_quote_permit_denied(self) -> None:
        # The price is inside the binding: the $1 quote intent hashes
        # differently from the MSRP quote intent it would impersonate.
        self.assertNotEqual(
            self.kernel.intent_hash(QUOTE_INTENT),
            self.kernel.intent_hash(QUOTE_ONE_DOLLAR_INTENT),
        )
        permit = self._issue_quote_permit(self.kernel)
        # (a) Same action, same vehicle, price parameter altered to $1:
        # the permit was bound to the MSRP intent hash and does not spend.
        self.assertFalse(self.ledger.execute(self.kernel, permit, QUOTE_ONE_DOLLAR_INTENT))
        # (b) Same vehicle, authorized price, but the *commitment* action
        # instead of the quote action: action substitution is also bound.
        self.assertFalse(self.ledger.execute(self.kernel, permit, SALE_MSRP_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {
                self.kernel.intent_hash(QUOTE_ONE_DOLLAR_INTENT),
                self.kernel.intent_hash(SALE_MSRP_INTENT),
            },
            rejected_hashes,
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denials were binding, not lockout: the permit still spends
        # on the exact intent it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, QUOTE_INTENT))
        self.assertEqual([("issue_quote", TAHOE_1, MSRP_CENTS)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: the permitted action against a different vehicle ------------

    def test_step3_different_vehicle_denied(self) -> None:
        permit = self._issue_quote_permit(self.kernel)
        self.assertFalse(
            self.ledger.execute(self.kernel, permit, QUOTE_OTHER_VEHICLE_INTENT)
        )
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(QUOTE_OTHER_VEHICLE_INTENT),
            rejected[0]["payload"]["intent_hash"],
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # Exact binding, not lockout: the permitted quote still executes.
        self.assertTrue(self.ledger.execute(self.kernel, permit, QUOTE_INTENT))
        self.assertEqual([("issue_quote", TAHOE_1, MSRP_CENTS)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- positive control ------------------------------------------------------

    def test_positive_control_quote_executes_exactly_once_replay_denied(self) -> None:
        permit = self._issue_quote_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, QUOTE_INTENT))
        self.assertEqual([("issue_quote", TAHOE_1, MSRP_CENTS)], self.ledger.effects)
        # The same permit cannot execute the same quote twice.
        self.assertFalse(self.ledger.execute(self.kernel, permit, QUOTE_INTENT))
        self.assertEqual([("issue_quote", TAHOE_1, MSRP_CENTS)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control --------------------------------------------------------

    def test_negative_control_unguarded_consume_executes_dollar_commitment(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a kernel
        # double whose consume skips token authentication and the
        # kernel's token-to-intent binding, over a state double whose
        # consume ignores the store's binding: the quote permit spends
        # on the $1 commitment and the commitment EXECUTES. The denials
        # above therefore come from the real consume path's binding
        # checks, not from a harness that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        blind_permit = self._issue_quote_permit(blind_kernel)
        self.assertTrue(
            self.ledger.execute(blind_kernel, blind_permit, SALE_ONE_DOLLAR_INTENT)
        )
        self.assertEqual(
            [("execute_sale", TAHOE_1, ONE_DOLLAR_CENTS)], self.ledger.effects
        )
        # Contrast, same attempt against the real backend: denied (step 1).
        real_permit = self._issue_quote_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(
            real_ledger.execute(self.kernel, real_permit, SALE_ONE_DOLLAR_INTENT)
        )
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

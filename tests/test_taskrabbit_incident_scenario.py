"""Scenario test: the GPT-4 / TaskRabbit incident's unauthorized-action failure mode.

Incident (Recorded, from OpenAI's GPT-4 System Card, March 2023, reporting
ARC evaluations): GPT-4, assigned an evaluation task it could not complete
on its own — solving a CAPTCHA — hired a TaskRabbit worker to solve it.
When the worker asked "are you a robot?", the model lied, claiming to be a
human with a vision impairment. ARC and OpenAI report the episode as an
evaluation finding, not a deployment breach; it is used here as a scenario
because the action chain is exactly documented.

Boundary stated up front: the lie is utterance. Pulpo does not govern what
a model says, and this module makes no claim about the deception. What the
kernel governs is the ACTS the deception served:

  1. CONTRACT A HUMAN — engaging a worker on a marketplace (an action
     class the agent was never granted);
  2. SPEND FUNDS — committing payment for that work (likewise ungranted);
  3. CIRCUMVENTED ACCESS — consuming a CAPTCHA-gated resource whose gate
     exists to keep bots out, using a proxy-obtained solution in place of
     authorization. A CAPTCHA solution is not a permit: the kernel has no
     notion of presenting one, so the attempt is modeled as what it is in
     consequence terms — an attempt to act on the protected resource with
     no permit bound to that intent, or with a permit bound elsewhere.

Setup: the evaluation agent receives exactly one permit — for its assigned
evaluation action on one exact object (attempt the task inside the task
environment), issued through a verified approval envelope plus ceremony
evidence, the kernel's stand-in for per-action accountable human
authorization. The three incident action classes are then attempted. The
kernel must deny each one, the consequence ledger must stay empty for all
of them, and the audit trail must account for every attempt.

This module models that failure mode against the canonical kernel API. It
does NOT reproduce TaskRabbit, any CAPTCHA system, model behavior, or the
deception. The "agent" is this harness holding intents; the only route from
intent to consequence is a successful ``GovernanceKernel.consume`` of a
permit bound to the exact intent hash.

Boundary: this proves kernel behavior at this commit for these action
classes (Verified, executable evidence). It proves nothing about any
deployed system that does not route its consequences through this kernel —
a control not on the execution path governs nothing.
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
AGENT = "agent:gpt4-arc-eval"
SESSION = "arc-eval-2023-03"

# The one object the agent is authorized to touch, and the incident targets.
TASK_ENV = "eval:task-environment"
MARKETPLACE = "taskrabbit:marketplace"
WALLET = "payments:agent-wallet"
PROTECTED_RESOURCE = "captcha-gated:protected-resource"

TASK_INTENT = Intent(AGENT, "attempt_task", TASK_ENV, 0, SESSION)
HIRE_INTENT = Intent(AGENT, "hire_worker", MARKETPLACE, 0, SESSION)
PAY_INTENT = Intent(AGENT, "commit_payment", WALLET, 0, SESSION)
ACCESS_INTENT = Intent(AGENT, "access_protected_resource", PROTECTED_RESOURCE, 0, SESSION)
INCIDENT_INTENTS = (HIRE_INTENT, PAY_INTENT, ACCESS_INTENT)


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


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume.

    This is the scenario's execution path: the harness executes an action
    (records its consequence) only when the kernel consumes a permit for
    that exact intent. A denial is therefore directly observable as the
    absence of a consequence, not merely as a returned status.
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

    Its consume ignores the intent binding: any issued, unspent permit
    spends for any intent. It exists only to prove the scenario's denial
    assertions discriminate — under this double the hire and payment
    attempts must EXECUTE, or the scenario would be denying by
    construction rather than by the kernel's binding.
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
    binds the permit to the presented intent, so the substituted spends
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


class TaskRabbitIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.ceremony = HmacCeremonyTestVerifier()
        self.policy = Policy(
            frozenset(
                {
                    "attempt_task",
                    "hire_worker",
                    "commit_payment",
                    "access_protected_resource",
                }
            ),
            100,
            frozenset(
                {
                    "attempt_task",
                    "hire_worker",
                    "commit_payment",
                    "access_protected_resource",
                }
            ),
            authority_trust=trust_for(self.verifier),
            ceremony_actions=frozenset({"attempt_task"}),
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
        envelope = signed_envelope(kernel, TASK_INTENT, self.verifier, now_ns=NOW)
        evidence = signed_evidence(kernel, TASK_INTENT, envelope, self.ceremony, now_ns=NOW)
        return envelope, evidence

    def _issue_task_permit(self, kernel: GovernanceKernel) -> str:
        envelope, evidence = self._envelope_and_evidence(kernel)
        decision = kernel.evaluate_with_approval(
            TASK_INTENT, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_assigned_action_executes_exactly_once(self) -> None:
        permit = self._issue_task_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, TASK_INTENT))
        self.assertEqual([("attempt_task", TASK_ENV)], self.ledger.effects)
        # The same permit cannot execute the same action twice.
        self.assertFalse(self.ledger.execute(self.kernel, permit, TASK_INTENT))
        self.assertEqual([("attempt_task", TASK_ENV)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: contract a human (hire a worker) --------------------------

    def test_step1_contract_a_human_without_permit_denied(self) -> None:
        envelope, evidence = self._envelope_and_evidence(self.kernel)
        # Asking plainly: hiring is an approval action the agent was never
        # approved for, so no permit exists.
        decision = self.kernel.evaluate(HIRE_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, HIRE_INTENT))
        # Mint path: the approval bound to the assigned task does not
        # authorize a permit for the marketplace intent.
        mint = self.kernel.evaluate_with_approval(
            HIRE_INTENT, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("deny", "approval_intent_mismatch"), (mint.outcome, mint.reason))
        self.assertIsNone(mint.permit)
        # The genuine task permit issues for its exact intent only, and
        # spending it on hiring is denied: the permit binds the exact
        # intent hash, not the agent or its session.
        permit = self._issue_task_permit(self.kernel)
        self.assertFalse(self.ledger.execute(self.kernel, permit, HIRE_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(HIRE_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still spends on the
        # exact action it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, TASK_INTENT))
        self.assertEqual([("attempt_task", TASK_ENV)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: spend funds (pay the worker) ------------------------------

    def test_step2_spend_funds_without_permit_denied(self) -> None:
        decision = self.kernel.evaluate(PAY_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, PAY_INTENT))
        # A fabricated permit token is not a permit.
        self.assertFalse(
            self.ledger.execute(self.kernel, "permit:fabricated:token", PAY_INTENT)
        )
        # The genuine task permit does not become a payment instrument.
        permit = self._issue_task_permit(self.kernel)
        self.assertFalse(self.ledger.execute(self.kernel, permit, PAY_INTENT))
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual({self.kernel.intent_hash(PAY_INTENT)}, rejected_hashes)
        # Binding is exact, not a global lockout after denied attempts.
        self.assertTrue(self.ledger.execute(self.kernel, permit, TASK_INTENT))
        self.assertEqual([("attempt_task", TASK_ENV)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: circumvented access (the CAPTCHA-gated resource) ----------

    def test_step3_circumvented_access_without_permit_denied(self) -> None:
        # The proxy-obtained CAPTCHA solution is not a permit, and no permit
        # exists for the protected resource: asking plainly fails.
        decision = self.kernel.evaluate(ACCESS_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(self.kernel, decision.permit, ACCESS_INTENT))
        # Spending the unrelated task permit on the gated resource — the
        # consequence form of "present whatever credential you obtained" —
        # is denied on intent binding.
        permit = self._issue_task_permit(self.kernel)
        self.assertFalse(self.ledger.execute(self.kernel, permit, ACCESS_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(ACCESS_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout.
        self.assertTrue(self.ledger.execute(self.kernel, permit, TASK_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: the scope-creep chain, end to end --------------------------

    def test_step4_scope_creep_chain_zero_consequences_complete_audit(self) -> None:
        # Discrimination note: every mismatched attempt below runs while
        # the task permit is still UNSPENT, so a rejection cannot be
        # explained by the token already being spent. An intent-blind
        # backend that accepts any unspent permit would EXECUTE a
        # mismatched attempt here instead of rejecting it — exactly what
        # test_negative_control_unguarded_consume_would_execute
        # demonstrates with the same unspent-permit setup. The legitimate
        # consume therefore comes LAST in this test, after the chain.
        permit = self._issue_task_permit(self.kernel)
        audit_before = len(self.kernel.audit)
        attempts = 0
        # The incident's chain in order — hire, then pay, then access —
        # each attempted by both routes an agent could reach for: asking
        # for authorization it never received, and spending a permit (the
        # genuine, still-unspent task permit — the only token it holds).
        for intent in INCIDENT_INTENTS:
            with self.subTest(action=intent.action):
                decision = self.kernel.evaluate(intent)
                self.assertEqual("require_approval", decision.outcome)
                self.assertIsNone(decision.permit)
                attempts += 1
                self.assertFalse(self.kernel.consume(permit, intent))
                attempts += 1
        fabricated = self.kernel.consume("permit:fabricated:token", ACCESS_INTENT)
        self.assertFalse(fabricated)
        attempts += 1
        # With the permit still unspent, the chain produced zero
        # consequences and no permit was consumed at all; every rejection
        # carries the incident intent hash it was attempted against.
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(attempts - len(INCIDENT_INTENTS), len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {self.kernel.intent_hash(intent) for intent in INCIDENT_INTENTS},
            rejected_hashes,
        )
        self.assertEqual(attempts, len(self.kernel.audit) - audit_before)
        # Only now is the permit spent — on the one legitimate
        # consequence: the assigned action, exactly once.
        self.assertTrue(self.ledger.execute(self.kernel, permit, TASK_INTENT))
        attempts += 1
        self.assertEqual([("attempt_task", TASK_ENV)], self.ledger.effects)
        consumed = _events(self.kernel, "permit_consumed")
        self.assertEqual(1, len(consumed))
        self.assertEqual(
            self.kernel.intent_hash(TASK_INTENT), consumed[0]["payload"]["intent_hash"]
        )
        self.assertEqual(attempts, len(self.kernel.audit) - audit_before)
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a kernel
        # double whose consume skips token authentication and the
        # kernel's token-to-intent binding, over a state double whose
        # consume ignores the store's binding: the hire and payment
        # attempts EXECUTE. The denials in the steps above therefore
        # come from the real consume path's binding checks, not from a
        # harness that denies by construction.
        hire_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        hire_permit = self._issue_task_permit(hire_kernel)
        self.assertTrue(self.ledger.execute(hire_kernel, hire_permit, HIRE_INTENT))
        self.assertEqual([("hire_worker", MARKETPLACE)], self.ledger.effects)

        blind_ledger = ConsequenceLedger()
        pay_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        pay_permit = self._issue_task_permit(pay_kernel)
        self.assertTrue(blind_ledger.execute(pay_kernel, pay_permit, PAY_INTENT))
        self.assertEqual([("commit_payment", WALLET)], blind_ledger.effects)

        # Contrast, same attempts against the real backend: denied (steps 1-2).
        real_permit = self._issue_task_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, HIRE_INTENT))
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, PAY_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()

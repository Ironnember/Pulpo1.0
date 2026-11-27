"""Developer trio, item 2: the fail-closed permit gate (pulpo.permit_gate).

The gate is call-site discipline over the canonical kernel, and these
tests pin its one contract: the wrapped action runs only after an
explicit ``allow`` decision AND a successful consume of that decision's
permit for the exact intent. Denial, an approval-required outcome, an
expired / mismatched / replayed permit, a presenter failure, and any
backend error all raise ``PermitRefused`` with the action unrun —
approval is never inferred from the absence of an error.

Presenter verifiers are the same-process HMAC test doubles from
tests/presenter_support.py, as in tests/test_presenter_binding.py.
"""

from __future__ import annotations

import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.permit_gate import PermitGate, PermitRefused, require_permit, spend_permit
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, trust_for
from tests.presenter_support import HmacPresenterVerifier, proof_for

NOW = 2_000_000_000
SECRET = b"kernel" + b"-secret"
INTENT = Intent("agent:builder", "write", "repo:core", 3, "s1")
PRESENTER = "executor:prod"


def make_kernel(policy=None, clock=None, state=None, presenter_verifiers=None):
    return GovernanceKernel(
        policy or Policy(frozenset({"write"}), 100),
        SECRET,
        clock=clock or (lambda: NOW),
        state=state if state is not None else InMemoryKernelState(),
        presenter_verifiers=presenter_verifiers,
    )


class Recorder:
    """A consequential action double: records that it ran."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return "executed"


class AllowPathTests(unittest.TestCase):
    def test_run_executes_action_after_consume(self):
        kernel = make_kernel()
        gate = PermitGate(kernel)
        action = Recorder()
        self.assertEqual(gate.run(INTENT, action), "executed")
        self.assertEqual(action.calls, 1)
        consumed = [
            record
            for record in kernel.audit
            if record["event"] == "permit_consumed"
            and record["payload"]["intent_hash"] == kernel.intent_hash(INTENT)
        ]
        self.assertEqual(len(consumed), 1)

    def test_require_permit_returns_the_allow_decision(self):
        kernel = make_kernel()
        decision = require_permit(kernel, INTENT)
        self.assertEqual(decision.outcome, "allow")
        self.assertEqual(decision.intent_hash, kernel.intent_hash(INTENT))
        self.assertIsNotNone(decision.permit)

    def test_guard_context_manager_runs_body_after_consume(self):
        kernel = make_kernel()
        gate = PermitGate(kernel)
        action = Recorder()
        with gate.guard(INTENT) as decision:
            self.assertEqual(decision.outcome, "allow")
            action()
        self.assertEqual(action.calls, 1)


class DenialTests(unittest.TestCase):
    def test_policy_denial_raises_and_action_does_not_run(self):
        kernel = make_kernel()
        gate = PermitGate(kernel)
        action = Recorder()
        too_expensive = Intent("agent:builder", "write", "repo:core", 10_000, "s1")
        with self.assertRaises(PermitRefused) as caught:
            gate.run(too_expensive, action)
        self.assertEqual(caught.exception.outcome, "deny")
        self.assertEqual(action.calls, 0)

    def test_disallowed_action_raises_and_action_does_not_run(self):
        kernel = make_kernel()
        gate = PermitGate(kernel)
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run(Intent("agent:builder", "delete", "repo:core", 1, "s1"), action)
        self.assertEqual(caught.exception.outcome, "deny")
        self.assertEqual(action.calls, 0)

    def test_require_approval_outcome_raises_and_action_does_not_run(self):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write"}),
            100,
            approval_actions=frozenset({"write"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            SECRET,
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=InMemoryKernelState(),
        )
        gate = PermitGate(kernel)
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run(INTENT, action)
        # The gate does not mint approval-path permits; the outcome is
        # surfaced, not routed around.
        self.assertEqual(caught.exception.outcome, "require_approval")
        self.assertEqual(action.calls, 0)


class SpendPermitTests(unittest.TestCase):
    def test_expired_permit_raises_and_action_does_not_run(self):
        now = [1_000_000_000_000]
        policy = Policy(frozenset({"write"}), 100, max_permit_ttl_ns=60_000_000_000)
        kernel = make_kernel(policy=policy, clock=lambda: now[0])
        permit = kernel.evaluate(INTENT).permit
        self.assertIsNotNone(permit)
        now[0] += 61_000_000_000  # past the signed expiry
        gate = PermitGate(kernel)
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run_with_permit(permit, INTENT, action)
        self.assertEqual(caught.exception.outcome, "consume_refused")
        self.assertEqual(action.calls, 0)
        reasons = [
            record["payload"]["reason"]
            for record in kernel.audit
            if record["event"] == "permit_rejected"
        ]
        self.assertIn("permit_expired", reasons)

    def test_wrong_intent_raises_and_action_does_not_run(self):
        kernel = make_kernel()
        permit = kernel.evaluate(INTENT).permit
        other = Intent("agent:builder", "write", "repo:other", 3, "s1")
        gate = PermitGate(kernel)
        action = Recorder()
        with self.assertRaises(PermitRefused):
            gate.run_with_permit(permit, other, action)
        self.assertEqual(action.calls, 0)
        # The failed attempt did not burn the permit: the exact intent
        # it was minted for can still spend it.
        self.assertEqual(gate.run_with_permit(permit, INTENT, action), "executed")
        self.assertEqual(action.calls, 1)

    def test_second_use_of_same_permit_raises(self):
        kernel = make_kernel()
        permit = kernel.evaluate(INTENT).permit
        gate = PermitGate(kernel)
        action = Recorder()
        self.assertEqual(gate.run_with_permit(permit, INTENT, action), "executed")
        with self.assertRaises(PermitRefused) as caught:
            gate.run_with_permit(permit, INTENT, action)
        self.assertEqual(caught.exception.outcome, "consume_refused")
        self.assertEqual(action.calls, 1)

    def test_spend_permit_function_form(self):
        kernel = make_kernel()
        permit = kernel.evaluate(INTENT).permit
        spend_permit(kernel, permit, INTENT)
        with self.assertRaises(PermitRefused):
            spend_permit(kernel, permit, INTENT)


class ExplodingKernel:
    """A backend double whose calls fail the way a down service does."""

    intent_hash = staticmethod(GovernanceKernel.intent_hash)

    def __init__(self, *, fail_on):
        self._fail_on = fail_on

    def evaluate(self, intent, *, presenter=None):
        if self._fail_on == "evaluate":
            raise ConnectionError("authority service unreachable")
        from pulpo import Decision

        return Decision("allow", "policy_satisfied", self.intent_hash(intent), "permit-token")

    def consume(self, permit, intent, *, presenter=None, presenter_proof=None):
        if self._fail_on == "consume":
            raise ConnectionError("authority service unreachable")
        return False


class BackendErrorTests(unittest.TestCase):
    def test_evaluate_error_raises_and_action_does_not_run(self):
        gate = PermitGate(ExplodingKernel(fail_on="evaluate"))
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run(INTENT, action)
        self.assertEqual(caught.exception.outcome, "kernel_error")
        self.assertEqual(action.calls, 0)

    def test_consume_error_raises_and_action_does_not_run(self):
        gate = PermitGate(ExplodingKernel(fail_on="consume"))
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run(INTENT, action)
        self.assertEqual(caught.exception.outcome, "kernel_error")
        self.assertEqual(action.calls, 0)

    def test_consume_returning_false_raises(self):
        gate = PermitGate(ExplodingKernel(fail_on="neither"))
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run(INTENT, action)
        self.assertEqual(caught.exception.outcome, "consume_refused")
        self.assertEqual(action.calls, 0)

    def test_allow_without_a_permit_is_not_approval(self):
        class NoPermitKernel(ExplodingKernel):
            def evaluate(self, intent, *, presenter=None):
                from pulpo import Decision

                return Decision("allow", "policy_satisfied", self.intent_hash(intent), None)

        gate = PermitGate(NoPermitKernel(fail_on="neither"))
        action = Recorder()
        with self.assertRaises(PermitRefused):
            gate.run(INTENT, action)
        self.assertEqual(action.calls, 0)


class PresenterBindingTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacPresenterVerifier(b"presenter-secret")
        self.policy = Policy(frozenset({"write"}), 100, require_presenter_binding=True)
        self.kernel = make_kernel(
            policy=self.policy,
            presenter_verifiers={PRESENTER: self.verifier},
        )

    def provider(self, permit, intent, presenter):
        return proof_for(self.kernel, self.verifier, permit, intent, presenter)

    def test_bound_presenter_allow_path_executes(self):
        gate = PermitGate(self.kernel, presenter=PRESENTER, proof_provider=self.provider)
        action = Recorder()
        self.assertEqual(gate.run(INTENT, action), "executed")
        self.assertEqual(action.calls, 1)

    def test_wrong_proof_raises_and_action_does_not_run(self):
        gate = PermitGate(
            self.kernel,
            presenter=PRESENTER,
            proof_provider=lambda permit, intent, presenter: "0" * 64,
        )
        action = Recorder()
        with self.assertRaises(PermitRefused):
            gate.run(INTENT, action)
        self.assertEqual(action.calls, 0)

    def test_presenter_without_proof_provider_refuses_locally(self):
        gate = PermitGate(self.kernel, presenter=PRESENTER)
        action = Recorder()
        with self.assertRaises(PermitRefused) as caught:
            gate.run(INTENT, action)
        self.assertEqual(caught.exception.outcome, "presenter_proof_unavailable")
        self.assertEqual(action.calls, 0)


if __name__ == "__main__":
    unittest.main()

"""Presenter binding (Item 4B) across the service boundary (gate v2).

Before this change the shipped service protocol had no presenter fields:
the evaluate verb could not bind a permit to a presenter and the consume
verb carried no proof, so a deployment behind the service boundary could
not run with ``require_presenter_binding`` at all (the merge gate's v1
bound: bearer permits inside a narrowed 5-minute TTL). The protocol now
carries two optional fields — ``presenter`` at issuance and
``presenter`` + ``presenter_proof`` at consumption — and the presenter a
request asserts is a claimed principal for credential-binding purposes.

Honesty label: the presenter verifier is the same-process HMAC test
double from ``tests.presenter_support``; production presenters sign with
their own asymmetric keys and the kernel holds a verification-only
adapter. The secrets here are test values.
"""

from __future__ import annotations

import unittest

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy
from pulpo.service import (
    KernelService,
    KernelServiceClient,
    ServiceRefusal,
    loopback_transport,
)
from pulpo.state import InMemoryKernelState
from tests.presenter_support import HmacPresenterVerifier, proof_for

NOW = 2_000_000
PRESENTER = "agent:iron"
SERVICE_SECRET = b"service-secret"
CREDENTIAL_ID = "iron"


class ServicePresenterFixture:
    def __init__(self, *, require_binding=True):
        self.presenter_key = HmacPresenterVerifier(b"presenter-test-secret")
        policy = Policy(
            frozenset({"merge"}),
            10,
            agent_grants=(
                AgentGrant(PRESENTER, frozenset({"merge"}), ("repo:",), 1),
            ),
            require_presenter_binding=require_binding,
        )
        self.kernel = GovernanceKernel(
            policy,
            b"kernel-secret",
            clock=lambda: NOW,
            state=InMemoryKernelState(),
            presenter_verifiers={PRESENTER: self.presenter_key},
        )
        self.service = KernelService(
            self.kernel,
            {CREDENTIAL_ID: (SERVICE_SECRET, frozenset({PRESENTER}))},
            clock=lambda: NOW,
            max_request_ttl_ns=500_000,
        )
        self.client = KernelServiceClient(
            loopback_transport(self.service),
            CREDENTIAL_ID,
            SERVICE_SECRET,
            clock=lambda: NOW,
            request_ttl_ns=400_000,
        )
        self.intent = Intent(PRESENTER, "merge", "repo:origin/main", 1, "gate-v2-test")

    def bound_permit(self):
        decision = self.client.evaluate(self.intent, presenter=PRESENTER)
        assert decision.outcome == "allow", decision
        return decision.permit

    def proof(self, permit, *, key=None, presenter=PRESENTER):
        return proof_for(self.kernel, key or self.presenter_key, permit, self.intent, presenter)


class ServicePresenterBindingTests(unittest.TestCase):
    def setUp(self):
        self.fx = ServicePresenterFixture()

    def test_bound_issue_and_proven_consume_across_the_boundary(self):
        permit = self.fx.bound_permit()
        self.assertTrue(
            self.fx.client.consume(
                permit,
                self.fx.intent,
                presenter=PRESENTER,
                presenter_proof=self.fx.proof(permit),
            )
        )
        # Single use still binds: a replayed consumption is refused even
        # with a fresh, valid proof for the same token and intent.
        self.assertFalse(
            self.fx.client.consume(
                permit,
                self.fx.intent,
                presenter=PRESENTER,
                presenter_proof=self.fx.proof(permit),
            )
        )

    def test_unbound_issuance_is_refused_when_binding_is_required(self):
        decision = self.fx.client.evaluate(self.fx.intent)
        self.assertEqual(("deny", "presenter_binding_required"), (decision.outcome, decision.reason))

    def test_unproven_consumption_is_refused(self):
        permit = self.fx.bound_permit()
        self.assertFalse(self.fx.client.consume(permit, self.fx.intent))
        self.assertFalse(
            self.fx.client.consume(permit, self.fx.intent, presenter=PRESENTER)
        )

    def test_wrong_presenter_key_proof_is_refused(self):
        permit = self.fx.bound_permit()
        foreign = HmacPresenterVerifier(b"someone-elses-secret")
        self.assertFalse(
            self.fx.client.consume(
                permit,
                self.fx.intent,
                presenter=PRESENTER,
                presenter_proof=self.fx.proof(permit, key=foreign),
            )
        )
        # The genuine presenter can still spend it: the refusal burned
        # nothing.
        self.assertTrue(
            self.fx.client.consume(
                permit,
                self.fx.intent,
                presenter=PRESENTER,
                presenter_proof=self.fx.proof(permit),
            )
        )

    def test_presenter_outside_the_credential_binding_is_refused_at_the_boundary(self):
        # The presenter a request asserts is a claimed principal: the
        # 'iron' credential is bound to agent:iron only, so asserting a
        # different presenter never reaches the kernel.
        with self.assertRaises(ServiceRefusal):
            self.fx.client.evaluate(self.fx.intent, presenter="agent:mallory")

    def test_unbound_policy_keeps_the_legacy_bearer_flow(self):
        fx = ServicePresenterFixture(require_binding=False)
        decision = fx.client.evaluate(fx.intent)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(fx.client.consume(decision.permit, fx.intent))


if __name__ == "__main__":
    unittest.main()

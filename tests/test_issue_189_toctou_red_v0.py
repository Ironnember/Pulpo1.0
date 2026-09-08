"""Diagnostic red proof for Issue #189 TOCTOU state inversion.

This file is intentionally expected to fail on the current executor contract.
It proves that a provider preflight hash is recorded but is not carried as a
provider-enforced state/version precondition into the write call.

Do not weaken the red assertion. The correct green transition is to introduce
an explicit execution-precondition contract (when a provider supports one), or
to classify the provider/action as non-atomic rather than claiming state lock.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_executor import TrustedDomainExecutor
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState


NOW = 19_000_000


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class MutableProviderStateRegistrar:
    """Provider-shaped fake whose target state can change after preflight.

    The current CustodyRegistrarAdapter purchase contract receives the order,
    charge cap, and idempotency key, but no expected provider state/version.
    This fake therefore cannot be required by the executor contract to compare
    the write against the exact state observed during preflight.
    """

    def __init__(self, *, mutate_after_preflight: bool) -> None:
        self.state_version = 1
        self.mutate_after_preflight = mutate_after_preflight
        self.preflight_version = None
        self.purchase_version = None
        self.effects = []

    def preflight(self, order):
        self.preflight_version = self.state_version
        evidence = {
            "domain": order.domain,
            "purchasable": True,
            "purchase_price_cents": order.purchase_price_cents,
            "renewal_price_cents": order.renewal_price_cents,
            "provider_state_version": self.state_version,
        }
        digest = sha256(_canonical(evidence)).hexdigest()

        # Simulate an out-of-band provider/target mutation after Pulpo's check
        # but before the write is committed.
        if self.mutate_after_preflight:
            self.state_version += 1
        return digest

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        self.purchase_version = self.state_version
        self.effects.append(
            {
                "domain": order.domain,
                "provider_state_version": self.state_version,
                "idempotency_key": idempotency_key,
            }
        )
        return RegistrarResult(
            payment_id="payment-toctou-red-v0",
            charged_cents=min(order.purchase_price_cents, max_charge_cents),
            receipt_hash="a" * 64,
            registration_id="registration-toctou-red-v0",
            domain=order.domain,
            registrar=order.registrar,
        )


class Issue189ToctouRedProof(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def _order(self):
        domain = "pulpo-issue-189-toctou.example"
        request = DomainPurchaseRequest(
            request_id="issue-189-toctou-request-v0",
            principal="agent:commerce",
            acceptable_domains=(domain,),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="issue-189-toctou-quote-v0",
            domain=domain,
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref="credential://name-com/issue-189-red-v0",
            now_ns=NOW,
        )
        self.assertIsNotNone(assessment.order)
        return assessment.order

    def _governed_attempt(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"issue-189-toctou-custody-secret",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(self.path)
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"issue-189-toctou-kernel-secret",
            clock=lambda: NOW,
            state=state,
        )
        order = self._order()
        intent = purchase_intent(order)
        target = kernel.lock_target("issue-189-toctou-target-v0", intent)
        decision = kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody, budget)
        reservation = coordinator.reserve(order)
        governed = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
            reservation_id=reservation.reservation_id,
        )
        return custody, governed, order

    def test_control_stable_provider_state_executes_once(self):
        custody, governed, order = self._governed_attempt()
        adapter = MutableProviderStateRegistrar(mutate_after_preflight=False)

        TrustedDomainExecutor(custody, executor_id="executor:issue-189-v0").execute(
            governed, order, adapter
        )

        self.assertEqual(adapter.preflight_version, adapter.purchase_version)
        self.assertEqual(1, len(adapter.effects))

    def test_red_provider_state_change_after_preflight_must_block_effect(self):
        custody, governed, order = self._governed_attempt()
        adapter = MutableProviderStateRegistrar(mutate_after_preflight=True)

        TrustedDomainExecutor(custody, executor_id="executor:issue-189-v0").execute(
            governed, order, adapter
        )

        # Required future invariant:
        # CHECKED_STATE != EXECUTION_PRECONDITION
        # A changed provider state must produce zero effect unless the provider
        # atomically accepts the exact state/version bound to authorization.
        self.assertEqual(
            adapter.preflight_version,
            adapter.purchase_version,
            "RED: provider state changed after preflight, but execution was not blocked",
        )
        self.assertEqual(
            [],
            adapter.effects,
            "RED: stale preflight still allowed a provider effect",
        )


if __name__ == "__main__":
    unittest.main()

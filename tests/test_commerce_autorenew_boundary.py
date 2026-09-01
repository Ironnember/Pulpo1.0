from __future__ import annotations

import unittest

from pulpo.commerce import DomainPurchaseOrder, DomainPurchaseRequest, VerificationEvidence
from pulpo.custody_reconcile import IndependentDomainObservation


class CommerceAutoRenewGovernedEffectGapTests(unittest.TestCase):
    """Red proof: future renewal state must be part of the governed consequence.

    A domain registrar can create auto-renew state that later causes a renewal
    charge. Pulpo must therefore bind that state in the exact authorized action
    object and independently observe it before reconciliation can succeed.
    """

    def test_request_binds_auto_renew_decision(self) -> None:
        self.assertIn(
            "auto_renew_enabled",
            DomainPurchaseRequest.__dataclass_fields__,
            "domain request does not bind future auto-renew authority",
        )

    def test_exact_order_hash_can_bind_auto_renew_decision(self) -> None:
        self.assertIn(
            "auto_renew_enabled",
            DomainPurchaseOrder.__dataclass_fields__,
            "domain order hash cannot bind future auto-renew state",
        )

    def test_independent_acceptance_evidence_observes_auto_renew_state(self) -> None:
        self.assertIn(
            "auto_renew_enabled",
            VerificationEvidence.__dataclass_fields__,
            "delivery verification does not observe future auto-renew state",
        )

    def test_custody_observation_observes_auto_renew_state(self) -> None:
        self.assertIn(
            "auto_renew_enabled",
            IndependentDomainObservation.__dataclass_fields__,
            "external reconciliation cannot compare observed auto-renew state to the order",
        )


if __name__ == "__main__":
    unittest.main()

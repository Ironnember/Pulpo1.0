import tempfile
import unittest
from pathlib import Path

from pulpo.commerce import DomainPurchaseRequest, DomainQuote, assess_quote, purchase_intent
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_reconcile import IndependentDomainObservation, IndependentDomainReconciler
from pulpo.kernel import GovernanceKernel, Policy
from pulpo.state import SQLiteKernelState


NOW = 15_000_000


class CustodyReconciliationTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def stack(self):
        custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"independent-observer-custody",
            clock=lambda: NOW,
        )
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"independent-observer-kernel",
            clock=lambda: NOW,
            state=state,
        )
        request = DomainPurchaseRequest(
            request_id="reconcile-request-v0",
            principal="agent:commerce",
            acceptable_domains=("pulpo-observed.example",),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id="reconcile-quote-v0",
            domain="pulpo-observed.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        order = assess_quote(
            request,
            quote,
            credential_ref="credential://name-com/hostile-worker-v0",
            now_ns=NOW,
        ).order
        self.assertIsNotNone(order)
        intent = purchase_intent(order)
        target = kernel.lock_target("reconcile-domain-v0", intent)
        decision = kernel.evaluate(intent)
        governed = GovernedDomainAttemptCoordinator(kernel, custody).authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=decision.permit,
        )
        head = custody.snapshot()
        custody.claim_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            executor_id="executor:domain-v0",
        )
        head = custody.snapshot()
        provider_request_id = f"domain:{governed.attempt_id}"
        custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
            provider_request_id=provider_request_id,
        )
        head = custody.snapshot()
        custody.require_reconciliation(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=governed.attempt_id,
        )
        return custody, governed, order, provider_request_id

    def observation(self, provider_request_id, **changes):
        values = {
            "observation_id": "observation-v0",
            "provider_request_id": provider_request_id,
            "provider_request_status": "succeeded",
            "domain": "pulpo-observed.example",
            "registrar": "name.com",
            "owner_ref": "owner://iron-ember",
            "registered": True,
            "charged_cents": 2_000,
            "receipt_hash": "a" * 64,
            "privacy_enabled": True,
            "dns_state": "registered",
        }
        values.update(changes)
        return IndependentDomainObservation(**values)

    def test_exact_independent_observation_can_reconcile_success(self):
        custody, governed, order, provider_request_id = self.stack()
        observation = self.observation(provider_request_id)
        result = IndependentDomainReconciler(
            custody,
            observer_id="observer:registrar-and-dns",
        ).reconcile(governed, order, observation)

        self.assertEqual(("success", "external_consequence_verified"), (result.outcome, result.reason))
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILED_SUCCESS,
            custody.attempt(governed.attempt_id).state,
        )
        self.assertEqual("success", custody.attempt(governed.attempt_id).reconciliation_outcome)
        self.assertTrue(custody.verify_receipt(result.receipt))

    def test_provider_success_without_complete_external_observation_stays_unresolved(self):
        custody, governed, order, provider_request_id = self.stack()
        observation = self.observation(provider_request_id, owner_ref=None)
        result = IndependentDomainReconciler(
            custody,
            observer_id="observer:registrar-and-dns",
        ).reconcile(governed, order, observation)

        self.assertEqual(("unresolved", "success_observation_incomplete"), (result.outcome, result.reason))
        self.assertEqual(
            SQLiteGovernanceCustody.UNRESOLVED,
            custody.attempt(governed.attempt_id).state,
        )

    def test_observed_substitution_is_reconciled_as_failure_not_success(self):
        custody, governed, order, provider_request_id = self.stack()
        observation = self.observation(provider_request_id, domain="wrong.example")
        result = IndependentDomainReconciler(
            custody,
            observer_id="observer:registrar-and-dns",
        ).reconcile(governed, order, observation)

        self.assertEqual(("failure", "observed_domain_mismatch"), (result.outcome, result.reason))
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILED_FAILURE,
            custody.attempt(governed.attempt_id).state,
        )

    def test_not_found_lookup_cannot_be_inferred_as_known_failure(self):
        custody, governed, order, provider_request_id = self.stack()
        observation = self.observation(
            provider_request_id,
            provider_request_status="not_found",
            domain=None,
            registrar=None,
            owner_ref=None,
            registered=None,
            charged_cents=None,
            receipt_hash=None,
            privacy_enabled=None,
            dns_state=None,
        )
        result = IndependentDomainReconciler(
            custody,
            observer_id="observer:registrar-query",
        ).reconcile(governed, order, observation)

        self.assertEqual(("unresolved", "provider_request_not_found"), (result.outcome, result.reason))
        self.assertEqual(
            SQLiteGovernanceCustody.UNRESOLVED,
            custody.attempt(governed.attempt_id).state,
        )

    def test_explicit_provider_failure_without_observed_effect_reconciles_failure(self):
        custody, governed, order, provider_request_id = self.stack()
        observation = self.observation(
            provider_request_id,
            provider_request_status="failed",
            domain=None,
            registrar=None,
            owner_ref=None,
            registered=False,
            charged_cents=0,
            receipt_hash=None,
            privacy_enabled=None,
            dns_state=None,
        )
        result = IndependentDomainReconciler(
            custody,
            observer_id="observer:registrar-query",
        ).reconcile(governed, order, observation)

        self.assertEqual(
            ("failure", "provider_failure_independently_observed"),
            (result.outcome, result.reason),
        )
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILED_FAILURE,
            custody.attempt(governed.attempt_id).state,
        )


if __name__ == "__main__":
    unittest.main()

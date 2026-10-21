"""Interactions of exact handles, explicit renewal observations and budget cleanup."""
from dataclasses import replace
import sqlite3
import unittest
from unittest.mock import patch

from pulpo.commerce import CommerceViolation
import test_api as fixtures


class CombinedCommerceRepairTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CustodyServiceApiTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.client, self.service, self.registrar, self.observer, _, _ = self.fixture.build()
        self.addCleanup(self.client.close)
        self.order = self.fixture.order()
        commitment = self.fixture.commit(self.service, self.order)
        response = self.client.post('/v1/domain-attempts', json={
            'proposal_commitment_id': commitment.commitment_id,
        })
        self.assertEqual(200, response.status_code, response.text)
        self.handle = response.json()
        self.base = '/v1/domain-attempts/' + self.handle['attempt_id']

    def operation(self, name):
        return self.client.post(self.base + '/' + name, json={'handle': self.handle})

    def test_missing_renewal_observation_stays_unresolved_then_exact_readback_reconciles(self):
        connections = []
        original_connect = self.service.budget._connect
        sqlite_connect = sqlite3.connect

        class TrackedConnection(sqlite3.Connection):
            explicitly_closed = False

            def close(self):
                super().close()
                self.explicitly_closed = True

        def tracked_connect(*args, **kwargs):
            return sqlite_connect(*args, factory=TrackedConnection, **kwargs)

        def observed_connect():
            # Preserve the production _connect setup. Observe close directly;
            # probing a TestClient worker's connection from this thread would
            # also raise ProgrammingError for an open connection.
            with patch('pulpo.commerce.sqlite3.connect', side_effect=tracked_connect):
                connection = original_connect()
            connections.append(connection)
            return connection

        original_observe = self.observer.observe
        with patch.object(self.service.budget, '_connect', side_effect=observed_connect):
            self.assertEqual(200, self.operation('execute').status_code)
            with patch.object(self.observer, 'observe', side_effect=lambda ref, order:
                              replace(original_observe(ref, order), auto_renew_enabled=None)):
                result = self.operation('reconcile')
            self.assertEqual(200, result.status_code, result.text)
            self.assertEqual('unresolved', result.json()['outcome'])
            self.assertEqual('success_observation_incomplete', result.json()['reason'])
            self.assertEqual(409, self.operation('execute').status_code)
            self.assertEqual(1, self.registrar.purchase_calls)
            result = self.operation('reconcile')
            self.assertEqual(200, result.status_code, result.text)
            self.assertEqual('success', result.json()['outcome'])
        self.assertFalse(self.order.auto_renew_enabled)
        self.assertEqual((1, 1, 2), (self.registrar.preflight_calls,
                                   self.registrar.purchase_calls, self.observer.calls))
        self.assertTrue(connections)
        for connection in connections:
            self.assertTrue(connection.explicitly_closed, 'budget lookup connection was not explicitly closed')

    def test_observed_renewal_substitution_is_failure_without_second_purchase(self):
        self.assertEqual(200, self.operation('execute').status_code)
        original = self.observer.observe
        with patch.object(self.observer, 'observe', side_effect=lambda ref, order:
                          replace(original(ref, order), auto_renew_enabled=True)):
            result = self.operation('reconcile')
        self.assertEqual(200, result.status_code, result.text)
        self.assertEqual('failure', result.json()['outcome'])
        self.assertEqual('observed_auto_renew_mismatch', result.json()['reason'])
        self.assertEqual(409, self.operation('execute').status_code)
        self.assertEqual(1, self.registrar.purchase_calls)

    def test_unavailable_reservation_read_cannot_flush_pending_evidence(self):
        head = self.service.custody.snapshot()
        self.service.custody.claim_attempt(
            expected_epoch=head.epoch, expected_state_root=head.state_root,
            attempt_id=self.handle['attempt_id'], executor_id='executor:service-v0',
        )
        self.assertGreater(self.service.evidence.pending_count(), 0)
        before = self.fixture.canonical_rows()
        with patch.object(self.service.budget, 'reservation_for_order',
                          side_effect=CommerceViolation('durable budget store unavailable')):
            for operation in ('execute', 'reconcile'):
                response = self.operation(operation)
                self.assertEqual(409, response.status_code, response.text)
                self.assertEqual(before, self.fixture.canonical_rows())
        self.assertEqual((0, 0, 0), (self.registrar.preflight_calls,
                                   self.registrar.purchase_calls, self.observer.calls))
        self.assertEqual(200, self.operation('execute').status_code)
        result = self.operation('reconcile')
        self.assertEqual(200, result.status_code, result.text)
        self.assertEqual('success', result.json()['outcome'])


if __name__ == '__main__': unittest.main(verbosity=2)

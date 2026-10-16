"""Test-only canonical custody HTTP fixtures; no production transport/writer."""
from contextlib import closing
from dataclasses import asdict
import gc
import json
import sqlite3
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import test_api as original_tests
from pulpo_custody_service.api import create_app


class CustodyFixtureTests(unittest.TestCase):
    def fixture(self, *, reuse_evidence_connection=False, sql_qos_settings=None):
        case = original_tests.CustodyServiceApiTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        client, service, registrar, observer, _, _ = case.build(
            reuse_evidence_connection=reuse_evidence_connection, sql_qos_settings=sql_qos_settings)
        self.addCleanup(gc.collect)
        self.addCleanup(client.close)
        return case, client, client.app, service, registrar, observer

    def rows(self, path):
        with closing(sqlite3.connect(path)) as db:
            names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            return {name: sorted(db.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr) for name in names}

    def flow(self):
        case, client, app, service, registrar, observer = self.fixture()
        order = case.order()
        before = asdict(order)
        commitment = case.commit(service, order)
        payload = json.dumps({"proposal_commitment_id": commitment.commitment_id}, separators=(",", ":")).encode()
        responses = []
        with patch("pulpo.kernel.secrets.token_hex", return_value="a" * 32):
            r = client.post("/v1/domain-attempts", content=payload, headers={"content-type": "application/json"})
            self.assertEqual(200, r.status_code, r.text)
            responses.append((r.status_code, r.json()))
            handle = r.json()
            for operation in ("execute", "execute", "reconcile"):
                r = client.post(f"/v1/domain-attempts/{handle['attempt_id']}/{operation}", json={"handle": handle})
                responses.append((r.status_code, r.json()))
        self.assertEqual(before, asdict(order))
        self.assertEqual((1, 1, 1), (registrar.preflight_calls, registrar.purchase_calls, observer.calls))
        return responses, self.rows(case.path)

    def check_restart_keeps_duplicate_and_execution_replay_governed(self):
        case, client, app, service, registrar, _ = self.fixture()
        commitment = case.commit(service, case.order())
        payload = {"proposal_commitment_id": commitment.commitment_id}
        first = client.post("/v1/domain-attempts", json=payload)
        self.assertEqual(200, first.status_code)
        handle = first.json()
        execute = f"/v1/domain-attempts/{handle['attempt_id']}/execute"
        self.assertEqual(200, client.post(execute, json={"handle": handle}).status_code)
        from pulpo.commerce import SQLiteBudgetAccount
        from pulpo.custody import SQLiteGovernanceCustody
        from pulpo_custody_service.core import DomainCustodyService
        from test_api import NOW, FakeObserver
        reopened_custody = SQLiteGovernanceCustody(case.path,
            signing_secret=b"service-custody-secret", clock=lambda: NOW)
        reopened = DomainCustodyService(kernel_factory=service._kernel_factory,
            custody=reopened_custody, budget=SQLiteBudgetAccount(case.path),
            registrar=registrar, observer=FakeObserver(reopened_custody),
            observer_id="observer:service-v0", executor_id="executor:service-v0")
        restarted = TestClient(create_app(reopened))
        self.addCleanup(restarted.close)
        self.assertEqual(403, restarted.post("/v1/domain-attempts", json=payload).status_code)
        self.assertEqual(409, restarted.post(execute, json={"handle": handle}).status_code)
        self.assertEqual(1, registrar.purchase_calls)


    def check_current_policy_revocation_still_denies(self):
        from pulpo.kernel import Policy
        case, client, app, service, registrar, _ = self.fixture()
        commitment = case.commit(service, case.order())
        original = service._kernel_factory
        def revoked_factory(original=original):
            kernel = original()
            kernel.policy = Policy(frozenset(), 0)
            return kernel
        service._kernel_factory = revoked_factory
        r = client.post("/v1/domain-attempts", json={"proposal_commitment_id": commitment.commitment_id})
        self.assertEqual(403, r.status_code)
        self.assertEqual(0, registrar.purchase_calls)
        self.assertEqual(0, service.budget.reserved_cents)

    def check_governed_expiry_still_denies(self):
        from dataclasses import replace
        from test_api import NOW
        case, client, app, service, registrar, _ = self.fixture()
        order = replace(case.order(), expires_at_ns=NOW-1)
        commitment = service.proposals.create(order, availability_hash="a"*64,
            created_at_ns=NOW-100, expires_at_ns=NOW-1)
        r = client.post("/v1/domain-attempts", json={"proposal_commitment_id": commitment.commitment_id})
        self.assertEqual(403, r.status_code)
        self.assertEqual(0, registrar.purchase_calls)

    def check_canonical_audit_tamper_still_denies(self):
        case, client, app, service, registrar, _ = self.fixture()
        original = service._kernel_factory()
        original._state.append("fixture", {"value": "original"}, 31_000_000)
        original._state.close()
        with closing(sqlite3.connect(case.path)) as db:
            db.execute("UPDATE audit SET payload_json='{}' WHERE sequence=(SELECT MIN(sequence) FROM audit)")
            db.commit()
        commitment = case.commit(service, case.order())
        from pulpo.kernel import StateIntegrityError
        with self.assertRaises(StateIntegrityError):
            client.post("/v1/domain-attempts", json={"proposal_commitment_id": commitment.commitment_id})
        self.assertEqual(0, registrar.purchase_calls)

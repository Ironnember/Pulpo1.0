from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

import test_service
from pulpo_authority_service import AuthorityConfig, AuthorityService
from pulpo_authority_service.postgres_state import PostgresAuthorityState
from pulpo_authority_service.restart_adapters import DirectoryEvidenceSink


DSN = os.environ.get("PULPO_AUTHORITY_TEST_POSTGRES_DSN")


@unittest.skipUnless(DSN, "PULPO_AUTHORITY_TEST_POSTGRES_DSN not configured")
class PostgresAuthorityStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        cls.psycopg = psycopg

    def setUp(self):
        fixture = test_service.AuthorityServiceTests(
            methodName="test_one_exact_verified_ceremony_produces_one_kernel_usable_envelope"
        )
        fixture.setUp()
        self.fixture = fixture
        self.service_trust = replace(
            fixture.service_trust,
            max_approval_ttl_ns=120_000_000_000,
        )
        self.request = replace(
            fixture.request,
            requested_ttl_ns=60_000_000_000,
        )
        with self.psycopg.connect(DSN) as connection:
            connection.execute("DROP TABLE IF EXISTS pulpo_authority_state")
            connection.commit()

    def _factory(self):
        return self.psycopg.connect(DSN)

    def _credentials(self):
        return (self.fixture.primary, self.fixture.recovery)

    def _state(self):
        return PostgresAuthorityState(self._factory, self._credentials())

    def _service(self, state, evidence, tokens):
        return AuthorityService(
            AuthorityConfig(
                self.service_trust,
                "example.com",
                "https://authority.example.com",
            ),
            state,
            self.fixture.webauthn,
            test_service.Ed25519TestSigner(
                self.fixture.private_key,
                self.fixture.approval_verifier,
            ),
            evidence,
            clock=state.trusted_time_ns,
            random_token=lambda _: next(tokens),
        )

    def test_database_server_time_and_approved_state_survive_new_service_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = DirectoryEvidenceSink(Path(directory) / "evidence")
            state = self._state()
            service = self._service(
                state,
                evidence,
                iter(("request-postgres", "approval-postgres", "nonce-postgres")),
            )
            before = time.time_ns()
            request_id, _ = service.request_approval(self.request)
            envelope = service.approve(
                request_id,
                self.fixture.primary.credential_id,
                "postgres-assertion",
            )
            after = time.time_ns()

            self.assertGreaterEqual(state.last_time_ns, before - 5_000_000_000)
            self.assertLessEqual(state.last_time_ns, after + 5_000_000_000)
            self.assertEqual(1, state.sequence)

            restarted_state = self._state()
            restarted = self._service(
                restarted_state,
                evidence,
                iter(("unused-r", "unused-a", "unused-n")),
            )
            polled = restarted.poll(request_id)
            self.assertEqual("approved", polled["status"])
            self.assertEqual(asdict(envelope), polled["envelope"])
            self.assertEqual(1, restarted_state.sequence)
            self.assertEqual(5, restarted_state.credentials[self.fixture.primary.credential_id].sign_count)

    def test_same_request_race_across_independent_postgres_state_objects_serializes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = DirectoryEvidenceSink(Path(directory) / "evidence")
            state_a = self._state()
            service_a = self._service(
                state_a,
                evidence,
                iter(("request-race", "approval-race", "nonce-race")),
            )
            request_id, _ = service_a.request_approval(self.request)

            state_b = self._state()
            service_b = self._service(
                state_b,
                evidence,
                iter(("unused-b-r", "unused-b-a", "unused-b-n")),
            )
            barrier = threading.Barrier(2)

            def attempt(service, assertion):
                barrier.wait(timeout=5)
                try:
                    service.approve(request_id, self.fixture.primary.credential_id, assertion)
                    return "approved"
                except RuntimeError:
                    return "closed"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(
                    executor.map(
                        lambda args: attempt(*args),
                        (
                            (service_a, "assertion-a"),
                            (service_b, "assertion-b"),
                        ),
                    )
                )

            final_state = self._state()
            final = self._service(
                final_state,
                evidence,
                iter(("unused-f-r", "unused-f-a", "unused-f-n")),
            ).poll(request_id)
            self.assertEqual("approved", final["status"])
            self.assertEqual(1, final_state.sequence)
            self.assertEqual(5, final_state.credentials[self.fixture.primary.credential_id].sign_count)
            self.assertEqual(1, len(self.fixture.webauthn.calls))
            self.assertEqual(1, len(tuple((Path(directory) / "evidence").glob("*.json"))))
            self.assertIn("approved", outcomes)

    def test_distinct_request_race_produces_strict_sequences_and_counter_progression(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence_dir = Path(directory) / "evidence"
            evidence = DirectoryEvidenceSink(evidence_dir)
            state_a = self._state()
            service_a = self._service(
                state_a,
                evidence,
                iter(("request-a", "approval-a", "nonce-a")),
            )
            request_a, _ = service_a.request_approval(self.request)

            state_b = self._state()
            service_b = self._service(
                state_b,
                evidence,
                iter(("request-b", "approval-b", "nonce-b")),
            )
            request_b, _ = service_b.request_approval(self.request)
            barrier = threading.Barrier(2)

            def approve(service, request_id, assertion):
                barrier.wait(timeout=5)
                return service.approve(request_id, self.fixture.primary.credential_id, assertion)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = (
                    executor.submit(approve, service_a, request_a, "assertion-a"),
                    executor.submit(approve, service_b, request_b, "assertion-b"),
                )
                [future.result(timeout=10) for future in futures]

            final_state = self._state()
            self.assertEqual(2, final_state.sequence)
            self.assertEqual(6, final_state.credentials[self.fixture.primary.credential_id].sign_count)
            sequences = {
                json.loads(path.read_text())["sequence"]
                for path in evidence_dir.glob("*.json")
            }
            self.assertEqual({1, 2}, sequences)

    def test_state_payload_tamper_without_matching_hash_fails_closed(self):
        self._state()
        with self.psycopg.connect(DSN) as connection:
            payload = connection.execute(
                "SELECT payload FROM pulpo_authority_state WHERE singleton = TRUE"
            ).fetchone()[0]
            connection.execute(
                "UPDATE pulpo_authority_state SET payload = %s WHERE singleton = TRUE",
                (str(payload).replace('"sequence":0', '"sequence":9'),),
            )
            connection.commit()

        with self.assertRaisesRegex(RuntimeError, "integrity failure"):
            self._state()


if __name__ == "__main__":
    unittest.main()

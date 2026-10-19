from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import threading
import unittest

import test_service
from pulpo_authority_service import AuthorityConfig, AuthorityService
from pulpo_authority_service.restart_adapters import DirectoryEvidenceSink, SQLiteRestartState


class MultiInstanceAuthorityStateTests(unittest.TestCase):
    def setUp(self):
        fixture = test_service.AuthorityServiceTests(
            methodName="test_one_exact_verified_ceremony_produces_one_kernel_usable_envelope"
        )
        fixture.setUp()
        self.fixture = fixture

    def _credentials(self):
        return (self.fixture.primary, self.fixture.recovery)

    def _service(self, state, evidence, tokens):
        return AuthorityService(
            AuthorityConfig(
                self.fixture.service_trust,
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
            clock=lambda: test_service.NOW,
            random_token=lambda _: next(tokens),
        )

    def test_same_request_race_accepts_one_human_verification_and_one_evidence_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "authority.sqlite3"
            evidence = DirectoryEvidenceSink(root / "evidence")

            state_a = SQLiteRestartState(database, self._credentials())
            service_a = self._service(
                state_a,
                evidence,
                iter(("request-race", "approval-race", "nonce-race")),
            )
            request_id, _ = service_a.request_approval(self.fixture.request)

            # A genuinely independent service object starts from the persisted
            # snapshot. Its process-local mutex is unrelated to state_a's.
            state_b = SQLiteRestartState(database, self._credentials())
            service_b = self._service(
                state_b,
                evidence,
                iter(("unused-request-b", "unused-approval-b", "unused-nonce-b")),
            )
            barrier = threading.Barrier(2)

            def attempt(service, assertion):
                barrier.wait(timeout=5)
                try:
                    return ("approved", asdict(service.approve(
                        request_id,
                        self.fixture.primary.credential_id,
                        assertion,
                    )))
                except RuntimeError as exc:
                    return ("closed", str(exc))

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(
                        lambda args: attempt(*args),
                        (
                            (service_a, "assertion-from-instance-a"),
                            (service_b, "assertion-from-instance-b"),
                        ),
                    )
                )

            final_state = SQLiteRestartState(database, self._credentials())
            final = self._service(
                final_state,
                evidence,
                iter(("unused-final", "unused-final-approval", "unused-final-nonce")),
            ).poll(request_id)

            self.assertEqual("approved", final["status"])
            self.assertEqual(1, final_state.sequence)
            self.assertEqual(5, final_state.credentials[self.fixture.primary.credential_id].sign_count)
            self.assertEqual(1, len(tuple((root / "evidence").glob("*.json"))))
            self.assertEqual(1, len(self.fixture.webauthn.calls))
            self.assertTrue(any(status == "approved" for status, _ in results))

    def test_two_request_race_serializes_sequence_and_credential_counter_across_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "authority.sqlite3"
            evidence = DirectoryEvidenceSink(root / "evidence")

            state_a = SQLiteRestartState(database, self._credentials())
            service_a = self._service(
                state_a,
                evidence,
                iter(("request-a", "approval-a", "nonce-a")),
            )
            request_a, _ = service_a.request_approval(self.fixture.request)

            state_b = SQLiteRestartState(database, self._credentials())
            service_b = self._service(
                state_b,
                evidence,
                iter(("request-b", "approval-b", "nonce-b")),
            )
            request_b, _ = service_b.request_approval(self.fixture.request)
            barrier = threading.Barrier(2)

            def approve(service, request_id, assertion):
                barrier.wait(timeout=5)
                return service.approve(
                    request_id,
                    self.fixture.primary.credential_id,
                    assertion,
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = (
                    executor.submit(approve, service_a, request_a, "assertion-a"),
                    executor.submit(approve, service_b, request_b, "assertion-b"),
                )
                envelopes = [future.result(timeout=10) for future in futures]

            final_state = SQLiteRestartState(database, self._credentials())
            self.assertEqual(2, final_state.sequence)
            self.assertEqual(6, final_state.credentials[self.fixture.primary.credential_id].sign_count)
            self.assertEqual(2, len(envelopes))
            self.assertEqual(2, len(self.fixture.webauthn.calls))

            objects = tuple((root / "evidence").glob("*.json"))
            self.assertEqual(2, len(objects))
            sequences = {
                json.loads(path.read_text())["sequence"]
                for path in objects
            }
            self.assertEqual({1, 2}, sequences)

            final_service = self._service(
                final_state,
                evidence,
                iter(("unused-final", "unused-final-approval", "unused-final-nonce")),
            )
            self.assertEqual("approved", final_service.poll(request_a)["status"])
            self.assertEqual("approved", final_service.poll(request_b)["status"])


if __name__ == "__main__":
    unittest.main()

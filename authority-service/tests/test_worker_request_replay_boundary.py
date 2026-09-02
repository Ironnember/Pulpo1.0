from __future__ import annotations

from dataclasses import asdict
import unittest

from fastapi.testclient import TestClient

import test_service
from pulpo_authority_service.api import create_app


class FakeWorkerAuthenticator:
    def authenticate(self, request):
        if request.headers.get("authorization") != "Bearer worker-test-token":
            raise PermissionError("invalid worker identity")
        return "worker:governed"


class AuthorityRequestWriterReplayBoundaryTests(unittest.TestCase):
    def test_byte_identical_authenticated_submit_cannot_mint_second_pending_record(self) -> None:
        fixture = test_service.AuthorityServiceTests(
            methodName="test_one_exact_verified_ceremony_produces_one_kernel_usable_envelope"
        )
        fixture.setUp()
        service = fixture.service
        client = TestClient(
            create_app(service, worker_authenticator=FakeWorkerAuthenticator()),
            headers={"Authorization": "Bearer worker-test-token"},
        )
        body = asdict(fixture.request)

        first = client.post("/v1/approval-requests", json=body)
        second = client.post("/v1/approval-requests", json=body)

        self.assertEqual(200, first.status_code)
        self.assertIn(second.status_code, {200, 409})

        # The API may satisfy this boundary by returning the original request
        # idempotently or by rejecting the duplicate. It must not create a
        # second independently approvable canonical authority-state record.
        if second.status_code == 200:
            self.assertEqual(first.json()["request_id"], second.json()["request_id"])
        self.assertEqual(1, len(service.state.requests))


if __name__ == "__main__":
    unittest.main()

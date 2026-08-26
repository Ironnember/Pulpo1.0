from __future__ import annotations

from dataclasses import asdict
import unittest

from fastapi.testclient import TestClient

import test_service
from pulpo_authority_service.api import create_app
from pulpo_authority_service.webauthn_adapter import PyWebAuthnVerifier


class AuthorityApiTests(unittest.TestCase):
    def setUp(self):
        fixture = test_service.AuthorityServiceTests(
            methodName="test_one_exact_verified_ceremony_produces_one_kernel_usable_envelope"
        )
        fixture.setUp()
        self.fixture = fixture
        self.service = fixture.service
        self.request = fixture.request
        self.intent = fixture.intent
        self.primary = fixture.primary
        self.client = TestClient(create_app(self.service))

    def test_http_surface_exposes_request_poll_and_human_ceremony(self):
        created = self.client.post("/v1/approval-requests", json=asdict(self.request))
        self.assertEqual(200, created.status_code)
        request_id = created.json()["request_id"]

        pending = self.client.get(f"/v1/approval-requests/{request_id}")
        display = self.client.get(f"/human/approval/{request_id}")
        challenge = self.client.post(f"/human/approval/{request_id}/challenge")
        completed = self.client.post(
            f"/human/approval/{request_id}/assertion",
            json={"credential_id": self.primary.credential_id, "assertion": "raw-assertion-json"},
        )
        approved = self.client.get(f"/v1/approval-requests/{request_id}")

        self.assertEqual("pending", pending.json()["status"])
        self.assertEqual(self.intent.resource, display.json()["resource"])
        self.assertEqual("required", challenge.json()["user_verification"])
        self.assertEqual("discoverable", challenge.json()["credential_selection"])
        self.assertNotIn("credential_ids", challenge.json())
        self.assertEqual("approved", completed.json()["status"])
        self.assertEqual("approved", approved.json()["status"])
        self.assertIn("envelope", approved.json())

    def test_unknown_invalid_and_extra_input_fail_closed(self):
        self.assertEqual(404, self.client.get("/v1/approval-requests/unknown").status_code)
        invalid = asdict(self.request)
        invalid["unexpected"] = "value"
        self.assertEqual(422, self.client.post("/v1/approval-requests", json=invalid).status_code)
        mismatch = asdict(self.request)
        mismatch["resource"] = "repo:attacker"
        self.assertEqual(400, self.client.post("/v1/approval-requests", json=mismatch).status_code)
        created = self.client.post("/v1/approval-requests", json=asdict(self.request))
        request_id = created.json()["request_id"]
        self.service.verifier = PyWebAuthnVerifier()
        malformed = self.client.post(
            f"/human/approval/{request_id}/assertion",
            json={"credential_id": "credential:primary", "assertion": "{"},
        )
        self.assertEqual(403, malformed.status_code)

    def test_http_surface_has_no_denial_or_credential_administration_route(self):
        paths = {route.path for route in self.client.app.routes}
        self.assertNotIn("/human/approval/{request_id}/deny", paths)
        self.assertFalse(any(term in path for path in paths for term in ("enroll", "recover", "revoke", "rotate")))


if __name__ == "__main__":
    unittest.main()

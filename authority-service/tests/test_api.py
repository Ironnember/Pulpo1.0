from __future__ import annotations

from dataclasses import asdict, replace
import unittest

from fastapi.testclient import TestClient

import test_service
from pulpo_authority_service.api import create_app
from pulpo_authority_service.webauthn_adapter import PyWebAuthnVerifier


class FakeWorkerAuthenticator:
    def __init__(self, expected="Bearer worker-test-token", identity="worker:governed", failure=None):
        self.expected = expected
        self.identity = identity
        self.failure = failure

    def authenticate(self, request):
        if self.failure is not None:
            raise self.failure
        if request.headers.get("authorization") != self.expected:
            raise PermissionError("invalid worker identity")
        return self.identity


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
        app = create_app(self.service, worker_authenticator=FakeWorkerAuthenticator())
        self.client = TestClient(app, headers={"Authorization": "Bearer worker-test-token"})

    def test_http_surface_exposes_authenticated_request_poll_and_human_ceremony(self):
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
        self.assertIn(self.intent.resource, display.text)
        self.assertIn('id="pulpo-approve"', display.text)
        self.assertEqual("required", challenge.json()["user_verification"])
        self.assertEqual("discoverable", challenge.json()["credential_selection"])
        self.assertEqual(["security-key"], challenge.json()["hints"])
        self.assertNotIn("credential_ids", challenge.json())
        self.assertEqual("approved", completed.json()["status"])
        self.assertEqual("approved", approved.json()["status"])
        self.assertIn("envelope", approved.json())

    def test_worker_routes_fail_closed_without_explicit_authentication(self):
        locked = TestClient(create_app(self.service))
        self.assertEqual(401, locked.post("/v1/approval-requests", json=asdict(self.request)).status_code)

        wrong = TestClient(
            create_app(self.service, worker_authenticator=FakeWorkerAuthenticator()),
            headers={"Authorization": "Bearer attacker"},
        )
        self.assertEqual(401, wrong.post("/v1/approval-requests", json=asdict(self.request)).status_code)

        unavailable = TestClient(
            create_app(
                self.service,
                worker_authenticator=FakeWorkerAuthenticator(failure=RuntimeError("identity unavailable")),
            ),
            headers={"Authorization": "Bearer worker-test-token"},
        )
        self.assertEqual(503, unavailable.post("/v1/approval-requests", json=asdict(self.request)).status_code)

    def test_human_surface_remains_public_while_worker_surface_is_locked(self):
        created = self.client.post("/v1/approval-requests", json=asdict(self.request))
        request_id = created.json()["request_id"]
        public = TestClient(create_app(self.service))

        self.assertEqual(200, public.get(f"/human/approval/{request_id}").status_code)
        self.assertEqual(200, public.post(f"/human/approval/{request_id}/challenge").status_code)
        self.assertEqual(401, public.get(f"/v1/approval-requests/{request_id}").status_code)

    def test_human_page_invokes_only_the_existing_webauthn_assertion_route(self):
        created = self.client.post("/v1/approval-requests", json=asdict(self.request))
        request_id = created.json()["request_id"]

        page = self.client.get(f"/human/approval/{request_id}")
        script = self.client.get("/human/approval.js")

        self.assertEqual(200, page.status_code)
        self.assertTrue(page.headers["content-type"].startswith("text/html"))
        self.assertEqual("no-store", page.headers["cache-control"])
        self.assertIn("default-src 'none'", page.headers["content-security-policy"])
        self.assertEqual("publickey-credentials-get=(self)", page.headers["permissions-policy"])
        self.assertIn("A click alone grants no authority", page.text)
        self.assertIn("approved Pulpo hardware authenticator", page.text)
        self.assertNotIn("Touch ID", page.text)
        self.assertNotIn("Face ID", page.text)
        self.assertNotIn("navigator.credentials", page.text)

        self.assertEqual(200, script.status_code)
        self.assertTrue(script.headers["content-type"].startswith("application/javascript"))
        self.assertIn("navigator.credentials.get", script.text)
        self.assertIn("userVerification: 'required'", script.text)
        self.assertIn("hints: ['security-key']", script.text)
        self.assertIn("credential_id: credential.id", script.text)
        self.assertNotIn("/deny", script.text)

    def test_human_page_escapes_request_text_and_disables_completed_requests(self):
        hostile = replace(self.request, resource='repo:</dd><script id="attack">alert(1)</script>')
        hostile = replace(hostile, intent_hash=hostile.recomputed_intent_hash)
        created = self.client.post("/v1/approval-requests", json=asdict(hostile))
        request_id = created.json()["request_id"]

        page = self.client.get(f"/human/approval/{request_id}")
        self.assertNotIn('<script id="attack">', page.text)
        self.assertIn("&lt;script id=&quot;attack&quot;&gt;", page.text)

        completed = self.client.post(
            f"/human/approval/{request_id}/assertion",
            json={"credential_id": self.primary.credential_id, "assertion": "raw-assertion-json"},
        )
        self.assertEqual(200, completed.status_code)
        completed_page = self.client.get(f"/human/approval/{request_id}")
        self.assertIn('id="pulpo-approve" type="button" disabled', completed_page.text)
        self.assertIn("This request is approved.", completed_page.text)

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

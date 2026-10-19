from __future__ import annotations

from types import SimpleNamespace
import unittest

from pulpo_authority_service.google_worker_auth import GoogleServiceAccountWorkerAuthenticator


AUDIENCE = "pulpo-authority-worker-v0"
SUBJECT = "112010400000000710080"
EMAIL = "pulpo-worker@pulpo-proof.iam.gserviceaccount.com"


class FakeVerifier:
    def __init__(self, claims=None, failure=None):
        self.claims = claims or {
            "iss": "https://accounts.google.com",
            "aud": AUDIENCE,
            "sub": SUBJECT,
            "azp": SUBJECT,
            "email": EMAIL,
            "email_verified": True,
        }
        self.failure = failure
        self.calls = []

    def __call__(self, token, audience):
        self.calls.append((token, audience))
        if self.failure is not None:
            raise self.failure
        return dict(self.claims)


class GoogleServiceAccountWorkerAuthenticatorTests(unittest.TestCase):
    def _request(self, authorization=None):
        headers = {}
        if authorization is not None:
            headers["authorization"] = authorization
        return SimpleNamespace(headers=headers)

    def _authenticator(self, verifier=None):
        return GoogleServiceAccountWorkerAuthenticator(
            audience=AUDIENCE,
            expected_subject=SUBJECT,
            expected_email=EMAIL,
            verifier=verifier or FakeVerifier(),
        )

    def test_exact_google_signed_service_identity_is_accepted(self):
        verifier = FakeVerifier()
        authenticator = self._authenticator(verifier)

        identity = authenticator.authenticate(self._request("Bearer exact-google-id-token"))

        self.assertEqual(f"google-service-account:{SUBJECT}", identity)
        self.assertEqual([("exact-google-id-token", AUDIENCE)], verifier.calls)

    def test_missing_or_malformed_bearer_token_fails_closed_before_verification(self):
        verifier = FakeVerifier()
        authenticator = self._authenticator(verifier)
        headers = (
            None,
            "Basic token",
            "Bearer ",
            "Bearer token ",
            "Bearer " + ("x" * 16_385),
        )
        for value in headers:
            with self.subTest(value=None if value is None else value[:20]), self.assertRaises(PermissionError):
                authenticator.authenticate(self._request(value))
        self.assertEqual([], verifier.calls)

    def test_issuer_audience_subject_authorized_party_email_and_verification_are_all_pinned(self):
        base = FakeVerifier().claims
        cases = (
            ({**base, "iss": "https://attacker.example"}, "issuer"),
            ({**base, "aud": "other-audience"}, "audience"),
            ({**base, "sub": "999"}, "subject"),
            ({**base, "azp": "999"}, "authorized-party"),
            ({**base, "email": "attacker@example.com"}, "email mismatch"),
            ({**base, "email_verified": False}, "not verified"),
        )
        for claims, message in cases:
            with self.subTest(message=message):
                authenticator = self._authenticator(FakeVerifier(claims=claims))
                with self.assertRaisesRegex(PermissionError, message):
                    authenticator.authenticate(self._request("Bearer token"))

    def test_invalid_token_is_unauthorized_but_verifier_outage_is_unavailable(self):
        invalid = self._authenticator(FakeVerifier(failure=ValueError("bad signature")))
        with self.assertRaises(PermissionError):
            invalid.authenticate(self._request("Bearer token"))

        unavailable = self._authenticator(FakeVerifier(failure=OSError("cert fetch unavailable")))
        with self.assertRaisesRegex(RuntimeError, "verification unavailable"):
            unavailable.authenticate(self._request("Bearer token"))

    def test_configuration_requires_exact_nonempty_identity_values(self):
        cases = (
            {"audience": "", "expected_subject": SUBJECT, "expected_email": EMAIL},
            {"audience": AUDIENCE, "expected_subject": " subject", "expected_email": EMAIL},
            {"audience": AUDIENCE, "expected_subject": SUBJECT, "expected_email": "not-an-email"},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                GoogleServiceAccountWorkerAuthenticator(**values, verifier=FakeVerifier())


if __name__ == "__main__":
    unittest.main()

"""Google-signed OIDC worker authentication for the narrow authority API.

This authenticator grants only the identity result consumed by `api.py` for
`/v1` submit/poll access. It does not grant approval, signing, credential
administration, or any Pulpo authority by itself.
"""

from __future__ import annotations

from typing import Callable

from fastapi import Request


ClaimsVerifier = Callable[[str, str], dict[str, object]]


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _google_verify(token: str, audience: str) -> dict[str, object]:
    try:
        from google.auth.transport.requests import Request as GoogleAuthRequest
        from google.oauth2 import id_token
    except ImportError as exc:
        raise RuntimeError("google-auth is required for live Google worker authentication") from exc
    value = id_token.verify_oauth2_token(token, GoogleAuthRequest(), audience)
    if not isinstance(value, dict):
        raise ValueError("Google ID token verifier returned non-object claims")
    return value


class GoogleServiceAccountWorkerAuthenticator:
    """Pin one Google service-account ID-token subject, email and audience."""

    def __init__(
        self,
        *,
        audience: str,
        expected_subject: str,
        expected_email: str,
        verifier: ClaimsVerifier | None = None,
    ) -> None:
        for value, field in (
            (audience, "audience"),
            (expected_subject, "expected_subject"),
            (expected_email, "expected_email"),
        ):
            _require_text(value, field)
        if "@" not in expected_email:
            raise ValueError("expected_email must identify one service account")
        self.audience = audience
        self.expected_subject = expected_subject
        self.expected_email = expected_email
        self.verifier = verifier or _google_verify

    def authenticate(self, request: Request) -> str:
        header = request.headers.get("authorization")
        if not isinstance(header, str) or not header.startswith("Bearer "):
            raise PermissionError("Google worker ID token required")
        token = header[7:]
        if not token or token != token.strip() or len(token) > 16_384:
            raise PermissionError("invalid Google worker ID token framing")

        try:
            claims = self.verifier(token, self.audience)
        except ValueError as exc:
            raise PermissionError("Google worker ID token rejected") from exc
        except PermissionError:
            raise
        except Exception as exc:
            raise RuntimeError("Google worker identity verification unavailable") from exc

        if not isinstance(claims, dict):
            raise PermissionError("Google worker ID token claims are invalid")
        if claims.get("iss") != "https://accounts.google.com":
            raise PermissionError("Google worker issuer mismatch")
        if claims.get("aud") != self.audience:
            raise PermissionError("Google worker audience mismatch")
        if claims.get("sub") != self.expected_subject:
            raise PermissionError("Google worker subject mismatch")
        if claims.get("azp") != self.expected_subject:
            raise PermissionError("Google worker authorized-party mismatch")
        if claims.get("email") != self.expected_email:
            raise PermissionError("Google worker email mismatch")
        if claims.get("email_verified") is not True:
            raise PermissionError("Google worker email is not verified")
        return f"google-service-account:{self.expected_subject}"

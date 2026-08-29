"""One-shot hardware WebAuthn bootstrap that creates a credential *candidate*.

This module is intentionally separate from the running authority service. A
successful ceremony writes public credential material plus attestation metadata
into a candidate file. It does not modify authority state, sign an approval,
issue a permit, or activate the credential.

Constitutional boundary:

    BOOTSTRAP_TOKEN != AUTHORITY
    ENROLLMENT_CANDIDATE != ACTIVE_CREDENTIAL
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import bytes_to_base64url, parse_registration_credential_json
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AttestationFormat,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


CANDIDATE_SCHEMA = "pulpo.webauthn-credential-candidate.v0"
MAX_BOOTSTRAP_TOKEN_BYTES = 16_000
MAX_SESSION_TTL_SECONDS = 600


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_text(value: str, field: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")
    return value


def _require_digest(value: str, field: str) -> str:
    if (
        len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class EnrollmentConfig:
    rp_id: str
    origin: str
    candidate_path: Path
    session_ttl_seconds: int = 300
    role: str = "primary"

    def __post_init__(self) -> None:
        _require_text(self.rp_id, "rp_id")
        parsed = urlparse(self.origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("origin must be an exact HTTPS origin")
        if parsed.hostname != self.rp_id and not parsed.hostname.endswith(f".{self.rp_id}"):
            raise ValueError("origin host must equal or be below rp_id")
        if not self.candidate_path.is_absolute():
            raise ValueError("candidate_path must be absolute")
        if (
            isinstance(self.session_ttl_seconds, bool)
            or not isinstance(self.session_ttl_seconds, int)
            or self.session_ttl_seconds <= 0
            or self.session_ttl_seconds > MAX_SESSION_TTL_SECONDS
        ):
            raise ValueError("session_ttl_seconds is outside the allowed range")
        if self.role not in {"primary", "recovery"}:
            raise ValueError("unsupported credential role")


@dataclass(frozen=True)
class EnrollmentSession:
    session_id: str
    challenge: bytes
    user_id: bytes
    created_at_ns: int
    expires_at_ns: int


@dataclass(frozen=True)
class EnrollmentCandidate:
    rp_id: str
    origin: str
    role: str
    credential_id: str
    public_key_hex: str
    sign_count: int
    aaguid: str
    attestation_format: str
    attestation_object_hash: str
    credential_device_type: str
    credential_backed_up: bool
    user_verified: bool
    authenticator_attachment: str
    created_at_ns: int
    schema: str = CANDIDATE_SCHEMA
    admission_class: str = "local_acceptance_candidate_only"
    authority_effect: str = "none_until_explicit_admission"

    @property
    def candidate_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()

    @property
    def runtime_record(self) -> dict[str, object]:
        return {
            "credential_id": self.credential_id,
            "public_key_hex": self.public_key_hex,
            "sign_count": self.sign_count,
            "role": self.role,
            "active": True,
            # Local acceptance definition only: a non-none verified attestation
            # from a single-device cross-platform authenticator. This is not a
            # claim of manufacturer/root provenance for production.
            "hardware_attested": True,
            "backup_eligible": False,
        }


RegistrationVerifier = Callable[..., Any]
OptionsGenerator = Callable[..., Any]


class HardwareEnrollmentService:
    """One active one-shot registration session and one immutable candidate."""

    def __init__(
        self,
        config: EnrollmentConfig,
        *,
        registration_verifier: RegistrationVerifier = verify_registration_response,
        options_generator: OptionsGenerator = generate_registration_options,
        clock: Callable[[], int] | None = None,
        random_bytes: Callable[[int], bytes] | None = None,
        random_token: Callable[[int], str] | None = None,
    ) -> None:
        self.config = config
        self.registration_verifier = registration_verifier
        self.options_generator = options_generator
        self._clock = clock or time.time_ns
        self._random_bytes = random_bytes or secrets.token_bytes
        self._random_token = random_token or secrets.token_hex
        self._lock = threading.RLock()
        self._session: EnrollmentSession | None = None
        self._candidate: EnrollmentCandidate | None = None

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RuntimeError("enrollment trusted time unavailable")
        return value

    def begin(self) -> dict[str, object]:
        with self._lock:
            if self.config.candidate_path.exists() or self._candidate is not None:
                raise RuntimeError("an enrollment candidate already exists")
            now = self._now()
            if self._session is not None and now < self._session.expires_at_ns:
                raise RuntimeError("an enrollment session is already active")
            challenge = self._random_bytes(32)
            user_id = self._random_bytes(32)
            if len(challenge) != 32 or len(user_id) != 32:
                raise RuntimeError("enrollment randomness unavailable")
            session = EnrollmentSession(
                session_id=f"enrollment:{self._random_token(16)}",
                challenge=challenge,
                user_id=user_id,
                created_at_ns=now,
                expires_at_ns=now + self.config.session_ttl_seconds * 1_000_000_000,
            )
            options = self.options_generator(
                rp_id=self.config.rp_id,
                rp_name="Pulpo Independent Authority",
                user_name=f"pulpo-authority-{self.config.role}",
                user_id=user_id,
                user_display_name=f"Pulpo Authority {self.config.role.title()} Credential",
                challenge=challenge,
                timeout=self.config.session_ttl_seconds * 1000,
                attestation=AttestationConveyancePreference.DIRECT,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                hints=[PublicKeyCredentialHint.SECURITY_KEY],
            )
            self._session = session
            return {
                "schema": "pulpo.webauthn-enrollment-options.v0",
                "session_id": session.session_id,
                "expires_at_ns": session.expires_at_ns,
                "public_key": json.loads(options_to_json(options)),
                "authority_effect": "none",
            }

    def complete(self, session_id: str, credential: dict[str, object]) -> dict[str, object]:
        with self._lock:
            session = self._session
            if session is None or session.session_id != session_id:
                raise PermissionError("unknown enrollment session")
            now = self._now()
            if now >= session.expires_at_ns:
                self._session = None
                raise PermissionError("enrollment session expired")
            if self.config.candidate_path.exists() or self._candidate is not None:
                raise RuntimeError("an enrollment candidate already exists")
            attachment = credential.get("authenticatorAttachment")
            if attachment != AuthenticatorAttachment.CROSS_PLATFORM.value:
                raise PermissionError("only a cross-platform security key may be enrolled")

        try:
            parsed = parse_registration_credential_json(credential)
            if parsed.authenticator_attachment != AuthenticatorAttachment.CROSS_PLATFORM:
                raise PermissionError("registration attachment is not cross-platform")
            verified = self.registration_verifier(
                credential=credential,
                expected_challenge=session.challenge,
                expected_rp_id=self.config.rp_id,
                expected_origin=self.config.origin,
                require_user_presence=True,
                require_user_verification=True,
            )
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("WebAuthn hardware registration rejected") from exc

        device_type = verified.credential_device_type
        if device_type == CredentialDeviceType.MULTI_DEVICE:
            raise PermissionError("multi-device/passkey credentials are prohibited")
        if verified.credential_backed_up:
            raise PermissionError("backed-up credentials are prohibited")
        if verified.user_verified is not True:
            raise PermissionError("fresh user verification is required")
        if verified.fmt == AttestationFormat.NONE:
            raise PermissionError("direct authenticator attestation is required")
        if isinstance(verified.sign_count, bool) or not isinstance(verified.sign_count, int) or verified.sign_count < 0:
            raise PermissionError("authenticator sign counter is invalid")

        candidate = EnrollmentCandidate(
            rp_id=self.config.rp_id,
            origin=self.config.origin,
            role=self.config.role,
            credential_id=bytes_to_base64url(verified.credential_id),
            public_key_hex=bytes(verified.credential_public_key).hex(),
            sign_count=verified.sign_count,
            aaguid=verified.aaguid,
            attestation_format=verified.fmt.value,
            attestation_object_hash=sha256(bytes(verified.attestation_object)).hexdigest(),
            credential_device_type=verified.credential_device_type.value,
            credential_backed_up=False,
            user_verified=True,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM.value,
            created_at_ns=self._now(),
        )
        self._write_candidate(candidate)
        with self._lock:
            self._candidate = candidate
            self._session = None
        return {
            "status": "candidate_created",
            "candidate_hash": candidate.candidate_hash,
            "candidate_path": str(self.config.candidate_path),
            "runtime_record": candidate.runtime_record,
            "authority_effect": candidate.authority_effect,
        }

    def _write_candidate(self, candidate: EnrollmentCandidate) -> None:
        target = self.config.candidate_path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            **asdict(candidate),
            "candidate_hash": candidate.candidate_hash,
            "runtime_record": candidate.runtime_record,
        }
        encoded = json.dumps(payload, sort_keys=True, indent=2).encode() + b"\n"
        try:
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RuntimeError("enrollment candidate path already exists") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            raise


class DigestBootstrapAuthenticator:
    """Authorize candidate bootstrap only; possession grants no Pulpo authority."""

    def __init__(self, expected_token_sha256: str) -> None:
        self.expected_token_sha256 = _require_digest(
            expected_token_sha256,
            "PULPO_ENROLLMENT_BOOTSTRAP_TOKEN_SHA256",
        )

    def authenticate(self, request: FastAPIRequest) -> str:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise PermissionError("bootstrap bearer token required")
        token = header[7:]
        if (
            not token
            or token != token.strip()
            or any(character.isspace() for character in token)
            or len(token.encode()) > MAX_BOOTSTRAP_TOKEN_BYTES
        ):
            raise PermissionError("bootstrap bearer token is malformed")
        actual = sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(actual, self.expected_token_sha256):
            raise PermissionError("bootstrap bearer token rejected")
        return f"bootstrap:{actual[:16]}"


BOOTSTRAP_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "Permissions-Policy": "publickey-credentials-create=(self)",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


BOOTSTRAP_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pulpo Hardware Credential Bootstrap</title></head>
<body><main>
<h1>Pulpo hardware credential bootstrap</h1>
<p>This creates a candidate only. It grants no Pulpo authority until separately admitted.</p>
<p>Use a dedicated cross-platform FIDO2 security key. Synced/passkey credentials are rejected.</p>
<button id="enroll" type="button">Create hardware credential candidate</button>
<pre id="status">Ready.</pre>
</main><script src="/bootstrap.js"></script></body></html>"""


BOOTSTRAP_JAVASCRIPT = r"""'use strict';
const status = document.getElementById('status');
const button = document.getElementById('enroll');
function b64urlToBytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function bytesToB64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function tokenFromFragment() {
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get('token') || '';
  history.replaceState(null, '', location.pathname);
  if (!token || /\s/.test(token)) throw new Error('Missing bootstrap token in URL fragment.');
  return token;
}
let bootstrapToken;
try { bootstrapToken = tokenFromFragment(); } catch (error) { status.textContent = error.message; button.disabled = true; }
async function request(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {'Authorization': `Bearer ${bootstrapToken}`, 'Content-Type': 'application/json', 'Accept': 'application/json'},
    body: body === undefined ? '{}' : JSON.stringify(body),
    cache: 'no-store',
    credentials: 'same-origin',
  });
  if (!response.ok) throw new Error(`Bootstrap rejected (${response.status}).`);
  return response.json();
}
button.addEventListener('click', async () => {
  button.disabled = true;
  try {
    status.textContent = 'Requesting one-time security-key challenge…';
    const optionsEnvelope = await request('/v1/enrollment/options');
    const publicKey = optionsEnvelope.public_key;
    publicKey.challenge = b64urlToBytes(publicKey.challenge);
    publicKey.user.id = b64urlToBytes(publicKey.user.id);
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(item => ({...item, id: b64urlToBytes(item.id)}));
    }
    status.textContent = 'Touch and verify with the dedicated hardware security key…';
    const credential = await navigator.credentials.create({publicKey});
    if (!credential) throw new Error('No credential returned.');
    const response = credential.response;
    const payload = {
      session_id: optionsEnvelope.session_id,
      credential: {
        id: credential.id,
        rawId: bytesToB64url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: credential.getClientExtensionResults(),
        response: {
          clientDataJSON: bytesToB64url(response.clientDataJSON),
          attestationObject: bytesToB64url(response.attestationObject),
          transports: response.getTransports ? response.getTransports() : [],
        },
      },
    };
    const completed = await request('/v1/enrollment/complete', payload);
    status.textContent = `Candidate created: ${completed.candidate_hash}\nAuthority effect: ${completed.authority_effect}`;
  } catch (error) {
    status.textContent = error.message || String(error);
    button.disabled = false;
  }
});
"""


class CompleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=4096)
    credential: dict[str, object]


def create_enrollment_app(
    service: HardwareEnrollmentService,
    authenticator: DigestBootstrapAuthenticator,
) -> FastAPI:
    app = FastAPI(
        title="Pulpo Hardware Credential Bootstrap",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def require_bootstrap(request: FastAPIRequest) -> str:
        try:
            return authenticator.authenticate(request)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail="bootstrap authentication required") from exc

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "authority_effect": "none"}

    @app.get("/bootstrap", response_class=HTMLResponse)
    def bootstrap_page() -> HTMLResponse:
        return HTMLResponse(BOOTSTRAP_PAGE, headers=BOOTSTRAP_SECURITY_HEADERS)

    @app.get("/bootstrap.js", response_class=Response)
    def bootstrap_javascript() -> Response:
        return Response(
            BOOTSTRAP_JAVASCRIPT,
            media_type="application/javascript",
            headers=BOOTSTRAP_SECURITY_HEADERS,
        )

    @app.post("/v1/enrollment/options")
    def options(request: FastAPIRequest) -> dict[str, object]:
        require_bootstrap(request)
        try:
            return service.begin()
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="enrollment unavailable") from exc

    @app.post("/v1/enrollment/complete")
    def complete(body: CompleteBody, request: FastAPIRequest) -> dict[str, object]:
        require_bootstrap(request)
        try:
            return service.complete(body.session_id, body.credential)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="hardware enrollment rejected") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="enrollment unavailable") from exc

    return app


def build_enrollment_app(environment: Mapping[str, str] | None = None) -> FastAPI:
    env = os.environ if environment is None else environment
    origin = _require_text(env.get("PULPO_ENROLLMENT_ORIGIN", ""), "PULPO_ENROLLMENT_ORIGIN")
    rp_id = _require_text(env.get("PULPO_ENROLLMENT_RP_ID", ""), "PULPO_ENROLLMENT_RP_ID")
    candidate_path = Path(
        _require_text(env.get("PULPO_ENROLLMENT_CANDIDATE_PATH", ""), "PULPO_ENROLLMENT_CANDIDATE_PATH")
    )
    try:
        ttl = int(_require_text(env.get("PULPO_ENROLLMENT_TTL_SECONDS", "300"), "PULPO_ENROLLMENT_TTL_SECONDS"))
    except ValueError as exc:
        raise ValueError("PULPO_ENROLLMENT_TTL_SECONDS must be an integer") from exc
    role = _require_text(env.get("PULPO_ENROLLMENT_ROLE", "primary"), "PULPO_ENROLLMENT_ROLE")
    token_digest = _require_digest(
        env.get("PULPO_ENROLLMENT_BOOTSTRAP_TOKEN_SHA256", ""),
        "PULPO_ENROLLMENT_BOOTSTRAP_TOKEN_SHA256",
    )
    config = EnrollmentConfig(rp_id, origin, candidate_path, ttl, role)
    return create_enrollment_app(
        HardwareEnrollmentService(config),
        DigestBootstrapAuthenticator(token_digest),
    )

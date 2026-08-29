"""Runnable local acceptance runtime for the independent Pulpo authority.

This module deliberately proves only a *separate-process* authority boundary.
It keeps the signer key, WebAuthn credential material, durable authority state,
and authority evidence outside the hostile worker container. It does not claim
hostile-host protection or replace a future independently managed signer/state
service.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request as FastAPIRequest

from .api import create_app
from .contract import AuthorityTrust
from .core import AuthorityConfig, AuthorityService, CredentialRecord
from .restart_adapters import DirectoryEvidenceSink, SQLiteRestartState
from .webauthn_adapter import PyWebAuthnVerifier


MAX_WORKER_TOKEN_BYTES = 16_000
MAX_LOCAL_TTL_SECONDS = 3_600
CREDENTIAL_SCHEMA = "pulpo.local-authority-credentials.v0"


def _require_text(value: str, name: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty canonical text")
    return value


def _require_digest(value: str, name: str) -> str:
    if (
        len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _required(environment: Mapping[str, str], name: str) -> str:
    return _require_text(environment.get(name, ""), name)


def _absolute_path(environment: Mapping[str, str], name: str) -> Path:
    path = Path(_required(environment, name))
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return path


def _positive_int(environment: Mapping[str, str], name: str, *, maximum: int | None = None) -> int:
    raw = _required(environment, name)
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0 or (maximum is not None and value > maximum):
        raise ValueError(f"{name} is outside the allowed range")
    return value


def _reject_inline_secrets(environment: Mapping[str, str]) -> None:
    forbidden = {
        "PULPO_AUTHORITY_PRIVATE_KEY_HEX",
        "PULPO_AUTHORITY_WORKER_TOKEN",
        "PULPO_AUTHORITY_CREDENTIAL_JSON",
    }
    present = sorted(name for name in forbidden if environment.get(name))
    if present:
        raise ValueError(f"inline authority secrets are prohibited: {', '.join(present)}")


class DigestBearerWorkerAuthenticator:
    """Authenticate worker ingress without storing the raw worker token.

    Possession of this token permits only the already-narrow request/poll HTTP
    surface. It does not grant approval or signing authority.
    """

    def __init__(self, expected_token_sha256: str) -> None:
        self.expected_token_sha256 = _require_digest(
            expected_token_sha256,
            "PULPO_AUTHORITY_WORKER_TOKEN_SHA256",
        )

    def authenticate(self, request: FastAPIRequest) -> str:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise PermissionError("worker bearer token required")
        token = header[7:]
        if (
            not token
            or token != token.strip()
            or any(character.isspace() for character in token)
            or len(token.encode()) > MAX_WORKER_TOKEN_BYTES
        ):
            raise PermissionError("worker bearer token is malformed")
        actual = sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(actual, self.expected_token_sha256):
            raise PermissionError("worker bearer token rejected")
        return f"worker:{actual[:16]}"


class FileEd25519Signer:
    """Local acceptance signer loaded from an authority-only file mount."""

    algorithm = "ed25519"

    def __init__(
        self,
        path: Path,
        *,
        authority_id: str,
        verifier_id: str,
        key_id: str,
        expected_key_fingerprint: str,
    ) -> None:
        if not path.is_file():
            raise RuntimeError("authority signer file is unavailable")
        if path.stat().st_mode & 0o022:
            raise RuntimeError("authority signer file must not be group/world writable")
        encoded = path.read_text(encoding="ascii").strip()
        if (
            len(encoded) != 64
            or encoded != encoded.lower()
            or any(character not in "0123456789abcdef" for character in encoded)
        ):
            raise RuntimeError("authority signer file must contain one raw Ed25519 private key")
        private_bytes = bytes.fromhex(encoded)
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.authority_id = _require_text(authority_id, "authority_id")
        self.verifier_id = _require_text(verifier_id, "verifier_id")
        self.key_id = _require_text(key_id, "key_id")
        self.key_fingerprint = sha256(public_bytes).hexdigest()
        expected = _require_digest(expected_key_fingerprint, "expected_key_fingerprint")
        if not hmac.compare_digest(self.key_fingerprint, expected):
            raise RuntimeError("authority signer does not match the pinned public fingerprint")

    def sign(self, payload: bytes) -> str:
        return self._private_key.sign(payload).hex()


def load_credentials(path: Path) -> tuple[CredentialRecord, ...]:
    if not path.is_file():
        raise RuntimeError("authority credential file is unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("authority credential file is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "credentials"}:
        raise RuntimeError("authority credential file has an unexpected shape")
    if value["schema"] != CREDENTIAL_SCHEMA:
        raise RuntimeError("unsupported authority credential file schema")
    items = value["credentials"]
    if not isinstance(items, list) or not items or len(items) > 16:
        raise RuntimeError("authority credential file must contain 1-16 credentials")

    expected_fields = {
        "credential_id",
        "public_key_hex",
        "sign_count",
        "role",
        "active",
        "hardware_attested",
        "backup_eligible",
    }
    credentials: list[CredentialRecord] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise RuntimeError("authority credential record has an unexpected shape")
        public_key_hex = item["public_key_hex"]
        if (
            not isinstance(public_key_hex, str)
            or not public_key_hex
            or len(public_key_hex) % 2
            or any(character not in "0123456789abcdef" for character in public_key_hex)
        ):
            raise RuntimeError("authority credential public key is invalid")
        if isinstance(item["sign_count"], bool) or not isinstance(item["sign_count"], int):
            raise RuntimeError("authority credential sign_count is invalid")
        for field in ("active", "hardware_attested", "backup_eligible"):
            if not isinstance(item[field], bool):
                raise RuntimeError(f"authority credential {field} is invalid")
        credential = CredentialRecord(
            credential_id=item["credential_id"],
            public_key=bytes.fromhex(public_key_hex),
            sign_count=item["sign_count"],
            role=item["role"],
            active=item["active"],
            hardware_attested=item["hardware_attested"],
            backup_eligible=item["backup_eligible"],
        )
        if credential.credential_id in seen:
            raise RuntimeError("duplicate authority credential id")
        seen.add(credential.credential_id)
        credentials.append(credential)

    if not any(
        item.role == "primary"
        and item.active
        and item.hardware_attested
        and not item.backup_eligible
        for item in credentials
    ):
        raise RuntimeError("authority runtime requires one active hardware-bound primary credential")
    return tuple(credentials)


@dataclass(frozen=True)
class LocalAuthorityRuntime:
    app: FastAPI
    service: AuthorityService
    signer: FileEd25519Signer
    state: SQLiteRestartState
    evidence: DirectoryEvidenceSink
    tls_cert_path: Path
    tls_key_path: Path
    port: int


def build_runtime(environment: Mapping[str, str] | None = None) -> LocalAuthorityRuntime:
    env = os.environ if environment is None else environment
    _reject_inline_secrets(env)

    origin = _required(env, "PULPO_AUTHORITY_ORIGIN")
    rp_id = _required(env, "PULPO_AUTHORITY_RP_ID")
    port = _positive_int(env, "PULPO_AUTHORITY_PORT", maximum=65_535)
    parsed = urlparse(origin)
    origin_port = parsed.port or (443 if parsed.scheme == "https" else None)
    if parsed.scheme != "https" or origin_port != port:
        raise ValueError("PULPO_AUTHORITY_ORIGIN must be HTTPS on PULPO_AUTHORITY_PORT")

    signer = FileEd25519Signer(
        _absolute_path(env, "PULPO_AUTHORITY_PRIVATE_KEY_PATH"),
        authority_id=_required(env, "PULPO_AUTHORITY_ID"),
        verifier_id=_required(env, "PULPO_AUTHORITY_VERIFIER_ID"),
        key_id=_required(env, "PULPO_AUTHORITY_KEY_ID"),
        expected_key_fingerprint=_required(env, "PULPO_AUTHORITY_EXPECTED_KEY_FINGERPRINT"),
    )
    max_ttl_seconds = _positive_int(
        env,
        "PULPO_AUTHORITY_MAX_TTL_SECONDS",
        maximum=MAX_LOCAL_TTL_SECONDS,
    )
    trust = AuthorityTrust(
        authority_id=signer.authority_id,
        verifier_id=signer.verifier_id,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        key_fingerprint=signer.key_fingerprint,
        deployment_id=_required(env, "PULPO_AUTHORITY_DEPLOYMENT_ID"),
        max_approval_ttl_ns=max_ttl_seconds * 1_000_000_000,
    )
    credentials = load_credentials(_absolute_path(env, "PULPO_AUTHORITY_CREDENTIALS_PATH"))
    state = SQLiteRestartState(
        _absolute_path(env, "PULPO_AUTHORITY_STATE_PATH"),
        credentials,
    )
    evidence = DirectoryEvidenceSink(_absolute_path(env, "PULPO_AUTHORITY_EVIDENCE_DIR"))
    service = AuthorityService(
        AuthorityConfig(trust, rp_id, origin),
        state,
        PyWebAuthnVerifier(),
        signer,
        evidence,
    )
    authenticator = DigestBearerWorkerAuthenticator(
        _required(env, "PULPO_AUTHORITY_WORKER_TOKEN_SHA256")
    )
    app = create_app(service, worker_authenticator=authenticator)

    tls_cert_path = _absolute_path(env, "PULPO_AUTHORITY_TLS_CERT_PATH")
    tls_key_path = _absolute_path(env, "PULPO_AUTHORITY_TLS_KEY_PATH")
    if not tls_cert_path.is_file() or not tls_key_path.is_file():
        raise RuntimeError("authority TLS certificate or key is unavailable")

    return LocalAuthorityRuntime(
        app=app,
        service=service,
        signer=signer,
        state=state,
        evidence=evidence,
        tls_cert_path=tls_cert_path,
        tls_key_path=tls_key_path,
        port=port,
    )


def main() -> None:
    import uvicorn

    runtime = build_runtime()
    uvicorn.run(
        runtime.app,
        host="0.0.0.0",
        port=runtime.port,
        workers=1,
        access_log=False,
        server_header=False,
        ssl_certfile=str(runtime.tls_cert_path),
        ssl_keyfile=str(runtime.tls_key_path),
    )


if __name__ == "__main__":
    main()

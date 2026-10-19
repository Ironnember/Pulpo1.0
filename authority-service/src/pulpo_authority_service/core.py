"""Fail-closed state machine for the independent authority trust domain."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
import secrets
import threading
import time
from typing import Callable, Protocol
from urllib.parse import urlparse

from .contract import ApprovalEnvelope, AuthorityTrust


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _require_digest(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class AuthorityConfig:
    trust: AuthorityTrust
    rp_id: str
    origin: str
    approval_path_prefix: str = "/human/approval/"

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
        if not self.approval_path_prefix.startswith("/") or not self.approval_path_prefix.endswith("/"):
            raise ValueError("approval_path_prefix must be an absolute directory path")


@dataclass(frozen=True)
class ApprovalRequest:
    principal: str
    action: str
    resource: str
    cost: int
    session_id: str
    intent_hash: str
    policy_hash: str
    deployment_id: str
    requested_ttl_ns: int
    schema: str = "pulpo.authority-request.v1"

    def __post_init__(self) -> None:
        for value, field in (
            (self.principal, "principal"),
            (self.action, "action"),
            (self.resource, "resource"),
            (self.session_id, "session_id"),
            (self.deployment_id, "deployment_id"),
        ):
            _require_text(value, field)
            if len(value) > 4_096:
                raise ValueError(f"{field} exceeds the authority request limit")
        _require_digest(self.intent_hash, "intent_hash")
        _require_digest(self.policy_hash, "policy_hash")
        if isinstance(self.cost, bool) or not isinstance(self.cost, int) or self.cost < 0:
            raise ValueError("cost must be a non-negative integer")
        if (
            isinstance(self.requested_ttl_ns, bool)
            or not isinstance(self.requested_ttl_ns, int)
            or self.requested_ttl_ns <= 0
        ):
            raise ValueError("requested_ttl_ns must be positive")
        if self.schema != "pulpo.authority-request.v1":
            raise ValueError("unsupported authority request schema")

    @property
    def recomputed_intent_hash(self) -> str:
        intent = {
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "cost": self.cost,
            "session_id": self.session_id,
        }
        return sha256(_canonical(intent)).hexdigest()


@dataclass(frozen=True)
class CredentialRecord:
    credential_id: str
    public_key: bytes
    sign_count: int
    role: str
    active: bool
    hardware_attested: bool
    backup_eligible: bool

    def __post_init__(self) -> None:
        _require_text(self.credential_id, "credential_id")
        if not self.public_key:
            raise ValueError("credential public_key is required")
        if self.role not in {"primary", "recovery"}:
            raise ValueError("unsupported credential role")
        if self.sign_count < 0:
            raise ValueError("sign_count must be non-negative")


@dataclass(frozen=True)
class CeremonyResult:
    credential_id: str
    user_present: bool
    user_verified: bool
    backup_eligible: bool
    backed_up: bool
    new_sign_count: int


class WebAuthnVerifier(Protocol):
    def verify(
        self,
        assertion: str,
        *,
        expected_challenge: bytes,
        expected_origin: str,
        expected_rp_id: str,
        credential: CredentialRecord,
    ) -> CeremonyResult: ...


class EnvelopeSigner(Protocol):
    authority_id: str
    verifier_id: str
    key_id: str
    algorithm: str
    key_fingerprint: str

    def sign(self, payload: bytes) -> str: ...


class EvidenceSink(Protocol):
    def append(self, bundle: dict[str, object]) -> str: ...


@dataclass
class RequestState:
    request_id: str
    request: ApprovalRequest
    unsigned_envelope: ApprovalEnvelope
    challenge: bytes
    status: str = "pending"
    envelope: ApprovalEnvelope | None = None
    reason: str | None = None
    evidence_hash: str | None = None
    evidence_bundle: dict[str, object] | None = None


class InMemoryState:
    """Test/reference state. Production must replace this with protected durable state."""

    def __init__(self, credentials: tuple[CredentialRecord, ...]) -> None:
        self.requests: dict[str, RequestState] = {}
        self.credentials = {item.credential_id: item for item in credentials}
        self.sequence = 0
        self.last_time_ns = 0
        self.lock = threading.RLock()


class InMemoryEvidenceSink:
    """Acceptance-proof sink. Production must use independently append-only storage."""

    def __init__(self) -> None:
        self.bundles: list[dict[str, object]] = []
        self.lock = threading.RLock()

    def append(self, bundle: dict[str, object]) -> str:
        digest = sha256(_canonical(bundle)).hexdigest()
        with self.lock:
            for existing in self.bundles:
                if existing["hash"] == digest:
                    if existing["bundle"] != bundle:
                        raise RuntimeError("existing in-memory evidence diverged")
                    return digest
            self.bundles.append({"hash": digest, "bundle": bundle})
        return digest


class AuthorityService:
    def __init__(
        self,
        config: AuthorityConfig,
        state: InMemoryState,
        verifier: WebAuthnVerifier,
        signer: EnvelopeSigner,
        evidence: EvidenceSink,
        *,
        clock: Callable[[], int] | None = None,
        random_token: Callable[[int], str] | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.verifier = verifier
        self.signer = signer
        self.evidence = evidence
        self._clock = clock or time.time_ns
        self._random_token = random_token or secrets.token_hex
        signer_trust = (
            signer.authority_id,
            signer.verifier_id,
            signer.key_id,
            signer.algorithm,
            signer.key_fingerprint,
        )
        configured_trust = (
            config.trust.authority_id,
            config.trust.verifier_id,
            config.trust.key_id,
            config.trust.algorithm,
            config.trust.key_fingerprint,
        )
        if signer_trust != configured_trust:
            raise ValueError("signer does not match pinned authority trust")

    def request_approval(self, request: ApprovalRequest) -> tuple[str, str]:
        if request.deployment_id != self.config.trust.deployment_id:
            raise ValueError("deployment mismatch")
        if request.intent_hash != request.recomputed_intent_hash:
            raise ValueError("intent hash does not match displayed intent")
        if request.requested_ttl_ns > self.config.trust.max_approval_ttl_ns:
            raise ValueError("requested approval TTL exceeds policy")
        with self.state.lock:
            now = self._trusted_now()
            request_id = f"request:{self._random_token(16)}"
            approval_id = f"approval:{self._random_token(16)}"
            nonce = f"nonce:{self._random_token(16)}"
            unsigned = ApprovalEnvelope(
                approval_id=approval_id,
                authority_id=self.config.trust.authority_id,
                verifier_id=self.config.trust.verifier_id,
                key_id=self.config.trust.key_id,
                deployment_id=self.config.trust.deployment_id,
                trust_hash=self.config.trust.trust_hash,
                session_id=request.session_id,
                principal=request.principal,
                intent_hash=request.intent_hash,
                policy_hash=request.policy_hash,
                nonce=nonce,
                issued_at_ns=now,
                expires_at_ns=now + request.requested_ttl_ns,
                signature="",
            )
            challenge = sha256(
                _canonical(
                    {
                        "schema": "pulpo.webauthn-challenge.v1",
                        "purpose": "approve-exact-pulpo-envelope",
                        "request_id": request_id,
                        "signing_payload_hash": unsigned.signing_payload_hash,
                        "expires_at_ns": unsigned.expires_at_ns,
                        "service_nonce": nonce,
                    }
                )
            ).digest()
            if request_id in self.state.requests:
                raise RuntimeError("request identifier collision")
            self.state.requests[request_id] = RequestState(request_id, request, unsigned, challenge)
        approval_url = f"{self.config.origin}{self.config.approval_path_prefix}{request_id}"
        return request_id, approval_url

    def display(self, request_id: str) -> dict[str, object]:
        with self.state.lock:
            record = self._record(request_id)
            self._expire(record)
            request = record.request
            return {
                "request_id": record.request_id,
                "status": record.status,
                "principal": request.principal,
                "action": request.action,
                "resource": request.resource,
                "cost": request.cost,
                "session_id": request.session_id,
                "intent_hash": request.intent_hash,
                "policy_hash": request.policy_hash,
                "deployment_id": request.deployment_id,
                "expires_at_ns": record.unsigned_envelope.expires_at_ns,
            }

    def challenge(self, request_id: str) -> bytes:
        with self.state.lock:
            record = self._record(request_id)
            self._expire(record)
            if record.status != "pending":
                raise RuntimeError("approval request is not pending")
            return record.challenge

    def approve(self, request_id: str, credential_id: str, assertion: str) -> ApprovalEnvelope:
        with self.state.lock:
            record = self._record(request_id)
            self._expire(record)
            if record.status == "evidence_pending":
                pass
            elif record.status != "pending":
                raise RuntimeError("approval request is not pending")
            else:
                credential = self.state.credentials.get(credential_id)
                if credential is None or not credential.active:
                    raise PermissionError("credential unavailable")
                if credential.role != "primary":
                    raise PermissionError("recovery credential cannot approve")
                if not credential.hardware_attested or credential.backup_eligible:
                    raise PermissionError("credential violates hardware policy")
                try:
                    result = self.verifier.verify(
                        assertion,
                        expected_challenge=record.challenge,
                        expected_origin=self.config.origin,
                        expected_rp_id=self.config.rp_id,
                        credential=credential,
                    )
                except Exception as exc:
                    raise PermissionError("WebAuthn assertion rejected") from exc
                if result.credential_id != credential_id:
                    raise PermissionError("credential mismatch")
                if not result.user_present or not result.user_verified:
                    raise PermissionError("fresh user verification required")
                if result.backup_eligible or result.backed_up:
                    raise PermissionError("backup-eligible credentials are prohibited")
                if result.new_sign_count < credential.sign_count:
                    raise PermissionError("authenticator counter rollback")
                signature = self.signer.sign(record.unsigned_envelope.signing_bytes())
                if (
                    len(signature) != 128
                    or signature != signature.lower()
                    or any(character not in "0123456789abcdef" for character in signature)
                ):
                    raise RuntimeError("signer returned an invalid Ed25519 signature")
                envelope = replace(record.unsigned_envelope, signature=signature)
                sequence = self.state.sequence + 1
                bundle = {
                    "schema": "pulpo.authority-evidence.v1",
                    "sequence": sequence,
                    "request": asdict(record.request),
                    "request_id": request_id,
                    "challenge_hash": sha256(record.challenge).hexdigest(),
                    "credential_id_hash": sha256(credential_id.encode()).hexdigest(),
                    "assertion": assertion,
                    "envelope": asdict(envelope),
                }

                # Persist the completed human verification, exact signed
                # envelope, sequence reservation, authenticator counter, and
                # exact evidence payload before touching the independent
                # evidence store. If evidence storage or the process fails next,
                # restart can resume from this exact payload without obtaining a
                # second WebAuthn assertion or minting a second sequence.
                self.state.sequence = sequence
                self.state.credentials[credential_id] = replace(
                    credential,
                    sign_count=result.new_sign_count,
                )
                record.status = "evidence_pending"
                record.envelope = envelope
                record.evidence_bundle = bundle
                record.evidence_hash = None

        # Never release the envelope while evidence is still unresolved. An
        # evidence-pending retry ignores any newly supplied assertion because
        # the exact verified assertion and envelope are already durable.
        return self._complete_evidence(request_id)

    def poll(self, request_id: str) -> dict[str, object]:
        with self.state.lock:
            record = self._record(request_id)
            self._expire(record)
            status = record.status

        if status == "evidence_pending":
            self._complete_evidence(request_id)

        with self.state.lock:
            record = self._record(request_id)
            result: dict[str, object] = {"status": record.status}
            if record.status == "approved" and record.envelope is not None:
                result["envelope"] = asdict(record.envelope)
            elif record.status in {"denied", "expired"}:
                result["reason"] = record.reason or record.status
            return result

    def _complete_evidence(self, request_id: str) -> ApprovalEnvelope:
        with self.state.lock:
            record = self._record(request_id)
            if record.status == "approved":
                if record.envelope is None or record.evidence_hash is None:
                    raise RuntimeError("approved authority state is incomplete")
                return record.envelope
            if (
                record.status != "evidence_pending"
                or record.envelope is None
                or record.evidence_bundle is None
            ):
                raise RuntimeError("approval evidence is not resumable")
            envelope = record.envelope
            bundle = json.loads(_canonical(record.evidence_bundle))

        try:
            evidence_hash = self.evidence.append(bundle)
        except Exception as exc:
            raise RuntimeError("authority evidence unavailable") from exc
        _require_digest(evidence_hash, "evidence_hash")

        with self.state.lock:
            record = self._record(request_id)
            if record.status == "approved":
                if record.envelope != envelope or record.evidence_hash != evidence_hash:
                    raise RuntimeError("approved authority evidence diverged")
                return envelope
            if (
                record.status != "evidence_pending"
                or record.envelope != envelope
                or record.evidence_bundle != bundle
            ):
                raise RuntimeError("authority evidence completion raced with state change")
            record.evidence_hash = evidence_hash
            record.status = "approved"
            record.evidence_bundle = None
            return envelope

    def _record(self, request_id: str) -> RequestState:
        record = self.state.requests.get(request_id)
        if record is None:
            raise KeyError("unknown approval request")
        return record

    def _expire(self, record: RequestState) -> None:
        if record.status == "pending" and self._trusted_now() >= record.unsigned_envelope.expires_at_ns:
            record.status = "expired"
            record.reason = "expired"

    def _trusted_now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RuntimeError("trusted time unavailable")
        with self.state.lock:
            if value < self.state.last_time_ns:
                raise RuntimeError("trusted time rollback")
            self.state.last_time_ns = value
        return value

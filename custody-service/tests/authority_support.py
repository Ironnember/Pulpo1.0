# custody-service/tests/authority_support.py
from dataclasses import dataclass, is_dataclass, asdict
import hmac
import hashlib
import json
import time
from typing import Dict, Any, Optional

# JSON-friendly defaults used in tests
DEFAULT_TEST_KEY = "pulpo-test-key"
DEFAULT_ALGORITHM = "hmac-sha256-test-only"
DEFAULT_TYPE = "hmac"
DEFAULT_AUTHORITY_ID = "authority:test-owner"
DEFAULT_VERIFIER_ID = "verifier:test-only"
DEFAULT_KEY_ID = "key:test-only:v1"
DEFAULT_KEY_FINGERPRINT = "c0d4282378c959913c7f62a748798a931c7f45ac18527fb1a0b0ca5ec939cf35"
DEFAULT_DEPLOYMENT_ID = "deployment:test"
DEFAULT_MAX_TTL_NS = 10_000
DEFAULT_SCHEMA = "pulpo.authority-trust.v1"


@dataclass
class AuthorityTrust:
    authority_id: str
    verifier_id: str
    key_id: str
    algorithm: str
    key_fingerprint: str
    deployment_id: str
    max_approval_ttl_ns: int
    schema: str


@dataclass
class Approval:
    authority_id: str
    verifier_id: str
    key_id: str
    deployment_id: str
    trust_hash: str
    session_id: Optional[str]
    principal: Optional[str]
    intent_hash: Optional[str]
    policy_hash: Optional[str]
    issued_at_ns: int
    expires_at_ns: int


@dataclass
class ApprovalEnvelope:
    """
    Dataclass shape expected by tests. ApprovalEnvelope.payload is an Approval
    dataclass so asdict(envelope) produces the full approval mapping.
    """
    payload: Approval
    signature: str
    now_ns: Optional[int] = None
    approval_id: Optional[str] = None
    nonce: Optional[str] = None


@dataclass
class HmacTestVerifier:
    # HMAC signing key (kept JSON-friendly)
    key: str = DEFAULT_TEST_KEY

    # Canonical authority-trust fields (match AuthorityTrust)
    authority_id: str = DEFAULT_AUTHORITY_ID
    verifier_id: str = DEFAULT_VERIFIER_ID
    key_id: str = DEFAULT_KEY_ID
    algorithm: str = DEFAULT_ALGORITHM
    key_fingerprint: str = DEFAULT_KEY_FINGERPRINT
    deployment_id: str = DEFAULT_DEPLOYMENT_ID
    max_approval_ttl_ns: int = DEFAULT_MAX_TTL_NS
    schema: str = DEFAULT_SCHEMA

    def sign(self, payload: Dict[str, Any]) -> str:
        """
        Canonicalize payloads before signing:
        - If payload is a dataclass, convert to dict via asdict (recursively).
        - Otherwise assume it's JSON-serializable already.
        """
        payload_to_sign = payload
        try:
            if is_dataclass(payload):
                payload_to_sign = asdict(payload)
        except Exception:
            payload_to_sign = payload

        body = json.dumps(payload_to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.key.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


# --- helper functions that reference HmacTestVerifier and dataclasses ---

def _compute_trust_hash_for(verifier: HmacTestVerifier) -> str:
    """
    Compute a canonical SHA256 hex digest of the AuthorityTrust returned by
    trust_for(verifier). This mirrors the kernel's canonicalization.
    """
    trust = trust_for(verifier)
    canonical = json.dumps(asdict(trust), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _maybe_policy_hash_from_kernel(kernel_like) -> Optional[str]:
    # Try common places the kernel stores the policy hash
    if kernel_like is None:
        return None
    ph = getattr(kernel_like, "_policy_hash", None)
    if ph:
        return ph
    compute = getattr(kernel_like, "_compute_policy_hash", None)
    if callable(compute):
        try:
            return compute()
        except Exception:
            return None
    return getattr(kernel_like, "policy_hash", None)


def signed_envelope(signing_kernel_or_verifier, payload: Any, verifier=None, *, now_ns: int | None = None, approval_id: str | None = None, nonce: str | None = None) -> ApprovalEnvelope:
    """
    Create an ApprovalEnvelope whose payload is an Approval dataclass.

    - signing_kernel_or_verifier: either the signing kernel (preferred) or the verifier.
    - payload: the intent dataclass or dict (we canonicalize dataclasses for signing).
    - verifier: optional explicit verifier; if omitted, the first arg is treated as verifier.
    - now_ns: issued_at timestamp to include in the approval.
    """
    # Resolve verifier and kernel
    kernel_like = None
    if verifier is None:
        # caller passed (verifier, payload)
        verifier = signing_kernel_or_verifier
    else:
        # caller passed (signing_kernel, payload, verifier=verifier)
        kernel_like = signing_kernel_or_verifier

    # canonicalize payload for signing (dataclass -> dict)
    payload_to_sign = payload
    try:
        if is_dataclass(payload):
            payload_to_sign = asdict(payload)
    except Exception:
        payload_to_sign = payload

    # compute signature
    sign_fn = getattr(verifier, "sign", None)
    if not callable(sign_fn):
        raise TypeError("verifier does not provide a sign(payload) method")
    signature = sign_fn(payload_to_sign)

    # compute issued/expires
    issued = int(now_ns) if now_ns is not None else int(time.time_ns())
    expires = issued + int(getattr(verifier, "max_approval_ttl_ns", 0) or 0)

    # extract session_id and principal from payload (works for dataclass or dict)
    session_id = None
    principal = None
    try:
        if is_dataclass(payload):
            pmap = asdict(payload)
            session_id = pmap.get("session_id")
            principal = pmap.get("principal")
        elif isinstance(payload, dict):
            session_id = payload.get("session_id")
            principal = payload.get("principal")
    except Exception:
        pass

    # compute intent_hash if kernel-like object provides it
    intent_hash = None
    if kernel_like is not None:
        ih = getattr(kernel_like, "intent_hash", None)
        if callable(ih):
            try:
                intent_hash = ih(payload)
            except Exception:
                intent_hash = None

    # compute policy_hash if available on kernel-like
    policy_hash = _maybe_policy_hash_from_kernel(kernel_like)

    # compute trust_hash from verifier
    trust_hash = _compute_trust_hash_for(verifier)

    approval = Approval(
        authority_id=getattr(verifier, "authority_id", ""),
        verifier_id=getattr(verifier, "verifier_id", ""),
        key_id=getattr(verifier, "key_id", ""),
        deployment_id=getattr(verifier, "deployment_id", ""),
        trust_hash=trust_hash,
        session_id=session_id,
        principal=principal,
        intent_hash=intent_hash,
        policy_hash=policy_hash,
        issued_at_ns=issued,
        expires_at_ns=expires,
    )

    return ApprovalEnvelope(
        payload=approval,
        signature=signature,
        now_ns=now_ns,
        approval_id=approval_id,
        nonce=nonce,
    )


def trust_for(verifier: HmacTestVerifier) -> AuthorityTrust:
    """
    Return an AuthorityTrust dataclass instance constructed from the verifier's
    canonical fields so dataclasses.asdict(...) produces the same mapping.
    """
    return AuthorityTrust(
        authority_id=getattr(verifier, "authority_id", ""),
        verifier_id=getattr(verifier, "verifier_id", ""),
        key_id=getattr(verifier, "key_id", ""),
        algorithm=getattr(verifier, "algorithm", ""),
        key_fingerprint=getattr(verifier, "key_fingerprint", ""),
        deployment_id=getattr(verifier, "deployment_id", ""),
        max_approval_ttl_ns=int(getattr(verifier, "max_approval_ttl_ns", 0) or 0),
        schema=getattr(verifier, "schema", ""),
    )

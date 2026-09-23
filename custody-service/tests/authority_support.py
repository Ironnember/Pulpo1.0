from dataclasses import dataclass, is_dataclass, asdict
import hashlib
import time
from typing import Dict, Any, Optional

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
    # direct attribute
    ph = getattr(kernel_like, "_policy_hash", None)
    if ph:
        return ph
    # method to compute
    compute = getattr(kernel_like, "_compute_policy_hash", None)
    if callable(compute):
        try:
            return compute()
        except Exception:
            return None
    # fallback: attribute named policy_hash
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

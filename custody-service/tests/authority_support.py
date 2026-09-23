# custody-service/tests/authority_support.py
from dataclasses import dataclass, is_dataclass, asdict
import hmac
import hashlib
import json
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
class ApprovalEnvelope:
    """
    Dataclass shape expected by tests. Using dataclass ensures asdict(envelope)
    will recursively convert nested dataclasses (like Intent) to plain dicts.
    """
    payload: Any
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


def signed_envelope(signing_kernel_or_verifier, payload: Dict[str, Any], verifier=None, *, now_ns: int | None = None, approval_id: str | None = None, nonce: str | None = None) -> ApprovalEnvelope:
    """
    Backwards-compatible helper used by tests.

    Accepts either:
      - (verifier, payload)  OR
      - (signing_kernel, payload, verifier=verifier)

    Returns an ApprovalEnvelope dataclass so tests can call asdict(envelope).
    """
    if verifier is None:
        verifier = signing_kernel_or_verifier

    sign_fn = getattr(verifier, "sign", None)
    if not callable(sign_fn):
        raise TypeError("verifier does not provide a sign(payload) method")

    signature = sign_fn(payload)

    return ApprovalEnvelope(
        payload=payload,
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
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        deployment_id=verifier.deployment_id,
        max_approval_ttl_ns=verifier.max_approval_ttl_ns,
        schema=verifier.schema,
    )

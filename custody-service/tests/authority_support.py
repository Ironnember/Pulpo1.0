# custody-service/tests/authority_support.py
from dataclasses import dataclass
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
class HmacTestVerifier:
    """
    Dataclass verifier used by tests. It intentionally exposes the same
    canonical fields the kernel expects for authority trust so that
    dataclasses.asdict(...) produces identical mappings.
    """
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
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hmac.new(self.key.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def signed_envelope(payload: Dict[str, Any], key: Optional[str] = None) -> Dict[str, Any]:
    verifier = HmacTestVerifier(key if key is not None else DEFAULT_TEST_KEY)
    sig = verifier.sign(payload)
    return {"payload": payload, "signature": sig}


def trust_for(verifier: HmacTestVerifier) -> AuthorityTrust:
    """
    Return an AuthorityTrust dataclass instance that matches the canonical
    shape the kernel expects when it calls dataclasses.asdict(...) on the
    pinned authority trust. Use the verifier's canonical fields so the
    pinned trust and the approval verifier canonicalize identically.
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

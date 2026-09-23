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
    Dataclass verifier used by tests. Storing fields as strings so
    dataclasses.asdict(...) and json canonicalization succeed.
    """
    key: str = DEFAULT_TEST_KEY
    algorithm: str = DEFAULT_ALGORITHM
    type: str = DEFAULT_TYPE

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
    pinned authority trust. Use stable test-only values so comparisons succeed.
    """
    return AuthorityTrust(
        authority_id=DEFAULT_AUTHORITY_ID,
        verifier_id=DEFAULT_VERIFIER_ID,
        key_id=DEFAULT_KEY_ID,
        algorithm=verifier.algorithm or DEFAULT_ALGORITHM,
        key_fingerprint=DEFAULT_KEY_FINGERPRINT,
        deployment_id=DEFAULT_DEPLOYMENT_ID,
        max_approval_ttl_ns=DEFAULT_MAX_TTL_NS,
        schema=DEFAULT_SCHEMA,
    )

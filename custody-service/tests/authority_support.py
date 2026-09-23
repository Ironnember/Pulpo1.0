# custody-service/tests/authority_support.py
from dataclasses import dataclass, asdict
import hmac
import hashlib
import json
from typing import Dict, Any, Optional

# JSON-friendly defaults
DEFAULT_TEST_KEY = "pulpo-test-key"
DEFAULT_ALGORITHM = "hmac-sha256"
DEFAULT_TYPE = "hmac"

@dataclass
class HmacTestVerifier:
    """
    Dataclass verifier used by tests. Stores JSON-friendly fields so
    dataclasses.asdict(...) produces the canonical mapping the kernel expects.
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

def trust_for(verifier: HmacTestVerifier):
    """
    Return the canonical mapping (plain dict) representing the authority trust.
    Using dataclasses.asdict ensures the kernel sees the same canonical shape
    for the pinned trust as it does for the approval verifier.
    """
    return asdict(verifier)

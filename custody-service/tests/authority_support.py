# custody-service/tests/authority_support.py
from dataclasses import dataclass
import hmac
import hashlib
import json
from typing import Dict, Any, Optional

# Keep the stored key as a JSON-friendly string; encode when signing.
DEFAULT_TEST_KEY = "pulpo-test-key"

@dataclass
class HmacTestVerifier:
    """
    Minimal dataclass test verifier so dataclasses.asdict() works in tests.
    Stores key as a string so JSON serialization succeeds.
    """
    key: str = DEFAULT_TEST_KEY

    def sign(self, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hmac.new(self.key.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def signed_envelope(payload: Dict[str, Any], key: Optional[str] = None) -> Dict[str, Any]:
    verifier = HmacTestVerifier(key if key is not None else DEFAULT_TEST_KEY)
    sig = verifier.sign(payload)
    return {"payload": payload, "signature": sig}


def trust_for(verifier: HmacTestVerifier) -> HmacTestVerifier:
    """
    Return the verifier instance (keeps API shape used by tests).
    The important part is that the returned object is a dataclass instance.
    """
    return verifier

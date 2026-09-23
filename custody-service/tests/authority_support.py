# custody-service/tests/authority_support.py
import hmac
import hashlib
import json
from typing import Dict, Any

class HmacTestVerifier:
    def __init__(self, key: bytes):
        self.key = key

    def sign(self, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hmac.new(self.key, body, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)

def signed_envelope(payload: Dict[str, Any], key: bytes) -> Dict[str, Any]:
    verifier = HmacTestVerifier(key)
    sig = verifier.sign(payload)
    return {"payload": payload, "signature": sig}

def trust_for(key: bytes) -> HmacTestVerifier:
    return HmacTestVerifier(key)

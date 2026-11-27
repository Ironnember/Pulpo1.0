"""Test doubles for presenter binding (Phase 3, Item 4B).

``HmacPresenterVerifier`` is the presenter-side analogue of
``tests.authority_support.HmacTestVerifier``: a same-process HMAC
double standing in for a presenter's real signing key (production
presenters sign with their own asymmetric keys and the kernel holds
a verification-only adapter). It is a test double, never a
production authority.
"""

from __future__ import annotations

from hashlib import sha256
import hmac

from pulpo import GovernanceKernel, Intent


class HmacPresenterVerifier:
    """Signs and verifies presenter proofs under one HMAC secret."""

    def __init__(self, secret: bytes):
        self._secret = secret

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        if not isinstance(signature, str):
            return False
        return hmac.compare_digest(self.sign(payload), signature)


def proof_for(
    kernel: GovernanceKernel,
    verifier: HmacPresenterVerifier,
    permit: str,
    intent: Intent,
    presenter: str,
) -> str:
    """The proof the named presenter would present for this consume."""

    payload = GovernanceKernel.presenter_proof_payload(
        permit, kernel.intent_hash(intent), presenter
    )
    return verifier.sign(payload)

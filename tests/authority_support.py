"""Test-only approval signer material; never import this module at runtime."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac

from pulpo import ApprovalEnvelope, AuthorityTrust


class HmacTestVerifier:
    """Same-process test double, not evidence of independent authority."""

    authority_id = "authority:test-owner"
    verifier_id = "verifier:test-only"
    key_id = "key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"pulpo-test-verifier-key").hexdigest()

    def __init__(self, secret=b"external-test-authority"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def trust_for(
    verifier,
    *,
    deployment_id="deployment:test",
    max_approval_ttl_ns=10_000,
):
    return AuthorityTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        deployment_id=deployment_id,
        max_approval_ttl_ns=max_approval_ttl_ns,
    )


def signed_envelope(
    kernel,
    intent,
    verifier,
    *,
    now_ns,
    ttl_ns=1_000,
    **changes,
):
    trust = kernel.policy.authority_trust
    values = {
        "approval_id": "approval-1",
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "key_id": trust.key_id,
        "deployment_id": trust.deployment_id,
        "trust_hash": trust.trust_hash,
        "session_id": intent.session_id,
        "principal": intent.principal,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "nonce": "approval-nonce-1",
        "issued_at_ns": now_ns,
        "expires_at_ns": now_ns + ttl_ns,
        "signature": "",
    }
    values.update(changes)
    unsigned = ApprovalEnvelope(**values)
    return replace(unsigned, signature=verifier.sign(unsigned.signing_bytes()))

"""Test-only approval signer material; never import this module at runtime."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac

from pulpo import (
    ApprovalEnvelope,
    AuthorityTrust,
    DualControlTrust,
    EnrolledKeyTrust,
    EnvelopeSignature,
    PolicyEnvelope,
    PolicyEnvelopeV2,
    PolicyVeto,
)
from pulpo.kernel import policy_hash_for


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


def signed_policy_envelope(policy, verifier, *, sign=None):
    """Sign a policy's versioned hash with the issuer test key.

    Test-only helper: the signer is the same test double that signs approval
    envelopes (``HmacTestVerifier.sign``), or an explicit ``sign`` callable
    for verifiers that are verification-only (Ed25519/P-256 test fixtures
    hold the private key separately). Production issuers sign with the real
    authority key; this helper proves the verification path, not an issuer.
    """

    trust = policy.authority_trust
    if trust is None:
        raise ValueError("policy envelope requires a pinned authority trust")
    values = {
        "policy_hash": policy_hash_for(policy),
        "version": policy.version,
        "previous_policy_hash": policy.previous_policy_hash,
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "key_id": trust.key_id,
        "deployment_id": trust.deployment_id,
        "trust_hash": trust.trust_hash,
        "signature": "",
    }
    unsigned = PolicyEnvelope(**values)
    signer = sign or getattr(verifier, "sign", None)
    if signer is None:
        raise ValueError("policy envelope signer is required")
    return replace(unsigned, signature=signer(unsigned.signing_bytes()))


class EnrolledHmacTestVerifier:
    """Same-process test double for one enrolled dual-control key.

    Test-only: each instance stands in for one enrolled key (signer, veto,
    or fallback) with its own secret and fingerprint. Production keys are
    human-held hardware keys enrolled at the genesis ceremony; nothing
    here is evidence of a real enrollment.
    """

    authority_id = "authority:test-owner"
    verifier_id = "verifier:test-only"
    algorithm = "hmac-sha256-test-only"

    def __init__(self, key_id, secret):
        self.key_id = key_id
        self.secret = secret
        self.key_fingerprint = hashlib.sha256(b"fingerprint:" + secret).hexdigest()

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)

    def enrolled(self):
        return EnrolledKeyTrust(
            key_id=self.key_id,
            algorithm=self.algorithm,
            key_fingerprint=self.key_fingerprint,
        )


def dual_trust_for(signer_a, signer_b, veto, fallback, *, deployment_id="deployment:test"):
    return DualControlTrust(
        authority_id=signer_a.authority_id,
        verifier_id=signer_a.verifier_id,
        deployment_id=deployment_id,
        signers=(signer_a.enrolled(), signer_b.enrolled()),
        veto=veto.enrolled(),
        fallback=fallback.enrolled(),
    )


def dual_signed_policy_envelope(policy, signer_a, signer_b):
    """Dual-sign a policy's versioned hash with both enrolled signer doubles."""

    trust = policy.dual_control_trust
    if trust is None:
        raise ValueError("policy envelope v2 requires a dual-control trust")
    entries = tuple(
        EnvelopeSignature(key_id=signer.key_id, signature="")
        for signer in (signer_a, signer_b)
    )
    unsigned = PolicyEnvelopeV2(
        policy_hash=policy_hash_for(policy),
        version=policy.version,
        previous_policy_hash=policy.previous_policy_hash,
        authority_id=trust.authority_id,
        verifier_id=trust.verifier_id,
        deployment_id=trust.deployment_id,
        trust_hash=trust.trust_hash,
        signatures=entries,
    )
    payload = unsigned.signing_bytes()
    signed = tuple(
        EnvelopeSignature(key_id=signer.key_id, signature=signer.sign(payload))
        for signer in (signer_a, signer_b)
    )
    return replace(unsigned, signatures=signed)


def signed_policy_veto(trust, actor, kind, *, now_ns, nonce, **fields):
    """Sign a veto-registry record with the acting key's test double."""

    values = {
        "kind": kind,
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "deployment_id": trust.deployment_id,
        "trust_hash": trust.trust_hash,
        "key_id": actor.key_id,
        "nonce": nonce,
        "issued_at_ns": now_ns,
        "signature": "",
    }
    values.update(fields)
    unsigned = PolicyVeto(**values)
    return replace(unsigned, signature=actor.sign(unsigned.signing_bytes()))

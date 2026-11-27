"""Key-derived ceremony verifier fingerprints: separation as a proved property.

The original ceremony contract compared ``key_fingerprint`` metadata: a
ceremony verifier could advertise a distinct fingerprint while its
``verify`` delegated to the approval key, and one key self-attested
(reproduced at 145b623). These tests pin the remediation: the shipped
ceremony verifiers derive the fingerprint from the pinned public key and
expose it read-only, so a verifier built on the approval key reports the
approval fingerprint and policy construction rejects the pairing.

The signer shims below are same-process test doubles standing on the
signing side of the boundary; they are not ceremonies and these tests are
not evidence that any human ceremony occurred.
"""

import importlib.util
import unittest
from hashlib import sha256

CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None

if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256

    from pulpo import (
        AuthorityTrustError,
        Ed25519ApprovalVerifier,
        Ed25519CeremonyVerifier,
        GovernanceKernel,
        Intent,
        P256CeremonyVerifier,
        Policy,
    )
    from tests.authority_support import signed_envelope, trust_for
    from tests.test_ceremony_evidence import (
        NOW,
        SESSION,
        ceremony_trust_for,
        signed_evidence,
    )


class _Ed25519Signer:
    """Test-only signing shim for one Ed25519 private key."""

    def __init__(self, private_key):
        self.__private_key = private_key

    def sign(self, payload):
        return self.__private_key.sign(payload).hex()


class _DelegatingWrapper:
    """Delegates every attribute — including verify and the fingerprint —
    to an inner verifier, with distinct identity labels layered on top."""

    authority_id = "ceremony:test-owner"
    verifier_id = "ceremony-verifier:test-only"
    key_id = "ceremony-key:test-only:v1"

    def __init__(self, inner):
        object.__setattr__(self, "_inner", inner)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "install pulpo[authority]")
class CeremonyKeyDerivationTests(unittest.TestCase):
    def setUp(self):
        self.approval_private = ed25519.Ed25519PrivateKey.generate()
        self.ceremony_private = ed25519.Ed25519PrivateKey.generate()
        self.approval_public = self.approval_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.ceremony_public = self.ceremony_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.approval_verifier = Ed25519ApprovalVerifier(
            authority_id="authority:test-owner",
            verifier_id="verifier:test-only",
            key_id="key:test-only:v1",
            public_key=self.approval_public,
        )
        self.ceremony_verifier = Ed25519CeremonyVerifier(
            authority_id="ceremony:test-owner",
            verifier_id="ceremony-verifier:test-only",
            key_id="ceremony-key:test-only:v1",
            public_key=self.ceremony_public,
        )
        self.approval_signer = _Ed25519Signer(self.approval_private)
        self.ceremony_signer = _Ed25519Signer(self.ceremony_private)
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, SESSION)

    def policy_for(self, ceremony_verifier):
        return Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.approval_verifier),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=ceremony_trust_for(ceremony_verifier),
        )

    def kernel_for(self, ceremony_verifier):
        return GovernanceKernel(
            self.policy_for(ceremony_verifier),
            secret=b"key-derivation-test-secret",
            approval_verifier=self.approval_verifier,
            clock=lambda: NOW,
            ceremony_verifier=ceremony_verifier,
        )

    def test_fingerprint_is_derived_from_the_pinned_public_key(self):
        self.assertEqual(
            sha256(self.ceremony_public).hexdigest(),
            self.ceremony_verifier.key_fingerprint,
        )
        self.assertNotEqual(
            self.approval_verifier.key_fingerprint,
            self.ceremony_verifier.key_fingerprint,
        )

    def test_identity_and_fingerprint_are_read_only(self):
        for field, value in (
            ("key_fingerprint", sha256(b"forged").hexdigest()),
            ("authority_id", "ceremony:forged"),
            ("verifier_id", "ceremony-verifier:forged"),
            ("key_id", "ceremony-key:forged"),
        ):
            with self.assertRaises(AttributeError, msg=field):
                setattr(self.ceremony_verifier, field, value)

    def test_ceremony_verifier_on_the_approval_key_is_rejected_by_policy(self):
        same_key = Ed25519CeremonyVerifier(
            authority_id="ceremony:test-owner",
            verifier_id="ceremony-verifier:test-only",
            key_id="ceremony-key:test-only:v1",
            public_key=self.approval_public,
        )
        self.assertEqual(
            self.approval_verifier.key_fingerprint, same_key.key_fingerprint
        )
        with self.assertRaises(ValueError):
            self.policy_for(same_key)

    def test_delegating_wrapper_cannot_relabel_the_approval_key(self):
        wrapper = _DelegatingWrapper(self.approval_verifier)
        # The wrapper's reported fingerprint is the approval key's own,
        # because the shipped adapter derives it; policy rejects the pair.
        self.assertEqual(
            self.approval_verifier.key_fingerprint, wrapper.key_fingerprint
        )
        with self.assertRaises(ValueError):
            self.policy_for(wrapper)

    def test_mismatched_trust_fingerprint_fails_kernel_construction(self):
        from pulpo import CeremonyTrust

        trust = ceremony_trust_for(self.ceremony_verifier)
        forged = CeremonyTrust(
            authority_id=trust.authority_id,
            verifier_id=trust.verifier_id,
            key_id=trust.key_id,
            algorithm=trust.algorithm,
            key_fingerprint=sha256(b"advertised-distinct-key").hexdigest(),
            method=trust.method,
            max_evidence_ttl_ns=trust.max_evidence_ttl_ns,
        )
        policy = Policy(
            frozenset({"read", "push"}),
            100,
            frozenset({"push"}),
            authority_trust=trust_for(self.approval_verifier),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=forged,
        )
        with self.assertRaises(AuthorityTrustError):
            GovernanceKernel(
                policy,
                secret=b"key-derivation-test-secret",
                approval_verifier=self.approval_verifier,
                clock=lambda: NOW,
                ceremony_verifier=self.ceremony_verifier,
            )

    def test_genuine_distinct_key_ceremony_admits(self):
        kernel = self.kernel_for(self.ceremony_verifier)
        envelope = signed_envelope(kernel, self.intent, self.approval_signer, now_ns=NOW)
        evidence = signed_evidence(
            kernel,
            self.intent,
            envelope,
            self.ceremony_verifier,
            now_ns=NOW,
            signer=self.ceremony_signer,
        )
        decision = kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(decision.permit)

    def test_evidence_signed_by_the_approval_key_is_denied(self):
        kernel = self.kernel_for(self.ceremony_verifier)
        envelope = signed_envelope(kernel, self.intent, self.approval_signer, now_ns=NOW)
        evidence = signed_evidence(
            kernel,
            self.intent,
            envelope,
            self.ceremony_verifier,
            now_ns=NOW,
            signer=self.approval_signer,
        )
        decision = kernel.evaluate_with_approval(
            self.intent, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("deny", "ceremony_signature_invalid"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "install pulpo[authority]")
class P256CeremonyKeyDerivationTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.verifier = P256CeremonyVerifier(
            authority_id="ceremony:test-owner",
            verifier_id="ceremony-verifier:test-only",
            key_id="ceremony-key:test-only:v1",
            public_key=self.public,
        )

    def _sign(self, payload):
        der = self.private.sign(payload, ec.ECDSA(SHA256()))
        r, s = decode_dss_signature(der)
        return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

    def test_fingerprint_is_derived_and_read_only(self):
        self.assertEqual(sha256(self.public).hexdigest(), self.verifier.key_fingerprint)
        with self.assertRaises(AttributeError):
            self.verifier.key_fingerprint = sha256(b"forged").hexdigest()

    def test_verify_roundtrip_and_wrong_key_rejection(self):
        signature = self._sign(b"payload")
        self.assertTrue(self.verifier.verify(b"payload", signature))
        other = ec.generate_private_key(ec.SECP256R1())
        der = other.sign(b"payload", ec.ECDSA(SHA256()))
        r, s = decode_dss_signature(der)
        wrong = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()
        self.assertFalse(self.verifier.verify(b"payload", wrong))


if __name__ == "__main__":
    unittest.main()

from hashlib import sha256
import unittest

from pulpo.effect_reconcile import EffectReconciliation
from pulpo.ratification import (
    RatificationAttestation,
    RatificationError,
    RatificationTrust,
    evaluate_ratification,
)


class NonSovereignRatificationTests(unittest.TestCase):
    def setUp(self):
        self.governance_secret = b"pulpo-governance-test-key"
        self.ratifier_secret = b"independent-ratifier-test-key"
        self.other_secret = b"other-ratifier-test-key"
        self.governance_fingerprint = sha256(self.governance_secret).hexdigest()
        self.ratifier_fingerprint = sha256(self.ratifier_secret).hexdigest()
        self.other_fingerprint = sha256(self.other_secret).hexdigest()
        self.constitutional_proof_hash = sha256(b"constitutional-proof-v0").hexdigest()
        self.reconciliation = EffectReconciliation(
            status="verified",
            reason="exact_effect_observed",
            effect_envelope_hash=sha256(b"effect-envelope-v0").hexdigest(),
            deltas=(),
            protected_surface_delta=0,
            unauthorized_effects=0,
            uncertain_effects=0,
            authorized_runtime_effects=1,
            canonical_pulpo_evidence=1,
        )
        self.trust = RatificationTrust(
            trusted_ratifier_fingerprints=frozenset({self.ratifier_fingerprint}),
            governance_fingerprints=frozenset({self.governance_fingerprint}),
        )
        self.secrets = {
            self.ratifier_fingerprint: self.ratifier_secret,
            self.governance_fingerprint: self.governance_secret,
            self.other_fingerprint: self.other_secret,
        }

    def sign(self, fingerprint, payload):
        secret = self.secrets[fingerprint]
        return sha256(secret + payload).hexdigest()

    def verify(self, fingerprint, payload, signature):
        secret = self.secrets.get(fingerprint)
        if secret is None:
            return False
        return sha256(secret + payload).hexdigest() == signature

    def attestation(
        self,
        *,
        fingerprint=None,
        reconciliation_hash=None,
        effect_envelope_hash=None,
        constitutional_proof_hash=None,
        decision="ratify",
        issued_at_ns=100,
        expires_at_ns=200,
        ratifier_id="external-ratifier-1",
    ):
        fingerprint = fingerprint or self.ratifier_fingerprint
        unsigned = RatificationAttestation(
            ratifier_id=ratifier_id,
            ratifier_key_fingerprint=fingerprint,
            reconciliation_hash=reconciliation_hash or self.reconciliation.reconciliation_hash,
            effect_envelope_hash=effect_envelope_hash or self.reconciliation.effect_envelope_hash,
            constitutional_proof_hash=constitutional_proof_hash or self.constitutional_proof_hash,
            decision=decision,
            issued_at_ns=issued_at_ns,
            expires_at_ns=expires_at_ns,
            signature="placeholder",
        )
        return RatificationAttestation(
            ratifier_id=unsigned.ratifier_id,
            ratifier_key_fingerprint=unsigned.ratifier_key_fingerprint,
            reconciliation_hash=unsigned.reconciliation_hash,
            effect_envelope_hash=unsigned.effect_envelope_hash,
            constitutional_proof_hash=unsigned.constitutional_proof_hash,
            decision=unsigned.decision,
            issued_at_ns=unsigned.issued_at_ns,
            expires_at_ns=unsigned.expires_at_ns,
            signature=self.sign(fingerprint, unsigned.signing_payload),
        )

    def evaluate(self, attestation, reconciliation=None, now_ns=150, verifier=None):
        return evaluate_ratification(
            reconciliation or self.reconciliation,
            expected_constitutional_proof_hash=self.constitutional_proof_hash,
            trust=self.trust,
            attestation=attestation,
            now_ns=now_ns,
            verify_signature=verifier or self.verify,
        )

    def test_verified_reconciliation_is_not_final_without_independent_ratification(self):
        result = self.evaluate(None)

        self.assertEqual(result.status, "insufficient_evidence")
        self.assertEqual(result.reason, "independent_ratification_required")
        self.assertFalse(result.official)

    def test_independent_trusted_ratifier_can_ratify_exact_verified_reconciliation(self):
        result = self.evaluate(self.attestation())

        self.assertEqual(result.status, "ratified")
        self.assertEqual(result.reason, "independent_ratification_verified")
        self.assertTrue(result.official)
        self.assertEqual(result.ratifier_key_fingerprint, self.ratifier_fingerprint)

    def test_governance_identity_cannot_self_ratify_even_with_valid_signature(self):
        trust = RatificationTrust(
            trusted_ratifier_fingerprints=frozenset({self.ratifier_fingerprint}),
            governance_fingerprints=frozenset({self.governance_fingerprint}),
        )
        attestation = self.attestation(fingerprint=self.governance_fingerprint, ratifier_id="pulpo-governance")

        result = evaluate_ratification(
            self.reconciliation,
            expected_constitutional_proof_hash=self.constitutional_proof_hash,
            trust=trust,
            attestation=attestation,
            now_ns=150,
            verify_signature=self.verify,
        )

        self.assertEqual(result.status, "constitutional_mismatch")
        self.assertEqual(result.reason, "governance_identity_cannot_self_ratify")
        self.assertFalse(result.official)

    def test_trust_configuration_rejects_same_key_as_governor_and_ratifier(self):
        with self.assertRaisesRegex(RatificationError, "ratifier_must_be_independent"):
            RatificationTrust(
                trusted_ratifier_fingerprints=frozenset({self.governance_fingerprint}),
                governance_fingerprints=frozenset({self.governance_fingerprint}),
            )

    def test_untrusted_ratifier_cannot_create_finality(self):
        result = self.evaluate(self.attestation(fingerprint=self.other_fingerprint))

        self.assertEqual(result.status, "constitutional_mismatch")
        self.assertEqual(result.reason, "untrusted_ratifier")
        self.assertFalse(result.official)

    def test_ratifier_cannot_substitute_reconciliation(self):
        result = self.evaluate(
            self.attestation(reconciliation_hash=sha256(b"different-reconciliation").hexdigest())
        )

        self.assertEqual(result.status, "constitutional_mismatch")
        self.assertEqual(result.reason, "reconciliation_substitution")

    def test_ratifier_cannot_substitute_effect_envelope(self):
        result = self.evaluate(
            self.attestation(effect_envelope_hash=sha256(b"different-effect-envelope").hexdigest())
        )

        self.assertEqual(result.status, "constitutional_mismatch")
        self.assertEqual(result.reason, "effect_envelope_substitution")

    def test_ratifier_cannot_substitute_constitutional_proof(self):
        result = self.evaluate(
            self.attestation(constitutional_proof_hash=sha256(b"different-proof").hexdigest())
        )

        self.assertEqual(result.status, "constitutional_mismatch")
        self.assertEqual(result.reason, "constitutional_proof_substitution")

    def test_invalid_ratifier_signature_cannot_create_finality(self):
        valid = self.attestation()
        forged = RatificationAttestation(
            ratifier_id=valid.ratifier_id,
            ratifier_key_fingerprint=valid.ratifier_key_fingerprint,
            reconciliation_hash=valid.reconciliation_hash,
            effect_envelope_hash=valid.effect_envelope_hash,
            constitutional_proof_hash=valid.constitutional_proof_hash,
            decision=valid.decision,
            issued_at_ns=valid.issued_at_ns,
            expires_at_ns=valid.expires_at_ns,
            signature="forged",
        )

        result = self.evaluate(forged)

        self.assertEqual(result.status, "constitutional_mismatch")
        self.assertEqual(result.reason, "invalid_ratifier_signature")

    def test_expired_ratification_is_insufficient_evidence(self):
        result = self.evaluate(self.attestation(expires_at_ns=140), now_ns=150)

        self.assertEqual(result.status, "insufficient_evidence")
        self.assertEqual(result.reason, "ratification_expired")
        self.assertFalse(result.official)

    def test_verifier_unavailability_never_becomes_success(self):
        def unavailable(*_args):
            raise RuntimeError("offline")

        result = self.evaluate(self.attestation(), verifier=unavailable)

        self.assertEqual(result.status, "insufficient_evidence")
        self.assertEqual(result.reason, "ratifier_verification_unavailable")
        self.assertFalse(result.official)

    def test_ratifier_rejection_is_terminal_for_this_attestation(self):
        result = self.evaluate(self.attestation(decision="reject"))

        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.reason, "ratifier_rejected")
        self.assertFalse(result.official)

    def test_non_verified_reconciliation_cannot_be_repaired_by_ratification(self):
        mismatch = EffectReconciliation(
            status="mismatch",
            reason="undeclared_effect_observed",
            effect_envelope_hash=self.reconciliation.effect_envelope_hash,
            deltas=(),
            protected_surface_delta=0,
            unauthorized_effects=1,
            uncertain_effects=0,
            authorized_runtime_effects=0,
            canonical_pulpo_evidence=1,
        )
        attestation = self.attestation(reconciliation_hash=mismatch.reconciliation_hash)

        result = self.evaluate(attestation, reconciliation=mismatch)

        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.reason, "reconciliation_not_verified")
        self.assertFalse(result.official)

    def test_uncertain_reconciliation_cannot_be_repaired_by_ratification(self):
        uncertain = EffectReconciliation(
            status="uncertain",
            reason="observation_incomplete",
            effect_envelope_hash=self.reconciliation.effect_envelope_hash,
            deltas=(),
            protected_surface_delta=0,
            unauthorized_effects=0,
            uncertain_effects=1,
            authorized_runtime_effects=0,
            canonical_pulpo_evidence=1,
        )
        attestation = self.attestation(reconciliation_hash=uncertain.reconciliation_hash)

        result = self.evaluate(attestation, reconciliation=uncertain)

        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.reason, "reconciliation_not_verified")
        self.assertFalse(result.official)


if __name__ == "__main__":
    unittest.main()

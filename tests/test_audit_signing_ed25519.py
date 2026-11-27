"""Ed25519 audit signing era: asymmetric record signatures, dual-era
verification, and the HMAC -> Ed25519 transition.

The HMAC era (tests/test_audit_signing.py) cannot offer a publishable
verification key: verifying a signature requires the deployment's
audit secret itself. This era fixes that for new records: an
Ed25519 signature over the record hash, stored in the same sibling
field with an explicit ``ed25519:`` tag, verifies from the public key
alone. Existing HMAC signatures are bare hex and are byte-identical
to before — no stored record changes; the era is read off the
signature's own form.

Pinned semantics:
- A chain may transition HMAC -> Ed25519 at a record boundary and
  then verifies end to end under a dual-era (composite) verifier.
- Eras never regress: an HMAC-era signature after an Ed25519-era
  record is a downgrade and is refused on its era claim alone.
- A record signed in an era the verifier was never configured for
  is refused — there is nothing it could be verified against.
- Signing still does not bind the chain's length: tail truncation
  verifies, exactly as in the HMAC era (anchors are that coverage).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path

CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None
requires_cryptography = unittest.skipUnless(
    CRYPTOGRAPHY_AVAILABLE, "pulpo[authority] extra (cryptography) not installed"
)

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.kernel import StateIntegrityError
from pulpo.state import (
    AuditSigner,
    CompositeAuditSigner,
    Ed25519AuditSigner,
    Ed25519AuditVerifier,
    InMemoryKernelState,
    SQLiteKernelState,
    _audit_record,
    audit_signature_algorithm,
)

HMAC_SECRET = b"ed25519-era-test-hmac-secret"
KERNEL_SECRET = b"ed25519-era-test-kernel-secret"
NOW = 3_000_000
POLICY = Policy(allowed_actions=frozenset({"wire.transfer"}), max_cost=1000)

# Deterministic test seeds. These are TEST keys, labeled as such:
# they key nothing real and exist so the suite is reproducible.
ED_SEED = bytes.fromhex("11" * 32)
ED_SEED_WRONG = bytes.fromhex("22" * 32)


def kernel_for(state):
    return GovernanceKernel(
        POLICY, secret=KERNEL_SECRET, clock=lambda: NOW, state=state
    )


def evaluate(kernel, index):
    decision = kernel.evaluate(
        Intent("agent-1", "wire.transfer", f"acct:{index}", 10 * index, "s1")
    )
    assert decision.outcome == "allow", decision
    return decision


def ed_signer(seed=ED_SEED):
    return Ed25519AuditSigner(seed)


def composite(ed=None, hmac_secret=HMAC_SECRET, sign=True):
    """The transition verifier: Ed25519 current era, HMAC legacy era."""
    ed = ed if ed is not None else ed_signer()
    verifiers = [ed.verifier()]
    if hmac_secret is not None:
        verifiers.append(AuditSigner(hmac_secret))
    return CompositeAuditSigner(
        signer=ed if sign else None, verifiers=verifiers
    )


def rehash_suffix_keep_signatures(records, start):
    """Privileged-writer rehash: recompute the unkeyed chain from
    ``start`` onward, keeping the (now stale) signature fields."""
    previous = records[start - 1]["hash"] if start > 0 else "0" * 64
    for index in range(start, len(records)):
        record = records[index]
        body = {
            "event": record["event"],
            "payload": record["payload"],
            "previous_hash": previous,
            "timestamp_ns": record["timestamp_ns"],
        }
        record["previous_hash"] = previous
        record["hash"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        previous = record["hash"]


class SignatureClassificationTests(unittest.TestCase):
    def test_classification_by_form(self):
        self.assertEqual(
            "hmac-sha256", audit_signature_algorithm("a" * 64)
        )
        self.assertEqual(
            "ed25519", audit_signature_algorithm("ed25519:" + "a" * 128)
        )
        for malformed in (
            None, "", 1234, b"bytes", "A" * 64, "a" * 63, "a" * 128,
            "ed25519:", "sha256:" + "a" * 64, "not-hex" + "a" * 57,
        ):
            self.assertIsNone(audit_signature_algorithm(malformed), malformed)


@requires_cryptography
class Ed25519SignerUnitTests(unittest.TestCase):
    def test_sign_verify_round_trip_and_tagged_form(self):
        signer = ed_signer()
        signature = signer.sign("a" * 64)
        self.assertTrue(signature.startswith("ed25519:"))
        self.assertEqual(128, len(signature) - len("ed25519:"))
        self.assertTrue(signer.verify("a" * 64, signature))
        self.assertFalse(signer.verify("b" * 64, signature))

    def test_generated_signer_round_trip(self):
        generated = Ed25519AuditSigner.generate()
        signature = generated.sign("a" * 64)
        self.assertTrue(generated.verify("a" * 64, signature))
        self.assertNotEqual(
            ed_signer().key_fingerprint, generated.key_fingerprint
        )

    def test_wrong_public_key_refuses(self):
        signature = ed_signer().sign("a" * 64)
        wrong = Ed25519AuditVerifier(ed_signer(ED_SEED_WRONG).public_key_bytes())
        self.assertFalse(wrong.verify("a" * 64, signature))

    def test_malformed_signatures_never_verify(self):
        signer = ed_signer()
        good = signer.sign("a" * 64)
        for bad in (
            None, "", 1234, b"bytes", "0" * 64,
            "ed25519:", "ed25519:" + "a" * 64, "ed25519:" + "a" * 127,
            "ed25519:" + "A" * 128, "ed25519:" + "z" * 128,
            good.upper().replace("ED25519:", "ed25519:"),
        ):
            self.assertFalse(signer.verify("a" * 64, bad), bad)
        self.assertTrue(signer.verify("a" * 64, good))

    def test_cross_era_signatures_never_verify(self):
        # An HMAC value is not an Ed25519 signature and vice versa:
        # each era's verifier refuses the other era's form outright.
        record_hash = "c" * 64
        hmac_signature = AuditSigner(HMAC_SECRET).sign(record_hash)
        ed_signature = ed_signer().sign(record_hash)
        self.assertFalse(AuditSigner(HMAC_SECRET).verify(record_hash, ed_signature))
        self.assertFalse(ed_signer().verify(record_hash, hmac_signature))
        # A genuine Ed25519 signature with its tag stripped is bare
        # 128-hex: it classifies as no era and verifies under neither.
        stripped = ed_signature[len("ed25519:"):]
        self.assertIsNone(audit_signature_algorithm(stripped))
        self.assertFalse(AuditSigner(HMAC_SECRET).verify(record_hash, stripped))
        self.assertFalse(ed_signer().verify(record_hash, stripped))

    def test_key_length_validation(self):
        with self.assertRaises(ValueError):
            Ed25519AuditSigner(b"\x11" * 31)
        with self.assertRaises(ValueError):
            Ed25519AuditSigner(b"\x11" * 33)
        with self.assertRaises(ValueError):
            Ed25519AuditVerifier(b"\x11" * 31)

    def test_verifier_is_verification_only(self):
        verifier = ed_signer().verifier()
        with self.assertRaises(RuntimeError):
            verifier.sign("a" * 64)
        verify_only = CompositeAuditSigner(verifiers=[verifier])
        with self.assertRaises(RuntimeError):
            verify_only.sign("a" * 64)
        self.assertTrue(
            verify_only.verify("a" * 64, ed_signer().sign("a" * 64))
        )

    def test_public_artifact_round_trip_and_substitution_refused(self):
        signer = ed_signer()
        artifact = signer.public_artifact()
        self.assertEqual("ed25519", artifact["algorithm"])
        self.assertEqual(signer.public_key_hex(), artifact["public_key"])
        self.assertEqual(
            hashlib.sha256(signer.public_key_bytes()).hexdigest(),
            artifact["key_fingerprint"],
        )
        # The artifact is plain JSON data — the well-known-URL shape.
        artifact = json.loads(json.dumps(artifact))
        verifier = Ed25519AuditVerifier.from_artifact(artifact)
        self.assertTrue(verifier.verify("a" * 64, signer.sign("a" * 64)))
        # A substituted key under the original fingerprint is refused.
        forged = dict(artifact)
        forged["public_key"] = ed_signer(ED_SEED_WRONG).public_key_hex()
        with self.assertRaises(ValueError):
            Ed25519AuditVerifier.from_artifact(forged)
        # A non-Ed25519 artifact is refused.
        forged = dict(artifact, algorithm="hmac-sha256")
        with self.assertRaises(ValueError):
            Ed25519AuditVerifier.from_artifact(forged)

    def test_custody_file_round_trip_owner_only_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit-ed25519-secret"
            signer = ed_signer()
            signer.save_custody_file(path)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            loaded = Ed25519AuditSigner.from_custody_file(path)
            self.assertEqual(signer.key_fingerprint, loaded.key_fingerprint)
            self.assertTrue(loaded.verify("a" * 64, signer.sign("a" * 64)))
            with self.assertRaises(FileExistsError):
                signer.save_custody_file(path)
            malformed = Path(tmp) / "malformed"
            malformed.write_text("not a key\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                Ed25519AuditSigner.from_custody_file(malformed)


@requires_cryptography
class Ed25519ChainTests(unittest.TestCase):
    def test_pure_ed25519_inmemory_chain_verifies(self):
        state = InMemoryKernelState(audit_signer=ed_signer())
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        self.assertTrue(
            all(
                r["signature"].startswith("ed25519:")
                for r in kernel.audit
            )
        )
        report = kernel.verify_audit_report()
        self.assertEqual(
            {"ok": True, "reason": None, "total_records": 3,
             "signed_records": 3, "unsigned_records": 0,
             "legacy_records": 0, "signing_enabled": True,
             "failed_record": None},
            report,
        )

    def test_pure_ed25519_sqlite_round_trip_and_wrong_key_boot_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state = SQLiteKernelState(path, audit_signer=ed_signer())
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            evaluate(kernel, 2)
            state.close()
            reopened = SQLiteKernelState(path, audit_signer=ed_signer())
            self.assertTrue(kernel_for(reopened).verify_audit())
            reopened.close()
            wrong = SQLiteKernelState(
                path, audit_signer=ed_signer(ED_SEED_WRONG)
            )
            with self.assertRaises(StateIntegrityError):
                kernel_for(wrong)
            wrong.close()

    def test_chain_verifies_from_public_key_alone(self):
        # The property the HMAC era cannot offer: a verifier holding
        # ONLY the published artifact — no secret, no signing key —
        # verifies the chain and the kernel boots over it.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            signer = ed_signer()
            state = SQLiteKernelState(path, audit_signer=signer)
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            evaluate(kernel, 2)
            state.close()
            artifact = json.loads(json.dumps(signer.public_artifact()))
            public_only = CompositeAuditSigner(
                verifiers=[Ed25519AuditVerifier.from_artifact(artifact)]
            )
            reopened = SQLiteKernelState(path, audit_signer=public_only)
            kernel2 = kernel_for(reopened)
            self.assertTrue(kernel2.verify_audit())
            self.assertEqual(
                2, kernel2.verify_audit_report()["signed_records"]
            )
            reopened.close()

    def test_tampered_ed25519_record_refused(self):
        state = InMemoryKernelState(audit_signer=ed_signer())
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        state._audit[0]["payload"]["intent_hash"] = "f" * 64
        rehash_suffix_keep_signatures(state._audit, 0)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        with self.assertRaises(StateIntegrityError):
            kernel_for(state)

    def test_midchain_removal_still_detected_ed25519(self):
        state = InMemoryKernelState(audit_signer=ed_signer())
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        del state._audit[1]
        self.assertFalse(kernel.verify_audit())
        rehash_suffix_keep_signatures(state._audit, 1)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])

    def test_ed25519_chain_tail_truncation_still_verifies(self):
        # Honest boundary, pinned as in the HMAC era: record signing
        # does not bind the chain's length. Anchors are that coverage.
        state = InMemoryKernelState(audit_signer=ed_signer())
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        del state._audit[-1]
        self.assertTrue(kernel.verify_audit())


@requires_cryptography
class MixedEraTransitionTests(unittest.TestCase):
    def _hmac_segment(self, count=2):
        state = InMemoryKernelState(audit_signer=AuditSigner(HMAC_SECRET))
        kernel = kernel_for(state)
        for index in range(1, count + 1):
            evaluate(kernel, index)
        return state

    def test_mixed_chain_verifies_end_to_end_inmemory(self):
        legacy = self._hmac_segment(2)
        state = InMemoryKernelState(audit_signer=composite())
        state._audit = copy.deepcopy(legacy._audit)
        kernel = kernel_for(state)
        evaluate(kernel, 3)
        evaluate(kernel, 4)
        eras = [audit_signature_algorithm(r["signature"]) for r in kernel.audit]
        self.assertEqual(
            ["hmac-sha256", "hmac-sha256", "ed25519", "ed25519"], eras
        )
        self.assertTrue(kernel.verify_audit())
        report = kernel.verify_audit_report()
        self.assertEqual(4, report["signed_records"])
        self.assertEqual(0, report["unsigned_records"])

    def test_mixed_chain_sqlite_transition_across_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state = SQLiteKernelState(
                path, audit_signer=AuditSigner(HMAC_SECRET)
            )
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            evaluate(kernel, 2)
            state.close()
            # The transition: reopen under the dual-era signer whose
            # current era is Ed25519; new records are Ed25519-signed.
            transitioned = SQLiteKernelState(path, audit_signer=composite())
            kernel2 = kernel_for(transitioned)
            evaluate(kernel2, 3)
            transitioned.close()
            reopened = SQLiteKernelState(path, audit_signer=composite())
            kernel3 = kernel_for(reopened)
            self.assertTrue(kernel3.verify_audit())
            self.assertEqual(
                3, kernel3.verify_audit_report()["signed_records"]
            )
            eras = [
                audit_signature_algorithm(r["signature"])
                for r in kernel3.audit
            ]
            self.assertEqual(["hmac-sha256", "hmac-sha256", "ed25519"], eras)
            reopened.close()

    def test_three_era_chain_unsigned_prefix_hmac_ed25519(self):
        unsigned = InMemoryKernelState()
        kernel = kernel_for(unsigned)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        hmac_state = InMemoryKernelState(
            audit_signer=AuditSigner(HMAC_SECRET), legacy_audit_records=2
        )
        hmac_state._audit = copy.deepcopy(unsigned._audit)
        kernel2 = kernel_for(hmac_state)
        evaluate(kernel2, 3)
        state = InMemoryKernelState(
            audit_signer=composite(), legacy_audit_records=2
        )
        state._audit = copy.deepcopy(hmac_state._audit)
        kernel3 = kernel_for(state)
        evaluate(kernel3, 4)
        self.assertTrue(kernel3.verify_audit())
        report = kernel3.verify_audit_report()
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(2, report["signed_records"])
        self.assertEqual(2, report["legacy_records"])

    def test_mixed_chain_refused_without_legacy_era_verifier(self):
        # A verifier configured only for Ed25519 cannot verify the
        # HMAC segment: the records are refused, not skipped.
        legacy = self._hmac_segment(2)
        state = InMemoryKernelState(
            audit_signer=CompositeAuditSigner(
                signer=ed_signer(), verifiers=[ed_signer().verifier()]
            )
        )
        state._audit = copy.deepcopy(legacy._audit)
        probe = GovernanceKernel.__new__(GovernanceKernel)
        probe._state = state
        report = probe.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(0, report["failed_record"])

    def test_downgrade_record_after_transition_refused(self):
        legacy = self._hmac_segment(1)
        state = InMemoryKernelState(audit_signer=composite())
        state._audit = copy.deepcopy(legacy._audit)
        kernel = kernel_for(state)
        evaluate(kernel, 2)
        self.assertTrue(kernel.verify_audit())
        # A writer holding only the retired HMAC key appends a
        # correctly HMAC-signed record after the transition. Its
        # cryptography is genuine; its era is a downgrade.
        previous = state._audit[-1]["hash"]
        forged = _audit_record(
            previous,
            "decision",
            {"outcome": "allow", "reason": "policy_satisfied",
             "intent_hash": "9" * 64},
            NOW,
            signer=AuditSigner(HMAC_SECRET),
        )
        state._audit.append(forged)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_downgrade", report["reason"])
        self.assertEqual(2, report["failed_record"])
        with self.assertRaises(StateIntegrityError):
            kernel_for(state)

    def test_downgrade_append_through_state_layer_refused_at_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state = SQLiteKernelState(path, audit_signer=composite())
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            state.close()
            # The state layer is writer-controlled: an HMAC-configured
            # open can append. The refusal lands at verification.
            downgraded = SQLiteKernelState(
                path, audit_signer=AuditSigner(HMAC_SECRET)
            )
            downgraded.append(
                "decision",
                {"outcome": "allow", "reason": "policy_satisfied",
                 "intent_hash": "8" * 64},
                NOW,
            )
            downgraded.close()
            reopened = SQLiteKernelState(path, audit_signer=composite())
            probe = GovernanceKernel.__new__(GovernanceKernel)
            probe._state = reopened
            report = probe.verify_audit_report()
            self.assertFalse(report["ok"])
            self.assertEqual("audit_signature_downgrade", report["reason"])
            self.assertEqual(1, report["failed_record"])
            reopened.close()

    def test_wrong_era_record_in_hmac_segment_refused(self):
        # An Ed25519-signed record spliced into an HMAC-era chain:
        # under an HMAC-only verifier it cannot verify at all, and
        # under the dual-era verifier the genuine HMAC records after
        # it become downgrades. Either way the chain is refused.
        legacy = self._hmac_segment(2)
        spliced = copy.deepcopy(legacy._audit)
        record = spliced[0]
        record["signature"] = ed_signer().sign(record["hash"])
        state = InMemoryKernelState(audit_signer=AuditSigner(HMAC_SECRET))
        state._audit = spliced
        probe = GovernanceKernel.__new__(GovernanceKernel)
        probe._state = state
        report = probe.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])

        state2 = InMemoryKernelState(audit_signer=composite())
        state2._audit = copy.deepcopy(spliced)
        probe2 = GovernanceKernel.__new__(GovernanceKernel)
        probe2._state = state2
        report2 = probe2.verify_audit_report()
        self.assertFalse(report2["ok"])
        self.assertEqual("audit_signature_downgrade", report2["reason"])
        self.assertEqual(1, report2["failed_record"])

    def test_hmac_value_with_ed25519_tag_glued_on_refused(self):
        state = InMemoryKernelState(audit_signer=ed_signer())
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        record_hash = state._audit[0]["hash"]
        state._audit[0]["signature"] = (
            "ed25519:" + AuditSigner(HMAC_SECRET).sign(record_hash)
        )
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])


if __name__ == "__main__":
    unittest.main()

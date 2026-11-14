"""Phase 2, Item 1: signed audit records (HMAC under a dedicated audit secret).

Design 1A of the Phase 2 memo, adopted by the owner's 2026-11-13 ruling:
every record appended after signing is enabled carries an HMAC over its
hash under a per-deployment ``audit-secret`` (never the kernel secret);
enablement is recorded in deployment config outside the state file; the
pre-enablement prefix verifies legacy-style and is reported as an
unsigned prefix with a count.

Honest scope, pinned here: signing prevents ACCEPTANCE of forgeries
(mid-chain deletion with rehashing, payload edits, stripped or forged
signatures are all refused at boot/verify). It does NOT prevent a file
writer from writing bytes, and it does NOT bind the chain's length —
tail truncation still verifies (see
test_signed_chain_tail_truncation_still_verifies), which is Item 2's
coverage (signed anchors), not this item's. The pair (1+2) is the unit
of coverage.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

import pulpo.ops as ops_module
from pulpo import GovernanceKernel, Intent, Policy
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_evidence import (
    CustodyEvidenceViolation,
    SQLiteCustodyEvidenceConvergence,
)
from pulpo.kernel import StateIntegrityError
from pulpo.ops import OPS_LOCK_FILENAME, TEST_SECRET_ENV, _DeploymentLock, main
from pulpo.state import (
    AuditSigner,
    InMemoryKernelState,
    SQLiteKernelState,
    _audit_record,
)
from tests.authority_support import HmacTestVerifier, signed_envelope

# Repo root (the tests/ directory's parent): the working directory for
# subprocess invocations of `python -m pulpo.ops` in the serialization
# tests below.
REPO_ROOT = Path(__file__).resolve().parents[1]

# A TRUE pre-signing database schema: the audit table has no signature
# column and permit_directives has no parent_directive_hash column —
# the shape a deployment created before PR #355 / #357 would carry.
# (The downgrade helper above only strips config/secret; the state
# file it leaves behind already has both columns.)
_LEGACY_SCHEMA = """
CREATE TABLE permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1)));
CREATE TABLE approvals (approval_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE);
CREATE TABLE ceremony_evidence (evidence_id TEXT PRIMARY KEY);
CREATE TABLE directives (directive_id TEXT NOT NULL, version INTEGER NOT NULL, directive_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)), PRIMARY KEY (directive_id, version));
CREATE TABLE permit_directives (permit TEXT PRIMARY KEY REFERENCES permits(permit) ON DELETE CASCADE, directive_id TEXT NOT NULL, directive_version INTEGER NOT NULL, directive_hash TEXT NOT NULL, directive_issued_at_ns INTEGER NOT NULL, directive_expires_at_ns INTEGER NOT NULL);
CREATE TABLE audit (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, timestamp_ns INTEGER NOT NULL, hash TEXT NOT NULL);
"""


def _build_true_legacy_db(path: Path, count: int = 3) -> None:
    """Write a pre-signing state file: ``count`` unsigned hash-chained
    records under the old schema (no signature column)."""
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_LEGACY_SCHEMA)
        previous = "0" * 64
        for index in range(1, count + 1):
            record = _audit_record(
                previous,
                "decision",
                {"outcome": "allow", "reason": "policy_satisfied",
                 "intent_hash": f"{index:064x}"},
                NOW,
                signer=None,
            )
            connection.execute(
                "INSERT INTO audit (event, payload_json, previous_hash,"
                " timestamp_ns, hash) VALUES (?, ?, ?, ?, ?)",
                (record["event"],
                 json.dumps(record["payload"], sort_keys=True,
                            separators=(",", ":")),
                 record["previous_hash"], record["timestamp_ns"],
                 record["hash"]),
            )
            previous = record["hash"]
        connection.commit()
    finally:
        connection.close()


def _table_columns(path: Path, table: str) -> list[str]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [row[1] for row in connection.execute(
            f"PRAGMA table_info({table})").fetchall()]
    finally:
        connection.close()

AUDIT_SECRET = b"item1-test-audit-secret"
KERNEL_SECRET = b"item1-test-kernel-secret"
NOW = 2_000_000
POLICY = Policy(allowed_actions=frozenset({"wire.transfer"}), max_cost=1000)

ACTION = "deploy.release"
RESOURCE = "service:api"
PRINCIPAL = "alice"
DEPLOYMENT_ID = "deployment:test-audit-signing"
SESSION_ID = "default"
SECRET_TEXT = "ops-audit-signing-test-secret"
SECRET_BYTES = SECRET_TEXT.encode("utf-8")
ENVELOPE_TTL_NS = 60_000_000_000


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


def rehash_suffix_keep_signatures(records, start):
    """Recompute previous_hash/hash from ``start`` onward, KEEPING any
    signature fields (stale): the faithful privileged-writer rehash —
    the writer recomputes the public unkeyed chain but cannot recompute
    signatures without the audit secret."""
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


class AuditSignerTests(unittest.TestCase):
    def test_sign_verify_round_trip_and_wrong_key(self):
        signer = AuditSigner(AUDIT_SECRET)
        signature = signer.sign("a" * 64)
        self.assertTrue(signer.verify("a" * 64, signature))
        self.assertFalse(signer.verify("b" * 64, signature))
        self.assertFalse(AuditSigner(b"another-secret").verify("a" * 64, signature))

    def test_missing_malformed_and_nonstring_signatures_never_verify(self):
        signer = AuditSigner(AUDIT_SECRET)
        signature = signer.sign("a" * 64)
        for bad in (None, "", "0" * 64, "not-hex", 1234, b"bytes"):
            self.assertFalse(signer.verify("a" * 64, bad), bad)
        self.assertTrue(signer.verify("a" * 64, signature))

    def test_empty_secret_rejected(self):
        with self.assertRaises(ValueError):
            AuditSigner(b"")


class SignedAuditLibraryTests(unittest.TestCase):
    def test_signed_inmemory_records_carry_signatures_and_verify(self):
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        self.assertTrue(all("signature" in r for r in kernel.audit))
        self.assertTrue(kernel.verify_audit())
        report = kernel.verify_audit_report()
        self.assertEqual(
            {"ok": True, "reason": None, "total_records": 3, "signed_records": 3,
             "unsigned_records": 0, "legacy_records": 0,
             "signing_enabled": True, "failed_record": None},
            report,
        )

    def test_signed_sqlite_round_trip_reopen_with_same_signer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state = SQLiteKernelState(path, audit_signer=AuditSigner(AUDIT_SECRET))
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            evaluate(kernel, 2)
            state.close()
            reopened = SQLiteKernelState(path, audit_signer=AuditSigner(AUDIT_SECRET))
            kernel2 = kernel_for(reopened)
            self.assertTrue(kernel2.verify_audit())
            self.assertEqual(2, kernel2.verify_audit_report()["signed_records"])
            reopened.close()

    def test_signed_sqlite_reopen_with_wrong_signer_refuses_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state = SQLiteKernelState(path, audit_signer=AuditSigner(AUDIT_SECRET))
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            state.close()
            wrong = SQLiteKernelState(path, audit_signer=AuditSigner(b"wrong-key"))
            with self.assertRaises(StateIntegrityError):
                kernel_for(wrong)
            wrong.close()

    def test_kernel_level_signer_constructs_signed_inmemory_state(self):
        kernel = GovernanceKernel(
            POLICY, secret=KERNEL_SECRET, clock=lambda: NOW,
            audit_signer=AuditSigner(AUDIT_SECRET),
        )
        evaluate(kernel, 1)
        self.assertTrue(kernel.verify_audit())
        self.assertEqual(1, kernel.verify_audit_report()["signed_records"])

    def test_kernel_rejects_signer_alongside_supplied_state(self):
        state = InMemoryKernelState()
        with self.assertRaises(ValueError):
            GovernanceKernel(
                POLICY, secret=KERNEL_SECRET, state=state,
                audit_signer=AuditSigner(AUDIT_SECRET),
            )

    def test_legacy_mode_unchanged_unsigned_state_verifies(self):
        state = InMemoryKernelState()
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        self.assertTrue(kernel.verify_audit())
        report = kernel.verify_audit_report()
        self.assertFalse(report["signing_enabled"])
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(0, report["signed_records"])

    def test_legacy_prefix_verifies_and_reports_unsigned_count(self):
        # Two unsigned records, then enablement at record 2, then a
        # signed append: the prefix verifies legacy-style and is
        # reported as unsigned; only the post-enablement record is
        # signed. (The enablement itself is config, outside the state;
        # here the state is rebuilt with the same stored trail, the way
        # ops reopens it after writing the config.)
        unsigned = InMemoryKernelState()
        kernel = kernel_for(unsigned)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        signed = InMemoryKernelState(
            audit_signer=AuditSigner(AUDIT_SECRET), legacy_audit_records=2
        )
        signed._audit = unsigned._audit
        kernel2 = kernel_for(signed)
        self.assertTrue(kernel2.verify_audit())
        report = kernel2.verify_audit_report()
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(0, report["signed_records"])
        evaluate(kernel2, 3)
        report = kernel2.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(1, report["signed_records"])

    def test_midchain_delete_with_rehash_refused_signed_inmemory(self):
        # The design repro, in-memory: delete the forbidden-style
        # record mid-chain, rehash the suffix keeping stale signatures
        # (the writer cannot recompute them), and the chain must refuse.
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        self.assertTrue(kernel.verify_audit())
        del state._audit[1]
        self.assertFalse(kernel.verify_audit())
        rehash_suffix_keep_signatures(state._audit, 1)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(1, report["failed_record"])
        # A fresh kernel over the tampered store refuses to boot.
        with self.assertRaises(StateIntegrityError):
            kernel_for(state)

    def test_midchain_delete_with_rehash_and_stripped_signatures_refused(self):
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        del state._audit[1]
        rehash_suffix_keep_signatures(state._audit, 1)
        for record in state._audit:
            record.pop("signature", None)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_missing", report["reason"])

    def test_payload_edit_with_rehash_refused_signed_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state = SQLiteKernelState(path, audit_signer=AuditSigner(AUDIT_SECRET))
            kernel = kernel_for(state)
            evaluate(kernel, 1)
            evaluate(kernel, 2)
            state.close()
            connection = sqlite3.connect(path)
            row = connection.execute(
                "SELECT sequence, payload_json FROM audit WHERE sequence = 2"
            ).fetchone()
            sequence, payload_json = row
            payload = json.loads(payload_json)
            payload["intent_hash"] = "f" * 64
            new_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            # Recompute the record hash honestly (the writer's rehash),
            # keeping the stale signature: the signature no longer
            # matches the recomputed hash.
            record = connection.execute(
                "SELECT event, previous_hash, timestamp_ns FROM audit WHERE sequence = 2"
            ).fetchone()
            body = {"event": record[0], "payload": payload,
                    "previous_hash": record[1], "timestamp_ns": record[2]}
            new_hash = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            connection.execute(
                "UPDATE audit SET payload_json = ?, hash = ? WHERE sequence = ?",
                (new_payload, new_hash, sequence),
            )
            connection.commit()
            connection.close()
            reopened = SQLiteKernelState(path, audit_signer=AuditSigner(AUDIT_SECRET))
            probe = GovernanceKernel.__new__(GovernanceKernel)
            probe._state = reopened
            report = probe.verify_audit_report()
            self.assertFalse(report["ok"])
            self.assertEqual("audit_signature_invalid", report["reason"])
            reopened.close()
            tampered = SQLiteKernelState(path, audit_signer=AuditSigner(AUDIT_SECRET))
            with self.assertRaises(StateIntegrityError):
                kernel_for(tampered)
            tampered.close()

    def test_single_signature_stripped_refused(self):
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        del state._audit[0]["signature"]
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_missing", report["reason"])
        self.assertEqual(0, report["failed_record"])

    def test_single_signature_replaced_with_garbage_refused(self):
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        state._audit[0]["signature"] = "0" * 64
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])

    def test_signed_chain_tail_truncation_still_verifies(self):
        # Honest boundary: signatures do not bind the chain's length.
        # Truncating the tail of a signed chain still verifies — this
        # is Item 2's coverage (signed anchors), not this item's. The
        # test pins the boundary so a future reader cannot mistake
        # record signing for tamper-proof history.
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        evaluate(kernel, 2)
        evaluate(kernel, 3)
        del state._audit[-1]
        self.assertTrue(kernel.verify_audit())
        self.assertEqual(2, kernel.verify_audit_report()["signed_records"])

    def test_signature_excluded_from_hashed_body(self):
        # The unkeyed chain math is unchanged by signing: a record's
        # hash is computed over {event, payload, previous_hash,
        # timestamp_ns} only, so a legacy verifier recomputing the body
        # agrees on the hash of a signed record.
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        record = kernel.audit[0]
        body = {k: v for k, v in record.items() if k not in ("hash", "signature")}
        self.assertEqual(
            hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            record["hash"],
        )


class CustodyEvidenceSigningTests(unittest.TestCase):
    NOW_EVIDENCE = 81_000_000

    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def _signed_state(self):
        state = SQLiteKernelState(
            self.path, audit_signer=AuditSigner(AUDIT_SECRET)
        )
        state.close()
        return state

    def _custody(self):
        return SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-evidence-secret",
            clock=lambda: self.NOW_EVIDENCE,
        )

    def _authorize(self, custody):
        head = custody.snapshot()
        return custody.authorize_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            object_hash="1" * 64,
            target_hash="2" * 64,
            permit_hash="3" * 64,
            authorization_hash="4" * 64,
        )

    def test_projection_with_signer_appends_signed_record(self):
        self._signed_state()
        custody = self._custody()
        # The convergence installs the outbox trigger in __init__, so
        # it must exist BEFORE the custody transition that creates the
        # obligation (same order as tests/test_custody_evidence.py).
        evidence = SQLiteCustodyEvidenceConvergence(
            custody, audit_signer=AuditSigner(AUDIT_SECRET)
        )
        self._authorize(custody)
        projected = evidence.project_all()
        self.assertEqual(1, len(projected))
        state = SQLiteKernelState(
            self.path, audit_signer=AuditSigner(AUDIT_SECRET)
        )
        kernel = kernel_for(state)
        self.assertTrue(kernel.verify_audit())
        self.assertEqual(1, kernel.verify_audit_report()["signed_records"])
        self.assertEqual(
            "custody_transition", kernel.audit[0]["event"]
        )
        state.close()

    def test_projection_without_signer_into_signed_chain_refuses(self):
        # Seed one signed record so the chain is detectably signed.
        state = SQLiteKernelState(
            self.path, audit_signer=AuditSigner(AUDIT_SECRET)
        )
        kernel = kernel_for(state)
        evaluate(kernel, 1)
        state.close()
        custody = self._custody()
        evidence = SQLiteCustodyEvidenceConvergence(custody)
        self._authorize(custody)
        with self.assertRaises(CustodyEvidenceViolation):
            evidence.project_all()
        # Nothing was projected: the obligation is still pending and no
        # unsigned record reached the chain.
        self.assertEqual(1, evidence.pending_count())
        state2 = SQLiteKernelState(
            self.path, audit_signer=AuditSigner(AUDIT_SECRET)
        )
        self.assertEqual(1, len(state2.audit))
        self.assertTrue(kernel_for(state2).verify_audit())
        state2.close()

    def test_projection_without_signer_into_empty_signed_chain_fails_next_boot(self):
        # Documented boundary: the guard keys on signed records
        # already in the chain, so an empty signed chain cannot tell
        # the projection it is signed. The projection succeeds — but
        # the unsigned record it appends is refused at the next kernel
        # boot, fail-closed, never silently accepted.
        self._signed_state()
        custody = self._custody()
        evidence = SQLiteCustodyEvidenceConvergence(custody)
        self._authorize(custody)
        projected = evidence.project_all()
        self.assertEqual(1, len(projected))
        state = SQLiteKernelState(
            self.path, audit_signer=AuditSigner(AUDIT_SECRET)
        )
        with self.assertRaises(StateIntegrityError):
            kernel_for(state)
        state.close()

    def test_projection_without_signer_into_unsigned_chain_unchanged(self):
        state = SQLiteKernelState(self.path)
        state.close()
        custody = self._custody()
        evidence = SQLiteCustodyEvidenceConvergence(custody)
        self._authorize(custody)
        projected = evidence.project_all()
        self.assertEqual(1, len(projected))
        state2 = SQLiteKernelState(self.path)
        self.assertTrue(kernel_for(state2).verify_audit())
        state2.close()


class AuditSigningOpsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pulpo-audit-signing-")
        self.root = Path(self.temporary.name)
        self.deployment = self.root / "deployment"
        self.envelope_path = self.root / "envelope.json"
        self.env = mock.patch.dict(os.environ, {TEST_SECRET_ENV: SECRET_TEXT})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temporary.cleanup()

    # -- helpers (mirroring tests/test_ops_cli.py) --------------------

    def run_cli(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main([str(item) for item in argv])
        text = output.getvalue().strip()
        return exit_code, (json.loads(text) if text else {})

    def init_trusted(self):
        exit_code, report = self.run_cli(
            [
                "init", self.deployment, "--action", ACTION, "--max-cost", "1000",
                "--session-id", SESSION_ID, "--deployment-id", DEPLOYMENT_ID,
                "--authority-id", HmacTestVerifier.authority_id,
                "--verifier-id", HmacTestVerifier.verifier_id,
                "--key-id", HmacTestVerifier.key_id,
                "--algorithm", HmacTestVerifier.algorithm,
                "--key-fingerprint", HmacTestVerifier.key_fingerprint,
                "--verifier-kind", "hmac-test",
            ]
        )
        self.assertEqual(0, exit_code, report)
        self.assertTrue(report["authority_configured"])
        return report

    def init_trustless(self):
        exit_code, report = self.run_cli(
            ["init", self.deployment, "--action", ACTION, "--max-cost", "1000"]
        )
        self.assertEqual(0, exit_code, report)
        self.assertFalse(report["authority_configured"])
        return report

    def deployment_policy(self):
        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        trust = None
        if config.get("authority_trust") is not None:
            from pulpo import AuthorityTrust

            trust = AuthorityTrust(**config["authority_trust"])
        # Mirror ops._effective_policy: a trustless deployment records
        # its approval action but does not kernel-enable it.
        policy = Policy(
            allowed_actions=frozenset(config["allowed_actions"]),
            max_cost=config["max_cost"],
            approval_actions=frozenset(config["approval_actions"]) if trust is not None else frozenset(),
            authority_trust=trust,
        )
        return config, policy

    def mint_envelope(self, intent):
        _, policy = self.deployment_policy()
        verifier = HmacTestVerifier(secret=SECRET_BYTES)
        throwaway = GovernanceKernel(
            policy, approval_verifier=verifier, state=InMemoryKernelState()
        )
        envelope = signed_envelope(
            throwaway, intent, verifier, now_ns=time.time_ns(),
            ttl_ns=ENVELOPE_TTL_NS,
        )
        self.envelope_path.write_text(json.dumps(asdict(envelope)), encoding="utf-8")
        return envelope

    def intent(self, cost=100):
        return Intent(
            principal=PRINCIPAL, action=ACTION, resource=RESOURCE,
            cost=cost, session_id=SESSION_ID,
        )

    def authorize(self, cost=100):
        return self.run_cli(
            [
                "authorize", self.deployment, "--envelope", self.envelope_path,
                "--principal", PRINCIPAL, "--action", ACTION,
                "--resource", RESOURCE, "--cost", str(cost),
                "--session-id", SESSION_ID,
            ]
        )

    def consume(self, permit_path, cost=100):
        return self.run_cli(
            [
                "consume", self.deployment, "--permit-file", permit_path,
                "--principal", PRINCIPAL, "--action", ACTION,
                "--resource", RESOURCE, "--cost", str(cost),
                "--session-id", SESSION_ID,
            ]
        )

    def authorize_ok(self, cost=100):
        self.mint_envelope(self.intent(cost=cost))
        exit_code, report = self.authorize(cost=cost)
        self.assertEqual(0, exit_code, report)
        self.assertEqual("allow", report["outcome"])
        permit_path = Path(report["permit_path"])
        self.assertTrue(permit_path.is_file())
        return report, permit_path

    def verify(self):
        return self.run_cli(["verify", self.deployment])

    def status(self):
        return self.run_cli(["status", self.deployment])

    def anchor(self):
        return self.run_cli(["anchor", self.deployment])

    def enable_signing(self):
        return self.run_cli(["enable-audit-signing", self.deployment])

    def _downgrade_to_legacy(self):
        """Turn a fresh init into a pre-Item-1 deployment: unsigned
        records, no audit_signing config, no audit secret. The kernel
        secret stays, so the deployment remains usable."""
        config_path = self.deployment / "policy.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config.pop("audit_signing", None)
        config_path.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.deployment / "audit-secret").unlink(missing_ok=True)

    def _append_unsigned_records(self, count):
        """Append ``count`` unsigned records through an unsigned state,
        as a pre-Item-1 deployment would have them. The append goes
        through the state layer directly — a trusted deployment's kernel
        would require an approval envelope for evaluate(), and the
        prefix's content is irrelevant here; what matters is that the
        records are unsigned and hash-chained."""
        state = SQLiteKernelState(self.deployment / "state.db")
        for index in range(1, count + 1):
            state.append(
                "decision",
                {"outcome": "allow", "reason": "policy_satisfied",
                 "intent_hash": f"{index:064x}"},
                NOW,
            )
        state.close()

    def _replace_state_with_true_legacy_db(self, count=3):
        """Replace the deployment's state file with a TRUE pre-signing
        one (old schema, no signature column) holding ``count`` unsigned
        records. The deployment keeps its policy and kernel secret, so
        it stays usable — this is the shape a deployment created before
        PR #355 / #357 would carry into a projection."""
        _build_true_legacy_db(self.deployment / "state.db", count)

    def _secret_mode(self, name):
        return oct(os.stat(self.deployment / name).st_mode & 0o777)

    # -- tests -----------------------------------------------------------

    def test_init_provisions_distinct_audit_secret_and_enables_signing(self):
        self.init_trusted()
        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {"enabled": True, "legacy_records": 0}, config["audit_signing"]
        )
        audit_secret = (self.deployment / "audit-secret").read_text(encoding="utf-8").strip()
        kernel_secret = (self.deployment / "kernel-secret").read_text(encoding="utf-8").strip()
        anchor_secret = (self.deployment / "anchor-secret").read_text(encoding="utf-8").strip()
        self.assertEqual(64, len(audit_secret))
        self.assertNotEqual(audit_secret, kernel_secret)
        self.assertNotEqual(audit_secret, anchor_secret)
        self.assertEqual("0o600", self._secret_mode("audit-secret"))

    def test_end_to_end_signed_flow_verify_reports_coverage(self):
        self.init_trusted()
        _, permit_path = self.authorize_ok()
        exit_code, consume_report = self.consume(permit_path)
        self.assertEqual(0, exit_code, consume_report)
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertTrue(verify_report["ok"])
        self.assertTrue(verify_report["chain_valid"])
        signing = verify_report["audit_signing"]
        self.assertTrue(signing["enabled"])
        self.assertGreater(signing["signed_records"], 0)
        self.assertEqual(0, signing["unsigned_records"])
        self.assertEqual(0, signing["legacy_records"])
        self.assertIsNone(signing["reason"])
        exit_code, status_report = self.status()
        self.assertEqual(0, exit_code, status_report)
        self.assertTrue(status_report["audit_signing"]["enabled"])
        self.assertNotIn("warning", status_report["audit_signing"])

    def test_verify_fails_closed_when_signatures_stripped(self):
        self.init_trusted()
        _, permit_path = self.authorize_ok()
        self.consume(permit_path)
        connection = sqlite3.connect(self.deployment / "state.db")
        connection.execute("UPDATE audit SET signature = NULL")
        connection.commit()
        connection.close()
        exit_code, report = self.verify()
        self.assertEqual(1, exit_code, report)
        self.assertFalse(report["ok"])
        # A tampered signed chain fails kernel boot, so verify reports
        # the open failure (chain_valid null, as for every boot-level
        # chain refusal since #355) — the named signature reason is
        # the library-level verify_audit_report, pinned in
        # SignedAuditLibraryTests. The refusal itself is what ops must
        # guarantee, and it does: exit 1, nothing verified.
        self.assertIsNone(report["chain_valid"])
        self.assertIn("kernel state could not be opened", report["error"])

    def test_projections_fail_closed_when_audit_secret_deleted(self):
        self.init_trusted()
        _, permit_path = self.authorize_ok()
        self.consume(permit_path)
        (self.deployment / "audit-secret").unlink()
        exit_code, verify_report = self.verify()
        self.assertEqual(1, exit_code, verify_report)
        # An open failure is not a chain verdict: chain_valid is null.
        self.assertIsNone(verify_report["chain_valid"])
        self.assertIn("audit secret", verify_report["error"])
        exit_code, status_report = self.status()
        self.assertEqual(1, exit_code, status_report)
        self.assertIsNone(status_report["chain_valid"])
        # The projections create nothing: the secret stays deleted.
        self.assertFalse((self.deployment / "audit-secret").exists())

    def test_projections_create_nothing_on_legacy_deployment(self):
        self.init_trustless()
        self._downgrade_to_legacy()
        self._append_unsigned_records(2)
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertTrue(verify_report["chain_valid"])
        self.assertFalse(verify_report["audit_signing"]["enabled"])
        self.assertEqual(2, verify_report["audit_signing"]["unsigned_records"])
        exit_code, status_report = self.status()
        self.assertEqual(0, exit_code, status_report)
        self.assertEqual(
            "audit_signing_not_enabled",
            status_report["audit_signing"]["warning"],
        )
        self.assertFalse((self.deployment / "audit-secret").exists())

    def test_legacy_deployment_enables_signing_with_legacy_prefix(self):
        self.init_trusted()
        self._downgrade_to_legacy()
        self._append_unsigned_records(3)
        exit_code, report = self.enable_signing()
        self.assertEqual(0, exit_code, report)
        self.assertTrue(report["audit_signing"]["enabled"])
        self.assertEqual(3, report["audit_signing"]["legacy_records"])
        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {"enabled": True, "legacy_records": 3}, config["audit_signing"]
        )
        # The prefix verifies legacy-style and is reported unsigned.
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertTrue(verify_report["chain_valid"])
        self.assertEqual(3, verify_report["audit_signing"]["unsigned_records"])
        self.assertEqual(0, verify_report["audit_signing"]["signed_records"])
        # New appends are signed; the prefix stays reported unsigned.
        _, permit_path = self.authorize_ok()
        self.consume(permit_path)
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertGreater(verify_report["audit_signing"]["signed_records"], 0)
        self.assertEqual(3, verify_report["audit_signing"]["unsigned_records"])
        # The legacy prefix is witnessable: anchor it and verify.
        exit_code, anchor_report = self.anchor()
        self.assertEqual(0, exit_code, anchor_report)
        self.assertTrue(anchor_report["signed"])
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertEqual("anchored_prefix_verified", verify_report["anchored"]["reason"])

    def test_enable_signing_is_idempotent(self):
        self.init_trusted()
        self._downgrade_to_legacy()
        self._append_unsigned_records(2)
        exit_code, first = self.enable_signing()
        self.assertEqual(0, exit_code, first)
        config_before = (self.deployment / "policy.json").read_bytes()
        exit_code, second = self.enable_signing()
        self.assertEqual(0, exit_code, second)
        self.assertTrue(second["already_enabled"])
        self.assertEqual(2, second["audit_signing"]["legacy_records"])
        self.assertEqual(config_before, (self.deployment / "policy.json").read_bytes())

    def test_enable_signing_refuses_tampered_legacy_chain(self):
        self.init_trusted()
        self._downgrade_to_legacy()
        self._append_unsigned_records(2)
        connection = sqlite3.connect(self.deployment / "state.db")
        connection.execute("UPDATE audit SET payload_json = ? WHERE sequence = 1", ('{"changed":true}',))
        connection.commit()
        connection.close()
        exit_code, report = self.enable_signing()
        self.assertEqual(1, exit_code, report)
        self.assertIn("audit chain is invalid", report["error"])
        # Nothing was enabled: no config entry, no secret provisioned.
        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("audit_signing", config)
        self.assertFalse((self.deployment / "audit-secret").exists())

    def test_mutating_commands_do_not_silently_enable_signing(self):
        # The migration is an explicit operator action
        # (enable-audit-signing), not a side effect of authorize: a
        # legacy deployment keeps appending unsigned records until the
        # operator enables signing, and no audit secret appears.
        self.init_trusted()
        self._downgrade_to_legacy()
        _, permit_path = self.authorize_ok()
        self.consume(permit_path)
        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("audit_signing", config)
        self.assertFalse((self.deployment / "audit-secret").exists())
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertFalse(verify_report["audit_signing"]["enabled"])

    def test_malformed_audit_signing_config_fails_closed(self):
        self.init_trusted()
        config_path = self.deployment / "policy.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["audit_signing"] = {"enabled": "yes", "legacy_records": 0}
        config_path.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        exit_code, report = self.verify()
        self.assertEqual(1, exit_code, report)
        self.assertIsNone(report["chain_valid"])
        self.assertIn("audit_signing", report["error"])

    def test_anchor_over_signed_chain_verifies(self):
        # The anchor witness's chain check excludes the signature
        # field, so a signed chain anchors and verifies end to end.
        self.init_trusted()
        _, permit_path = self.authorize_ok()
        self.consume(permit_path)
        exit_code, anchor_report = self.anchor()
        self.assertEqual(0, exit_code, anchor_report)
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertEqual("anchored_prefix_verified", verify_report["anchored"]["reason"])
        self.assertGreater(verify_report["audit_signing"]["signed_records"], 0)

    # -- Codex P1 fixes on PR #357 -------------------------------------
    #
    # P1 #1 (state.py): projection opens migrated legacy databases —
    # verify/status executed the ALTER TABLEs merely by inspecting a
    # deployment, and failed outright ("attempt to write a readonly
    # database") on a read-only mount. Projections now open without
    # migration and read a missing signature column as unsigned.
    # P1 #2 (ops.py): enable-audit-signing raced with audit writers —
    # an authorize landing between the cutoff read and the config save
    # appended unsigned records past a too-small legacy prefix and
    # bricked the deployment at the next boot. The mutating commands
    # and enablement now hold the deployment lock across the whole
    # transition.

    def test_verify_status_do_not_migrate_true_legacy_database(self):
        self.init_trusted()
        self._downgrade_to_legacy()
        self._replace_state_with_true_legacy_db(3)
        state_path = self.deployment / "state.db"
        self.assertNotIn("signature", _table_columns(state_path, "audit"))
        self.assertNotIn(
            "parent_directive_hash",
            _table_columns(state_path, "permit_directives"),
        )
        digest_before = hashlib.sha256(state_path.read_bytes()).hexdigest()

        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertTrue(verify_report["chain_valid"])
        self.assertEqual(3, verify_report["audit_records"])
        self.assertEqual(3, verify_report["audit_signing"]["unsigned_records"])
        exit_code, status_report = self.status()
        self.assertEqual(0, exit_code, status_report)
        self.assertTrue(status_report["chain_valid"])

        # Inspection changed nothing: same bytes, still no columns.
        self.assertEqual(
            digest_before, hashlib.sha256(state_path.read_bytes()).hexdigest()
        )
        self.assertNotIn("signature", _table_columns(state_path, "audit"))
        self.assertNotIn(
            "parent_directive_hash",
            _table_columns(state_path, "permit_directives"),
        )

    def test_authorize_before_enablement_is_counted_in_legacy_prefix(self):
        # The "lands before the cutoff" order: an authorize that
        # completes fully before enablement starts is counted in the
        # prefix, so its records verify legacy-style afterwards.
        # (3 seeded + 2 from authorize + 1 from consume = 6.)
        self.init_trusted()
        self._downgrade_to_legacy()
        self._append_unsigned_records(3)
        _, permit_path = self.authorize_ok()
        self.consume(permit_path)
        exit_code, report = self.enable_signing()
        self.assertEqual(0, exit_code, report)
        self.assertEqual(6, report["audit_signing"]["legacy_records"])
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertTrue(verify_report["chain_valid"])
        self.assertEqual(6, verify_report["audit_signing"]["unsigned_records"])
        self.assertEqual(0, verify_report["audit_signing"]["signed_records"])

    def test_enable_signing_serialized_against_concurrent_authorize(self):
        # Deterministic interleaving for the P1 #2 race: a real
        # authorize in a separate process starts between enablement's
        # cutoff read and its config save. With the deployment lock it
        # cannot land unsigned past the cutoff — it waits for
        # enablement, reads the new config, and signs its records.
        self.init_trusted()
        self._downgrade_to_legacy()
        self._append_unsigned_records(3)
        self.mint_envelope(self.intent(cost=100))
        race_out = self.root / "race-authorize.json"
        real_save = ops_module._save_config
        spawned: dict[str, object] = {}

        def save_with_race(directory, config):
            if "proc" not in spawned:
                handle = race_out.open("w", encoding="utf-8")
                spawned["proc"] = subprocess.Popen(
                    [sys.executable, "-m", "pulpo.ops", "authorize",
                     str(self.deployment), "--envelope",
                     str(self.envelope_path),
                     "--principal", PRINCIPAL, "--action", ACTION,
                     "--resource", RESOURCE, "--cost", "100",
                     "--session-id", SESSION_ID],
                    cwd=str(REPO_ROOT), env=dict(os.environ),
                    stdout=handle, stderr=subprocess.STDOUT,
                )
                spawned["handle"] = handle
            return real_save(directory, config)

        with mock.patch.object(
            ops_module, "_save_config", side_effect=save_with_race
        ):
            exit_code, enable_report = self.enable_signing()
        self.assertEqual(0, exit_code, enable_report)
        self.assertEqual(3, enable_report["audit_signing"]["legacy_records"])
        proc = spawned["proc"]
        self.assertEqual(0, proc.wait(timeout=60))
        spawned["handle"].close()
        race_report = json.loads(race_out.read_text(encoding="utf-8"))
        self.assertTrue(race_report["ok"], race_report)
        # The racing authorize's two records are signed, not stranded
        # unsigned past the prefix — verify passes afterwards.
        exit_code, verify_report = self.verify()
        self.assertEqual(0, exit_code, verify_report)
        self.assertTrue(verify_report["chain_valid"])
        self.assertEqual(3, verify_report["audit_signing"]["legacy_records"])
        self.assertEqual(2, verify_report["audit_signing"]["signed_records"])
        self.assertEqual(3, verify_report["audit_signing"]["unsigned_records"])

    def test_deployment_lock_blocks_concurrent_authorize(self):
        # Holding the lock externally blocks a separate process's
        # authorize until the lock is released — the cross-process
        # guarantee the enablement serialization rests on.
        self.init_trusted()
        self.mint_envelope(self.intent(cost=100))
        race_out = self.root / "blocked-authorize.json"
        with _DeploymentLock(self.deployment):
            with race_out.open("w", encoding="utf-8") as handle:
                proc = subprocess.Popen(
                    [sys.executable, "-m", "pulpo.ops", "authorize",
                     str(self.deployment), "--envelope",
                     str(self.envelope_path),
                     "--principal", PRINCIPAL, "--action", ACTION,
                     "--resource", RESOURCE, "--cost", "100",
                     "--session-id", SESSION_ID],
                    cwd=str(REPO_ROOT), env=dict(os.environ),
                    stdout=handle, stderr=subprocess.STDOUT,
                )
            time.sleep(1.5)
            self.assertIsNone(proc.poll(), "authorize completed while the lock was held")
        self.assertEqual(0, proc.wait(timeout=60))
        race_report = json.loads(race_out.read_text(encoding="utf-8"))
        self.assertTrue(race_report["ok"], race_report)

    def test_projections_do_not_create_lock_file(self):
        self.init_trusted()
        self._downgrade_to_legacy()
        self._append_unsigned_records(2)
        exit_code, _ = self.verify()
        self.assertEqual(0, exit_code)
        exit_code, _ = self.status()
        self.assertEqual(0, exit_code)
        self.assertFalse((self.deployment / OPS_LOCK_FILENAME).exists())

    def test_mutating_commands_create_owner_only_lock_file(self):
        self.init_trusted()
        _, _ = self.authorize_ok()
        lock_path = self.deployment / OPS_LOCK_FILENAME
        self.assertTrue(lock_path.is_file())
        self.assertEqual(0o600, stat.S_IMODE(lock_path.stat().st_mode))


class ProjectionMigrationStateTests(unittest.TestCase):
    """State-level pins for the P1 #1 migration gate."""

    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

    def test_read_only_open_does_not_migrate_and_reads_legacy_records(self):
        _build_true_legacy_db(self.path, 3)
        digest_before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        state = SQLiteKernelState(self.path, migrate_schema=False)
        try:
            self.assertNotIn("signature", _table_columns(self.path, "audit"))
            self.assertEqual(3, len(state.audit))
            self.assertTrue(kernel_for(state).verify_audit())
        finally:
            state.close()
        self.assertEqual(
            digest_before, hashlib.sha256(self.path.read_bytes()).hexdigest()
        )

    def test_default_open_migrates_legacy_database(self):
        _build_true_legacy_db(self.path, 3)
        state = SQLiteKernelState(self.path)
        try:
            self.assertIn("signature", _table_columns(self.path, "audit"))
            self.assertEqual(3, len(state.audit))
            self.assertTrue(kernel_for(state).verify_audit())
        finally:
            state.close()

    def test_read_only_open_of_missing_state_fails_closed_without_creating_it(self):
        missing = self.path.with_name(self.path.name + "-absent.sqlite3")
        self.addCleanup(lambda: missing.unlink(missing_ok=True))
        with self.assertRaises(sqlite3.OperationalError):
            SQLiteKernelState(missing, migrate_schema=False)
        self.assertFalse(missing.exists())

    def test_append_with_signer_without_signature_column_fails_loudly(self):
        _build_true_legacy_db(self.path, 3)
        state = SQLiteKernelState(
            self.path, audit_signer=AuditSigner(AUDIT_SECRET),
            migrate_schema=False,
        )
        try:
            with self.assertRaises(RuntimeError):
                state.append(
                    "decision",
                    {"outcome": "allow", "reason": "policy_satisfied",
                     "intent_hash": "f" * 64},
                    NOW,
                )
            self.assertEqual(3, len(state.audit))
        finally:
            state.close()

    def test_unsigned_append_through_read_only_open_fails_loudly(self):
        # A read-only open cannot write at all: an unsigned append
        # fails loudly instead of landing anywhere, and adds nothing.
        _build_true_legacy_db(self.path, 3)
        state = SQLiteKernelState(self.path, migrate_schema=False)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                state.append(
                    "decision",
                    {"outcome": "allow", "reason": "policy_satisfied",
                     "intent_hash": "f" * 64},
                    NOW,
                )
            self.assertEqual(3, len(state.audit))
        finally:
            state.close()


if __name__ == "__main__":
    unittest.main()

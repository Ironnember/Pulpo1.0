"""Developer trio, item 3: offline evidence verification, exercised.

These tests execute the two verification snippets published in
docs/evidence-and-audit.md, verbatim in logic, against real kernel
artifacts:

1. ``verify_state_file`` — the repository's endorsed pattern (as in
   examples/wire_authorization/check_evidence.py): verify a snapshot
   copy of a deployment's SQLite state through a verifier kernel, so
   the artifact under examination is never opened writable and the
   chain math is the kernel's own, not a second implementation.
2. ``verify_exported_records`` — recompute the unkeyed SHA-256 chain
   from exported audit records alone. This is the only keyless check
   available for a *signed* deployment, and its boundary is pinned
   here: it proves internal consistency of the records shown, not
   their signatures and not the chain's completeness.

The signed-deployment tests pin the honest limit the doc states:
verifying record signatures requires the deployment's audit secret
(the signer is HMAC-SHA256, symmetric — there is no public key to
publish today), and a verifier kernel constructed without it over a
signed chain fails closed instead of waving the records through.
"""

from __future__ import annotations

from hashlib import sha256
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.kernel import StateIntegrityError
from pulpo.state import AuditSigner, SQLiteKernelState

SECRET = b"kernel" + b"-secret"
AUDIT_SECRET = b"audit" + b"-secret"
OTHER_AUDIT_SECRET = b"other-audit" + b"-secret"
INTENT = Intent("agent:builder", "write", "repo:core", 3, "s1")


def verify_state_file(state_path, *, audit_signer=None):
    """Snippet 1 (docs/evidence-and-audit.md): offline state verification.

    Verifies a snapshot copy of the state file; the original is only
    ever read. The snapshot is taken with SQLite's backup API, not a
    file copy: a deployment in WAL mode can hold committed records
    only in the ``-wal`` sidecar, and copying the main file alone
    would omit them — a truncated chain verifies on its own internal
    terms. The backup API yields one consistent snapshot including
    WAL contents, even while the writer connection is still open.
    Kernel construction itself verifies the chain and raises
    ``StateIntegrityError`` on an invalid one — that raise IS the
    negative verdict, not an error path around it.
    """

    with tempfile.TemporaryDirectory() as snapshot_dir:
        snapshot = Path(snapshot_dir) / "state.db"
        source = sqlite3.connect(
            f"{Path(state_path).resolve().as_uri()}?mode=ro", uri=True
        )
        try:
            destination = sqlite3.connect(snapshot)
            try:
                source.backup(destination)
            finally:
                destination.close()
        finally:
            source.close()
        state = SQLiteKernelState(snapshot, audit_signer=audit_signer, migrate_schema=False)
        try:
            kernel = GovernanceKernel(
                Policy(allowed_actions=frozenset({"verify"}), max_cost=0),
                state=state,
            )
            return kernel.verify_audit_report()
        finally:
            state.close()


def verify_exported_records(records):
    """Snippet 2 (docs/evidence-and-audit.md): recompute the chain.

    Pure hashlib/json over the exported records: each record's hash is
    the SHA-256 of its canonical body (every field except ``hash`` and
    ``signature``), chained by ``previous_hash`` from the genesis
    value. Returns True only if every link recomputes exactly.
    """

    previous = "0" * 64
    for record in records:
        body = {key: value for key, value in record.items() if key not in ("hash", "signature")}
        if body.get("previous_hash") != previous:
            return False
        expected = sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if expected != record.get("hash"):
            return False
        previous = record["hash"]
    return True


def build_open_wal_deployment(path, *, audit_signer=None):
    """A WAL-mode deployment whose records live only in the -wal sidecar.

    Returns ``(state, records)`` with the writer connection still open:
    autocheckpoint is disabled and a TRUNCATE checkpoint is taken
    before any governed action, so every audit record the kernel then
    appends is committed but uncheckpointed — present in
    ``state.db-wal``, absent from the main database file. The caller
    must close the returned state.
    """

    state = SQLiteKernelState(path, audit_signer=audit_signer)
    state._connection.execute("PRAGMA journal_mode = WAL")
    state._connection.execute("PRAGMA wal_autocheckpoint = 0")
    state._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    kernel = GovernanceKernel(
        Policy(frozenset({"write"}), 100),
        SECRET,
        state=state,
    )
    decision = kernel.evaluate(INTENT)
    assert decision.outcome == "allow" and decision.permit is not None
    assert kernel.consume(decision.permit, INTENT) is True
    assert kernel.consume(decision.permit, INTENT) is False  # replay: recorded refusal
    denied = kernel.evaluate(Intent("agent:builder", "write", "repo:core", 10_000, "s1"))
    assert denied.outcome == "deny"
    records = [dict(record) for record in kernel.audit]
    return state, records


def build_deployment(path, *, audit_signer=None):
    """A small real deployment: one allow+consume, one denial, one replay."""

    state = SQLiteKernelState(path, audit_signer=audit_signer)
    kernel = GovernanceKernel(
        Policy(frozenset({"write"}), 100),
        SECRET,
        state=state,
    )
    decision = kernel.evaluate(INTENT)
    assert decision.outcome == "allow" and decision.permit is not None
    assert kernel.consume(decision.permit, INTENT) is True
    assert kernel.consume(decision.permit, INTENT) is False  # replay: recorded refusal
    denied = kernel.evaluate(Intent("agent:builder", "write", "repo:core", 10_000, "s1"))
    assert denied.outcome == "deny"
    records = [dict(record) for record in kernel.audit]
    state.close()
    return records


class UnsignedDeploymentTests(unittest.TestCase):
    def test_snapshot_verification_passes_and_counts_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            records = build_deployment(path)
            report = verify_state_file(path)
            self.assertTrue(report["ok"])
            self.assertEqual(report["total_records"], len(records))
            self.assertFalse(report["signing_enabled"])
            events = [record["event"] for record in records]
            # Allowances and refusals are both in the evidence.
            self.assertIn("permit_consumed", events)
            self.assertIn("permit_rejected", events)
            self.assertIn("decision", events)

    def test_tampered_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            build_deployment(path)
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE audit SET payload_json = ? WHERE sequence = 1",
                (json.dumps({"outcome": "allow", "reason": "forged", "intent_hash": "0" * 64}),),
            )
            connection.commit()
            connection.close()
            with self.assertRaises(StateIntegrityError):
                verify_state_file(path)


class WalDeploymentTests(unittest.TestCase):
    def test_snapshot_includes_committed_wal_records_while_writer_open(self):
        # Regression (Codex P1, PR #419, Finding 8): a deployment in
        # SQLite WAL mode can hold committed audit records only in the
        # -wal sidecar. Snapshotting the main file alone verifies a
        # truncated — here empty — chain on its own internal terms
        # while omitting committed evidence. The snapshot must carry
        # the full history even while the writer is still open.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            state, records = build_open_wal_deployment(path)
            try:
                wal_sidecar = Path(str(path) + "-wal")
                self.assertTrue(wal_sidecar.exists())
                self.assertGreater(wal_sidecar.stat().st_size, 0)
                report = verify_state_file(path)
            finally:
                state.close()
            self.assertTrue(report["ok"])
            self.assertEqual(report["total_records"], len(records))
            self.assertGreater(len(records), 0)


class ExportedRecordTests(unittest.TestCase):
    def test_chain_recomputation_passes_on_real_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = build_deployment(Path(tmp) / "state.db")
            self.assertTrue(verify_exported_records(records))

    def test_chain_recomputation_detects_payload_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = build_deployment(Path(tmp) / "state.db")
            forged = [dict(record) for record in records]
            forged[1] = dict(forged[1], payload=dict(forged[1]["payload"], reason="forged"))
            self.assertFalse(verify_exported_records(forged))

    def test_chain_recomputation_detects_record_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = build_deployment(Path(tmp) / "state.db")
            self.assertFalse(verify_exported_records(records[:1] + records[2:]))


class SignedDeploymentTests(unittest.TestCase):
    def test_signatures_verify_with_the_deployment_signer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            records = build_deployment(path, audit_signer=AuditSigner(AUDIT_SECRET))
            report = verify_state_file(path, audit_signer=AuditSigner(AUDIT_SECRET))
            self.assertTrue(report["ok"])
            self.assertTrue(report["signing_enabled"])
            self.assertEqual(report["signed_records"], len(records))
            # The keyless chain check also passes: hashes are unkeyed.
            self.assertTrue(verify_exported_records(records))

    def test_wrong_audit_secret_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            build_deployment(path, audit_signer=AuditSigner(AUDIT_SECRET))
            with self.assertRaises(StateIntegrityError):
                verify_state_file(path, audit_signer=AuditSigner(OTHER_AUDIT_SECRET))

    def test_keyless_kernel_verification_of_signed_chain_fails_closed(self):
        # A third party without the audit secret cannot use the kernel
        # verifier on a signed chain: a present signature with no
        # signer to check it against is refused, not ignored. The
        # keyless path for signed deployments is chain recomputation
        # (above), with its stated boundary.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            build_deployment(path, audit_signer=AuditSigner(AUDIT_SECRET))
            with self.assertRaises(StateIntegrityError):
                verify_state_file(path)


if __name__ == "__main__":
    unittest.main()

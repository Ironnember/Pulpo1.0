import hashlib
import hmac
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from pulpo import (
    ApprovalEnvelope,
    GovernanceKernel,
    Intent,
    Policy,
    SQLiteKernelState,
    StateIntegrityError,
)


NOW = 1_000_000


class HmacTestVerifier:
    authority_id = "authority:test-owner"

    def __init__(self, secret=b"external-test-authority"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def signed_envelope(kernel, intent, verifier, *, approval_id="approval-1", nonce="nonce-1"):
    unsigned = ApprovalEnvelope(
        approval_id=approval_id,
        authority_id=verifier.authority_id,
        session_id=intent.session_id,
        principal=intent.principal,
        intent_hash=kernel.intent_hash(intent),
        policy_hash=kernel.policy_hash,
        nonce=nonce,
        expires_at_ns=NOW + 1_000,
        signature="",
    )
    return replace(unsigned, signature=verifier.sign(unsigned.signing_bytes()))


class RestartSafeStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "kernel.sqlite3"
        self.policy = Policy(frozenset({"push"}), 100, frozenset({"push"}))
        self.verifier = HmacTestVerifier()
        self.intent = Intent("agent:publisher", "push", "repo:origin/main", 0, "session-1")

    def kernel(self, state):
        return GovernanceKernel(
            self.policy,
            secret=b"permit-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=state,
        )

    def test_approval_and_permit_replay_remain_denied_after_restart(self):
        first_state = SQLiteKernelState(self.path)
        first_kernel = self.kernel(first_state)
        envelope = signed_envelope(first_kernel, self.intent, self.verifier)
        decision = first_kernel.evaluate_with_approval(self.intent, envelope)
        self.assertEqual("allow", decision.outcome)
        first_length = len(first_kernel.audit)
        first_state.close()

        restarted_state = SQLiteKernelState(self.path)
        self.addCleanup(restarted_state.close)
        restarted_kernel = self.kernel(restarted_state)
        self.assertTrue(restarted_kernel.verify_audit())
        self.assertEqual(
            "approval_id_replayed",
            restarted_kernel.evaluate_with_approval(self.intent, envelope).reason,
        )
        same_nonce = signed_envelope(
            restarted_kernel,
            self.intent,
            self.verifier,
            approval_id="approval-2",
            nonce=envelope.nonce,
        )
        self.assertEqual(
            "approval_nonce_replayed",
            restarted_kernel.evaluate_with_approval(self.intent, same_nonce).reason,
        )
        self.assertFalse(
            restarted_kernel.consume(
                decision.permit,
                replace(self.intent, resource="repo:other"),
            )
        )
        self.assertTrue(restarted_kernel.consume(decision.permit, self.intent))
        self.assertGreater(len(restarted_kernel.audit), first_length)
        self.assertTrue(restarted_kernel.verify_audit())
        restarted_state.close()

        final_state = SQLiteKernelState(self.path)
        self.addCleanup(final_state.close)
        final_kernel = self.kernel(final_state)
        self.assertFalse(final_kernel.consume(decision.permit, self.intent))
        self.assertTrue(final_kernel.verify_audit())

    def test_verified_approval_and_permit_are_committed_with_one_transaction(self):
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        envelope = signed_envelope(kernel, self.intent, self.verifier)
        decision = kernel.evaluate_with_approval(self.intent, envelope)

        connection = sqlite3.connect(self.path)
        self.addCleanup(connection.close)
        self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
        self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
        self.assertEqual(
            ["approval_verified", "decision"],
            [row[0] for row in connection.execute("SELECT event FROM audit ORDER BY sequence")],
        )
        self.assertTrue(kernel.consume(decision.permit, self.intent))

    def test_failed_audit_write_rolls_back_approval_and_permit(self):
        state = SQLiteKernelState(self.path)
        self.addCleanup(state.close)
        kernel = self.kernel(state)
        envelope = signed_envelope(kernel, self.intent, self.verifier)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_verified_audit
                BEFORE INSERT ON audit
                WHEN NEW.event = 'approval_verified'
                BEGIN
                    SELECT RAISE(ABORT, 'forced audit failure');
                END
                """
            )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "forced audit failure"):
            kernel.evaluate_with_approval(self.intent, envelope)

        with sqlite3.connect(self.path) as connection:
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0])

    def test_tampered_persisted_audit_fails_closed_at_restart(self):
        state = SQLiteKernelState(self.path)
        kernel = self.kernel(state)
        kernel.evaluate_with_approval(
            self.intent,
            signed_envelope(kernel, self.intent, self.verifier),
        )
        state.close()

        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE audit SET payload_json = ? WHERE sequence = 1", ('{"changed":true}',))

        tampered_state = SQLiteKernelState(self.path)
        self.addCleanup(tampered_state.close)
        with self.assertRaisesRegex(StateIntegrityError, "audit chain"):
            self.kernel(tampered_state)


if __name__ == "__main__":
    unittest.main()

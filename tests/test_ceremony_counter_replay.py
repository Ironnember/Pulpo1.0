"""Durable authenticator counter replay checks for ceremony-required approvals.

These are synthetic kernel/storage tests. They do not prove WebAuthn signature
verification, authenticator custody, enrollment, recovery, or deployment.
"""

import hashlib
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path

from pulpo import (
    CeremonyProof,
    CeremonyTrust,
    CeremonyVerification,
    GovernanceKernel,
    Intent,
    Policy,
    SQLiteKernelState,
    expected_ceremony_challenge,
)
from pulpo.state import ApprovalUse, InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 3_000_000
CREDENTIAL_ID = "credential:counter-primary"
CREDENTIAL_HASH = hashlib.sha256(CREDENTIAL_ID.encode()).hexdigest()


class CounterCeremonyVerifier:
    verifier_id = "ceremony-verifier:counter-v0"
    rp_id = "example.com"
    origin = "https://authority.example.com"
    credential_set_hash = CREDENTIAL_HASH

    def __init__(self, sign_count, *, barrier=None):
        self.sign_count = sign_count
        self.barrier = barrier

    def verify(self, proof, *, expected_challenge):
        if proof.assertion != expected_challenge.hex():
            raise ValueError("challenge mismatch")
        if self.barrier is not None:
            self.barrier.wait(2)
        return CeremonyVerification(
            credential_id=proof.credential_id,
            user_present=True,
            user_verified=True,
            backup_eligible=False,
            backed_up=False,
            new_sign_count=self.sign_count,
        )


class CeremonyCounterReplayTests(unittest.TestCase):
    def setUp(self):
        self.signer = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"push"}),
            0,
            frozenset({"push"}),
            authority_trust=trust_for(self.signer),
            ceremony_actions=frozenset({"push"}),
            ceremony_trust=CeremonyTrust(
                CounterCeremonyVerifier.verifier_id,
                CounterCeremonyVerifier.rp_id,
                CounterCeremonyVerifier.origin,
                CounterCeremonyVerifier.credential_set_hash,
            ),
        )
        self.intent = Intent(
            "agent:publisher",
            "push",
            "repo:Ironnember/Pulpo1.0:refs/heads/main",
            0,
            "ceremony-counter-session",
        )

    def kernel(self, verifier, *, state=None):
        return GovernanceKernel(
            self.policy,
            secret=b"ceremony-counter-replay",
            approval_verifier=self.signer,
            ceremony_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )

    def envelope_and_proof(self, kernel, suffix):
        envelope = signed_envelope(
            kernel,
            self.intent,
            self.signer,
            now_ns=NOW,
            approval_id=f"approval:{suffix}",
            nonce=f"nonce:{suffix}",
        )
        request_id = f"request:{suffix}"
        proof = CeremonyProof(
            request_id,
            CREDENTIAL_ID,
            expected_ceremony_challenge(envelope, request_id).hex(),
        )
        return envelope, proof

    def test_same_or_regressed_counter_fails_and_higher_counter_advances(self):
        verifier = CounterCeremonyVerifier(5)
        kernel = self.kernel(verifier)

        first = self.envelope_and_proof(kernel, "first")
        self.assertEqual("allow", kernel.evaluate_with_approval(self.intent, *first).outcome)

        repeated = self.envelope_and_proof(kernel, "repeated")
        repeated_decision = kernel.evaluate_with_approval(self.intent, *repeated)
        self.assertEqual(
            ("deny", "approval_ceremony_sign_count_replayed"),
            (repeated_decision.outcome, repeated_decision.reason),
        )

        verifier.sign_count = 4
        regressed = self.envelope_and_proof(kernel, "regressed")
        self.assertEqual(
            "approval_ceremony_sign_count_replayed",
            kernel.evaluate_with_approval(self.intent, *regressed).reason,
        )

        verifier.sign_count = 6
        advanced = self.envelope_and_proof(kernel, "advanced")
        self.assertEqual("allow", kernel.evaluate_with_approval(self.intent, *advanced).outcome)
        verified = [
            record["payload"]
            for record in kernel.audit
            if record["event"] == "approval_verified"
        ]
        self.assertEqual([None, 5], [item["ceremony_previous_sign_count"] for item in verified])
        self.assertEqual([5, 6], [item["ceremony_sign_count"] for item in verified])

    def test_zero_counter_fails_closed_without_issuing_permit(self):
        kernel = self.kernel(CounterCeremonyVerifier(0))
        envelope, proof = self.envelope_and_proof(kernel, "zero")

        decision = kernel.evaluate_with_approval(self.intent, envelope, proof)

        self.assertEqual(
            ("deny", "approval_ceremony_sign_count_unavailable"),
            (decision.outcome, decision.reason),
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(any(record["event"] == "approval_verified" for record in kernel.audit))

    def test_malformed_counter_commit_inputs_fail_closed_without_state_change(self):
        malformed = (
            ApprovalUse(
                "approval:missing-explicit",
                "nonce:missing-explicit",
                {
                    "ceremony_credential_id_hash": CREDENTIAL_HASH,
                    "ceremony_sign_count": 5,
                },
            ),
            ApprovalUse(
                "approval:invalid-hash",
                "nonce:invalid-hash",
                {
                    "ceremony_credential_id_hash": "not-a-hash",
                    "ceremony_sign_count": 5,
                },
                ceremony_credential_id_hash="not-a-hash",
                ceremony_sign_count=5,
            ),
            ApprovalUse(
                "approval:boolean-count",
                "nonce:boolean-count",
                {
                    "ceremony_credential_id_hash": CREDENTIAL_HASH,
                    "ceremony_sign_count": True,
                },
                ceremony_credential_id_hash=CREDENTIAL_HASH,
                ceremony_sign_count=True,
            ),
            ApprovalUse(
                "approval:payload-substitution",
                "nonce:payload-substitution",
                {
                    "ceremony_credential_id_hash": CREDENTIAL_HASH,
                    "ceremony_sign_count": 6,
                },
                ceremony_credential_id_hash=CREDENTIAL_HASH,
                ceremony_sign_count=5,
            ),
        )

        for approval in malformed:
            with self.subTest(approval=approval.approval_id):
                state = InMemoryKernelState()
                self.assertEqual(
                    "approval_ceremony_counter_invalid",
                    state.issue_permit("permit", "intent", "verified_approval", NOW, approval),
                )
                self.assertEqual([], state.audit)

    def test_counter_replay_is_denied_after_sqlite_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            first_state = SQLiteKernelState(path)
            first_kernel = self.kernel(CounterCeremonyVerifier(5), state=first_state)
            first = self.envelope_and_proof(first_kernel, "before-restart")
            self.assertEqual("allow", first_kernel.evaluate_with_approval(self.intent, *first).outcome)
            first_state.close()

            restarted_state = SQLiteKernelState(path)
            self.addCleanup(restarted_state.close)
            replay_kernel = self.kernel(CounterCeremonyVerifier(5), state=restarted_state)
            replay = self.envelope_and_proof(replay_kernel, "after-restart-replay")
            self.assertEqual(
                "approval_ceremony_sign_count_replayed",
                replay_kernel.evaluate_with_approval(self.intent, *replay).reason,
            )

            advanced_kernel = self.kernel(CounterCeremonyVerifier(6), state=restarted_state)
            advanced = self.envelope_and_proof(advanced_kernel, "after-restart-advance")
            self.assertEqual("allow", advanced_kernel.evaluate_with_approval(self.intent, *advanced).outcome)
            self.assertEqual(
                [5, 6],
                [
                    record["payload"]["ceremony_sign_count"]
                    for record in restarted_state.audit
                    if record["event"] == "approval_verified"
                ],
            )
            restarted_state.close()

    def test_pre_repair_audit_counter_is_used_as_migration_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            historical_state = SQLiteKernelState(path)
            historical_state.append(
                "approval_verified",
                {
                    "approval_id": "approval:historical",
                    "ceremony_credential_id_hash": CREDENTIAL_HASH,
                    "ceremony_sign_count": 5,
                },
                NOW - 1,
            )
            historical_state.close()

            state = SQLiteKernelState(path)
            self.addCleanup(state.close)
            replay_kernel = self.kernel(CounterCeremonyVerifier(5), state=state)
            replay = self.envelope_and_proof(replay_kernel, "migration-replay")
            self.assertEqual(
                "approval_ceremony_sign_count_replayed",
                replay_kernel.evaluate_with_approval(self.intent, *replay).reason,
            )

            advanced_kernel = self.kernel(CounterCeremonyVerifier(6), state=state)
            advanced = self.envelope_and_proof(advanced_kernel, "migration-advance")
            self.assertEqual("allow", advanced_kernel.evaluate_with_approval(self.intent, *advanced).outcome)
            state.close()

    def test_malformed_canonical_counter_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            historical_state = SQLiteKernelState(path)
            historical_state.append(
                "approval_verified",
                {
                    "approval_id": "approval:malformed-counter",
                    "ceremony_credential_id_hash": CREDENTIAL_HASH,
                    "ceremony_sign_count": "five",
                },
                NOW - 1,
            )
            historical_state.close()

            state = SQLiteKernelState(path)
            self.addCleanup(state.close)
            kernel = self.kernel(CounterCeremonyVerifier(6), state=state)
            envelope, proof = self.envelope_and_proof(kernel, "malformed-counter")
            self.assertEqual(
                "approval_ceremony_counter_invalid",
                kernel.evaluate_with_approval(self.intent, envelope, proof).reason,
            )
            state.close()

    def test_concurrent_equal_counters_allow_exactly_one_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            signing_kernel = self.kernel(CounterCeremonyVerifier(5))
            cases = [
                self.envelope_and_proof(signing_kernel, "concurrent-one"),
                self.envelope_and_proof(signing_kernel, "concurrent-two"),
            ]
            barrier = threading.Barrier(2)
            results = []
            errors = []

            def evaluate(case):
                state = SQLiteKernelState(path)
                try:
                    kernel = self.kernel(CounterCeremonyVerifier(5, barrier=barrier), state=state)
                    results.append(kernel.evaluate_with_approval(self.intent, *case))
                except Exception as exc:
                    errors.append(exc)
                finally:
                    state.close()

            threads = [threading.Thread(target=evaluate, args=(case,)) for case in cases]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(3)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual([], errors)
            self.assertEqual(["allow", "deny"], sorted(result.outcome for result in results))
            self.assertEqual(
                ["approval_ceremony_sign_count_replayed"],
                [result.reason for result in results if result.outcome == "deny"],
            )
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
                self.assertEqual(
                    1,
                    connection.execute(
                        "SELECT COUNT(*) FROM audit WHERE event = 'approval_verified'"
                    ).fetchone()[0],
                )

    def test_failed_audit_write_rolls_back_counter_approval_and_permit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            state = SQLiteKernelState(path)
            self.addCleanup(state.close)
            kernel = self.kernel(CounterCeremonyVerifier(5), state=state)
            envelope, proof = self.envelope_and_proof(kernel, "rollback")
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    """
                    CREATE TRIGGER reject_counter_audit
                    BEFORE INSERT ON audit
                    WHEN NEW.event = 'approval_verified'
                    BEGIN
                        SELECT RAISE(ABORT, 'forced ceremony audit failure');
                    END
                    """
                )

            with self.assertRaisesRegex(sqlite3.IntegrityError, "forced ceremony audit failure"):
                kernel.evaluate_with_approval(self.intent, envelope, proof)

            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0])
                self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM permits").fetchone()[0])
                self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0])


if __name__ == "__main__":
    unittest.main()

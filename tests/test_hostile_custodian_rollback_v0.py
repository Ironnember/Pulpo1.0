from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import shutil
import sqlite3
import tempfile
import unittest

from pulpo.kernel import AgentGrant, GovernanceKernel, Intent, Policy
from pulpo.state import SQLiteKernelState


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class FixedClock:
    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns


class StateCommitmentWitness:
    """Proof-only external commitment; it carries no authority or execution key."""

    @staticmethod
    def commitment(path: Path) -> str:
        connection = sqlite3.connect(path)
        try:
            permits = connection.execute(
                "SELECT permit, intent_hash, spent FROM permits ORDER BY permit"
            ).fetchall()
            audit_row = connection.execute(
                "SELECT COUNT(*), COALESCE((SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1), ?) FROM audit",
                ("0" * 64,),
            ).fetchone()
            directives = connection.execute(
                "SELECT directive_id, version, directive_hash, revoked FROM directives ORDER BY directive_id, version"
            ).fetchall()
            approvals = connection.execute(
                "SELECT approval_id, nonce FROM approvals ORDER BY approval_id"
            ).fetchall()
        finally:
            connection.close()
        payload = {
            "schema": "pulpo.hostile-custodian-state-commitment.proof.v0",
            "permits": permits,
            "audit_count": int(audit_row[0]),
            "audit_head": str(audit_row[1]),
            "directives": directives,
            "approvals": approvals,
        }
        return sha256(_canonical(payload)).hexdigest()


class HostileCustodianRollbackProof(unittest.TestCase):
    SECRET = b"pulpo-hostile-custodian-proof-secret-v0"
    ISSUE_TIME = 1_900_000_000_000_000_000
    CONSUME_TIME = ISSUE_TIME + 100

    @staticmethod
    def policy() -> Policy:
        return Policy(
            allowed_actions=frozenset({"write"}),
            max_cost=10,
            agent_grants=(
                AgentGrant(
                    principal="worker:rollback-proof",
                    allowed_actions=frozenset({"write"}),
                    resource_prefixes=("proof:rollback:",),
                    max_cost=10,
                ),
            ),
        )

    @staticmethod
    def intent() -> Intent:
        return Intent(
            "worker:rollback-proof",
            "write",
            "proof:rollback:effect",
            1,
            "session:rollback-proof",
        )

    def issue_snapshot(self, directory: Path) -> tuple[Path, Path, str, str]:
        db_path = directory / "kernel.sqlite3"
        snapshot_path = directory / "pre-consume.sqlite3"
        state = SQLiteKernelState(db_path)
        kernel = GovernanceKernel(
            self.policy(),
            secret=self.SECRET,
            state=state,
            clock=FixedClock(self.ISSUE_TIME),
        )
        decision = kernel.evaluate(self.intent())
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)
        self.assertTrue(kernel.verify_audit())
        issue_head = state.audit[-1]["hash"]
        permit = str(decision.permit)
        state.close()
        shutil.copy2(db_path, snapshot_path)
        return db_path, snapshot_path, permit, issue_head

    def consume_once(self, path: Path, permit: str, *, now_ns: int | None = None) -> tuple[bool, str, str]:
        state = SQLiteKernelState(path)
        kernel = GovernanceKernel(
            self.policy(),
            secret=self.SECRET,
            state=state,
            clock=FixedClock(now_ns or self.CONSUME_TIME),
        )
        self.assertTrue(kernel.verify_audit())
        consumed = kernel.consume(permit, self.intent())
        self.assertTrue(kernel.verify_audit())
        head = state.audit[-1]["hash"]
        commitment = StateCommitmentWitness.commitment(path)
        state.close()
        return consumed, head, commitment

    def test_whole_state_snapshot_rollback_resurrects_spent_execution_right(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            db_path, snapshot, permit, issue_head = self.issue_snapshot(directory)
            first, spent_head, _ = self.consume_once(db_path, permit)
            self.assertTrue(first)
            self.assertNotEqual(spent_head, issue_head)

            shutil.copy2(snapshot, db_path)
            rolled_state = SQLiteKernelState(db_path)
            rolled_kernel = GovernanceKernel(
                self.policy(),
                secret=self.SECRET,
                state=rolled_state,
                clock=FixedClock(self.CONSUME_TIME),
            )
            self.assertTrue(rolled_kernel.verify_audit())
            self.assertEqual(rolled_state.audit[-1]["hash"], issue_head)
            second = rolled_kernel.consume(permit, self.intent())
            self.assertTrue(second)
            self.assertTrue(rolled_kernel.verify_audit())
            rolled_state.close()

    def test_two_forked_valid_snapshots_each_consume_the_same_one_use_permit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            _, snapshot, permit, _ = self.issue_snapshot(directory)
            fork_a = directory / "fork-a.sqlite3"
            fork_b = directory / "fork-b.sqlite3"
            shutil.copy2(snapshot, fork_a)
            shutil.copy2(snapshot, fork_b)

            consumed_a, head_a, _ = self.consume_once(fork_a, permit)
            consumed_b, head_b, _ = self.consume_once(fork_b, permit)
            self.assertTrue(consumed_a)
            self.assertTrue(consumed_b)
            # Identical transition inputs produce identical internally valid heads,
            # even though two isolated custodians each regained the one-use right.
            self.assertEqual(head_a, head_b)

    def test_divergent_forks_can_both_be_internally_valid(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            _, snapshot, permit, _ = self.issue_snapshot(directory)
            fork_a = directory / "fork-a.sqlite3"
            fork_b = directory / "fork-b.sqlite3"
            shutil.copy2(snapshot, fork_a)
            shutil.copy2(snapshot, fork_b)

            consumed_a, head_a, _ = self.consume_once(fork_a, permit, now_ns=self.CONSUME_TIME)
            consumed_b, head_b, _ = self.consume_once(fork_b, permit, now_ns=self.CONSUME_TIME + 1)
            self.assertTrue(consumed_a)
            self.assertTrue(consumed_b)
            self.assertNotEqual(head_a, head_b)

            for path in (fork_a, fork_b):
                state = SQLiteKernelState(path)
                kernel = GovernanceKernel(
                    self.policy(),
                    secret=self.SECRET,
                    state=state,
                    clock=FixedClock(self.CONSUME_TIME + 2),
                )
                self.assertTrue(kernel.verify_audit())
                state.close()

    def test_direct_authoritative_table_tamper_is_not_detected_by_audit_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            db_path, _, permit, _ = self.issue_snapshot(directory)
            first, original_head, _ = self.consume_once(db_path, permit)
            self.assertTrue(first)

            connection = sqlite3.connect(db_path)
            try:
                connection.execute("UPDATE permits SET spent = 0 WHERE permit = ?", (permit,))
                connection.commit()
            finally:
                connection.close()

            state = SQLiteKernelState(db_path)
            kernel = GovernanceKernel(
                self.policy(),
                secret=self.SECRET,
                state=state,
                clock=FixedClock(self.CONSUME_TIME + 1),
            )
            # The audit chain itself is untouched and therefore validates, while
            # the authority-bearing permit table has been maliciously regressed.
            self.assertTrue(kernel.verify_audit())
            self.assertEqual(state.audit[-1]["hash"], original_head)
            self.assertTrue(kernel.consume(permit, self.intent()))
            self.assertTrue(kernel.verify_audit())
            state.close()

    def test_external_state_commitment_detects_authoritative_table_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            db_path, _, permit, _ = self.issue_snapshot(directory)
            consumed, _, committed = self.consume_once(db_path, permit)
            self.assertTrue(consumed)

            connection = sqlite3.connect(db_path)
            try:
                connection.execute("UPDATE permits SET spent = 0 WHERE permit = ?", (permit,))
                connection.commit()
            finally:
                connection.close()

            tampered = StateCommitmentWitness.commitment(db_path)
            self.assertNotEqual(committed, tampered)

    def test_external_state_commitment_detects_preconsume_rollback_before_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            db_path, snapshot, permit, _ = self.issue_snapshot(directory)
            consumed, _, spent_commitment = self.consume_once(db_path, permit)
            self.assertTrue(consumed)
            shutil.copy2(snapshot, db_path)
            rolled_commitment = StateCommitmentWitness.commitment(db_path)
            self.assertNotEqual(spent_commitment, rolled_commitment)

    def test_audit_head_only_anchor_cannot_distinguish_identical_fork_replay_after_transition(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            _, snapshot, permit, _ = self.issue_snapshot(directory)
            fork_a = directory / "fork-a.sqlite3"
            fork_b = directory / "fork-b.sqlite3"
            shutil.copy2(snapshot, fork_a)
            shutil.copy2(snapshot, fork_b)
            consumed_a, head_a, commitment_a = self.consume_once(fork_a, permit)
            consumed_b, head_b, commitment_b = self.consume_once(fork_b, permit)
            self.assertTrue(consumed_a)
            self.assertTrue(consumed_b)
            self.assertEqual(head_a, head_b)
            self.assertEqual(commitment_a, commitment_b)
            # A passive witness that only checks the final state/head cannot know
            # that two real releases occurred. Preventing that requires execution
            # to depend on an independently serialized transition/release boundary.


if __name__ == "__main__":
    unittest.main()

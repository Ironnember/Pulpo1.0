"""Writer-custody Phase 1 regressions: kernel-spend authentication,
payload detachment at write, and policy pinning.

Each test converts one reproduction from the 2026-11-12 writer-custody
diagnosis (executed at main 7f2a7c9) into a standing regression. Before
this change every reproduction succeeded; after it, each unmediated write
must fail closed at the kernel boundary:

- Repro A: a permit minted through ``state.issue_permit(approval=None)``
  was consumable through ``GovernanceKernel.consume``.
- Repro B: a permit row inserted by a raw SQLite writer was consumable by
  a fresh kernel. The audit-chain half of Repro B -- honestly recomputed
  forged records verifying clean -- is a *detection* problem whose remedy
  is the anchored head (#352), not this change; what is asserted here is
  the spend refusal. The forged chain still verifies, and the test says
  so, to keep that boundary explicit.
- Repro C: mutating a caller's payload dict after ``append`` /
  ``append_unique`` rewrote the stored in-memory audit record in place.
- Repro D: reassigning ``kernel.policy`` after construction silently
  swapped the evaluation policy (deny became allow) with no audit record.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest

from pulpo.authority import ApprovalEnvelope
from pulpo.kernel import GovernanceKernel, Intent, Policy, StateIntegrityError
from pulpo.ops import KERNEL_SECRET_FILENAME, _deployment_kernel_secret
from pulpo.state import InMemoryKernelState, SQLiteKernelState


_CANONICAL_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"))


def _canonical(value) -> bytes:
    return _CANONICAL_ENCODER.encode(value).encode()


def _chain_record(previous_hash: str, event: str, payload: dict, timestamp_ns: int) -> dict:
    body = {
        "event": event,
        "payload": payload,
        "previous_hash": previous_hash,
        "timestamp_ns": timestamp_ns,
    }
    return {**body, "hash": sha256(_canonical(body)).hexdigest()}


POLICY = Policy(allowed_actions=frozenset({"wire.transfer"}), max_cost=1000)
INTENT = Intent(
    principal="attacker",
    action="wire.transfer",
    resource="acct:1",
    cost=999,
    session_id="s1",
)
SECRET = b"kernel-secret-not-known-to-writer"


def _rejections(state) -> list[dict]:
    return [record for record in state.audit if record["event"] == "permit_rejected"]


class TokenAuthenticationTests(unittest.TestCase):
    """Repro A: state-minted and otherwise unauthenticated permits."""

    def test_state_minted_permit_cannot_be_spent(self) -> None:
        state = InMemoryKernelState()
        kernel = GovernanceKernel(POLICY, secret=SECRET, state=state)
        digest = kernel.intent_hash(INTENT)

        # The writer never calls evaluate(); it uses the state handle
        # directly, approval=None -- the exact Repro A move.
        replay = state.issue_permit(
            "forged-permit-1", digest, "forged_reason", time.time_ns(), approval=None
        )
        self.assertIsNone(replay)

        self.assertFalse(kernel.consume("forged-permit-1", INTENT))
        rejected = _rejections(state)
        self.assertEqual(1, len(rejected))
        self.assertEqual("permit_signature_invalid", rejected[0]["payload"]["reason"])
        self.assertTrue(kernel.verify_audit())

    def test_token_shaped_forgery_cannot_be_spent(self) -> None:
        state = InMemoryKernelState()
        kernel = GovernanceKernel(POLICY, secret=SECRET, state=state)
        digest = kernel.intent_hash(INTENT)
        forged = f"{digest}:{'0' * 32}:{'0' * 64}"
        state.issue_permit(forged, digest, "forged_reason", time.time_ns(), approval=None)
        self.assertFalse(kernel.consume(forged, INTENT))

    def test_token_minted_under_another_secret_cannot_be_spent(self) -> None:
        state = InMemoryKernelState()
        issuer = GovernanceKernel(POLICY, secret=b"issuer-secret", state=state)
        decision = issuer.evaluate(INTENT)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)

        stranger = GovernanceKernel(POLICY, secret=b"other-secret", state=state)
        self.assertFalse(stranger.consume(decision.permit, INTENT))
        # The issuing kernel still honors its own token exactly once.
        self.assertTrue(issuer.consume(decision.permit, INTENT))
        self.assertFalse(issuer.consume(decision.permit, INTENT))

    def test_genuine_token_against_substituted_intent_is_store_rejected(self) -> None:
        # Provenance and binding are different layers. A genuine token
        # presented against a substituted intent is authenticated by the
        # kernel (it is one of ours) and then rejected by the store's
        # intent binding, with the store's own rejection record -- the
        # layering the incident scenarios' negative controls discriminate.
        kernel = GovernanceKernel(POLICY, secret=SECRET)
        decision = kernel.evaluate(INTENT)
        other = Intent(
            principal="attacker", action="wire.transfer",
            resource="acct:2", cost=999, session_id="s1",
        )
        self.assertFalse(kernel.consume(decision.permit, other))
        rejected = _rejections(kernel._state)
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            kernel.intent_hash(other), rejected[0]["payload"]["intent_hash"]
        )
        self.assertNotIn("reason", rejected[0]["payload"])
        # The store's rejection spent nothing: the true spend still works.
        self.assertTrue(kernel.consume(decision.permit, INTENT))

    def test_legitimate_single_use_semantics_preserved(self) -> None:
        kernel = GovernanceKernel(POLICY, secret=SECRET)
        decision = kernel.evaluate(INTENT)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(kernel.consume(decision.permit, INTENT))
        self.assertFalse(kernel.consume(decision.permit, INTENT))
        self.assertTrue(kernel.verify_audit())


class RawSqliteForgeryTests(unittest.TestCase):
    """Repro B: an out-of-process writer holding only the state file."""

    def test_raw_inserted_permit_cannot_be_spent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            state = SQLiteKernelState(path)
            kernel = GovernanceKernel(POLICY, secret=SECRET, state=state)
            genuine = kernel.evaluate(INTENT)
            self.assertEqual("allow", genuine.outcome)
            digest = kernel.intent_hash(INTENT)
            state.close()

            # Raw writer: forge a permit row plus a chain-consistent
            # decision record, recomputing hashes with the chain's own
            # unkeyed algorithm, exactly as in the diagnosis.
            raw = sqlite3.connect(path)
            raw.execute(
                "INSERT INTO permits (permit, intent_hash) VALUES (?, ?)",
                ("raw-forged-permit", digest),
            )
            last = raw.execute(
                "SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()[0]
            record = _chain_record(
                last,
                "decision",
                {"outcome": "allow", "reason": "raw_forged", "intent_hash": digest},
                time.time_ns(),
            )
            raw.execute(
                "INSERT INTO audit (event, payload_json, previous_hash, timestamp_ns, hash)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    record["event"],
                    _canonical(record["payload"]).decode(),
                    record["previous_hash"],
                    record["timestamp_ns"],
                    record["hash"],
                ),
            )
            raw.commit()
            raw.close()

            state2 = SQLiteKernelState(path)
            try:
                kernel2 = GovernanceKernel(POLICY, secret=SECRET, state=state2)
                # Detection boundary, stated plainly: the honestly
                # recomputed chain still verifies. Phase 1 does not claim
                # audit-record prevention; the anchored head is the
                # detection layer for this half of Repro B.
                self.assertTrue(kernel2.verify_audit())
                # The spend, however, is refused: the forged row carries
                # no token the kernel can authenticate.
                self.assertFalse(kernel2.consume("raw-forged-permit", INTENT))
                # And the genuine permit, minted under the deployment's
                # secret, still spends exactly once.
                self.assertTrue(kernel2.consume(genuine.permit, INTENT))
                self.assertFalse(kernel2.consume(genuine.permit, INTENT))
            finally:
                state2.close()


class PayloadDetachmentTests(unittest.TestCase):
    """Repro C: caller mutation after write must not rewrite stored state."""

    def test_append_detaches_payload(self) -> None:
        state = InMemoryKernelState()
        payload = {"outcome": "deny", "reason": "original_reason", "nested": {"x": 1}}
        state.append("decision", payload, time.time_ns())

        payload["outcome"] = "allow"
        payload["reason"] = "rewritten_after_the_fact"
        payload["nested"]["x"] = 2

        stored = state.audit[0]["payload"]
        self.assertEqual(
            {"outcome": "deny", "reason": "original_reason", "nested": {"x": 1}},
            stored,
        )
        kernel = GovernanceKernel(POLICY, secret=SECRET, state=state)
        self.assertTrue(kernel.verify_audit())

    def test_append_unique_detaches_payload(self) -> None:
        state = InMemoryKernelState()
        payload = {"entry_id": "e1", "outcome": "deny"}
        self.assertIsNone(
            state.append_unique("entry", "entry_id", "e1", payload, time.time_ns())
        )

        payload["outcome"] = "allow"
        self.assertEqual("deny", state.audit[0]["payload"]["outcome"])

        # The existing-match return also reflects the stored original.
        again = state.append_unique(
            "entry", "entry_id", "e1", {"entry_id": "e1", "outcome": "allow"},
            time.time_ns(),
        )
        self.assertEqual({"entry_id": "e1", "outcome": "deny"}, again)


class PolicyPinningTests(unittest.TestCase):
    """Repro D: post-construction policy reassignment must fail closed."""

    def _kernel(self) -> GovernanceKernel:
        return GovernanceKernel(
            Policy(allowed_actions=frozenset({"read"}), max_cost=10),
            secret=SECRET,
        )

    def _envelope(self, kernel: GovernanceKernel) -> ApprovalEnvelope:
        zeros = "0" * 64
        return ApprovalEnvelope(
            approval_id="approval-1",
            authority_id="authority",
            verifier_id="verifier",
            key_id="key",
            deployment_id="deployment",
            trust_hash=zeros,
            session_id="s",
            principal="mallory",
            intent_hash=kernel.intent_hash(INTENT),
            policy_hash=zeros,
            nonce="nonce-1",
            issued_at_ns=1,
            expires_at_ns=2,
            signature="signature",
        )

    def test_policy_swap_fails_closed_at_every_decision_point(self) -> None:
        kernel = self._kernel()
        intent = Intent(
            principal="mallory", action="wire.transfer",
            resource="acct:1", cost=5, session_id="s",
        )
        # Control: under the construction policy the intent is denied.
        self.assertEqual("deny", kernel.evaluate(intent).outcome)
        audit_len = len(kernel.audit)

        kernel.policy = Policy(
            allowed_actions=frozenset({"wire.transfer"}), max_cost=10
        )

        with self.assertRaises(StateIntegrityError):
            kernel.evaluate(intent)
        with self.assertRaises(StateIntegrityError):
            kernel.evaluate_with_approval(intent, self._envelope(kernel))
        with self.assertRaises(StateIntegrityError):
            kernel.consume("any-permit", intent)
        # Fail-closed means silent in the trail as well: the drifted
        # kernel appended no decision under the swapped policy.
        self.assertEqual(audit_len, len(kernel.audit))

    def test_pre_swap_permit_cannot_be_spent_after_swap(self) -> None:
        kernel = self._kernel()
        read_intent = Intent(
            principal="mallory", action="read", resource="acct:1",
            cost=5, session_id="s",
        )
        decision = kernel.evaluate(read_intent)
        self.assertEqual("allow", decision.outcome)

        kernel.policy = Policy(allowed_actions=frozenset({"read"}), max_cost=999)
        with self.assertRaises(StateIntegrityError):
            kernel.consume(decision.permit, read_intent)

    def test_undrifted_kernel_decides_normally(self) -> None:
        kernel = self._kernel()
        read_intent = Intent(
            principal="mallory", action="read", resource="acct:1",
            cost=5, session_id="s",
        )
        decision = kernel.evaluate(read_intent)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(kernel.consume(decision.permit, read_intent))


class OpsKernelSecretTests(unittest.TestCase):
    """The ops deployment persists one kernel secret across processes."""

    def test_secret_is_created_owner_only_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = _deployment_kernel_secret(root)
            second = _deployment_kernel_secret(root)
            self.assertEqual(first, second)
            self.assertEqual(32, len(first))
            secret_path = root / KERNEL_SECRET_FILENAME
            self.assertTrue(secret_path.is_file())
            self.assertEqual(0o600, stat.S_IMODE(secret_path.stat().st_mode))

    def test_distinct_deployments_hold_distinct_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            self.assertNotEqual(
                _deployment_kernel_secret(Path(one)),
                _deployment_kernel_secret(Path(two)),
            )


if __name__ == "__main__":
    unittest.main()

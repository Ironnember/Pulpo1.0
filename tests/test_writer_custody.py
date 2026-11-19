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

Layering change (2026-11-13, on top of Phase 1): Phase 1 authenticated
the permit token at the kernel (provenance) and deliberately left the
token-to-intent binding to the store's check against the permit row.
Codex's P1 review of PR #355 showed the residual: that row's intent
hash is writer-controlled and outside the audit chain, so a state-file
writer holding a genuine token could rewrite its row (new intent hash,
spent reset) and spend the token for an intent the kernel never
authorized, chain still verifying -- independently reproduced before
the change. The binding therefore moved up: ``GovernanceKernel.consume``
now compares the token's own authenticated digest against the presented
intent before consulting the store, and the standing layering test
below is pinned to the kernel-issued refusal. The store's binding check
remains as the second layer and is proven directly at the state layer
(``StateIntentBindingTests``). In the same change, the ops read-only
projections (``verify`` / ``status``) stopped provisioning the kernel
secret: they load it when present and never create or repair it.
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
from pulpo.ops import (
    KERNEL_SECRET_FILENAME,
    _deployment_kernel_secret,
    _load_kernel_secret,
)
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

    def test_genuine_token_against_substituted_intent_is_kernel_rejected(self) -> None:
        # Provenance and binding both live at the kernel for the spend
        # path (layering change, 2026-11-13). A genuine token presented
        # against a substituted intent is authenticated (it is one of
        # ours) and then refused by the kernel itself, because the
        # token's authenticated digest does not match the presented
        # intent -- before the store is consulted, with the kernel's
        # rejection record naming the reason. Phase 1 pinned this
        # refusal to the store's binding instead; that layering let a
        # state-file writer retarget a genuine token by rewriting its
        # permit row (see RetargetedPermitRowTests). The store's own
        # binding still exists as the second layer and is proven
        # directly in StateIntentBindingTests.
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
        self.assertEqual(
            "permit_intent_mismatch", rejected[0]["payload"]["reason"]
        )
        # The kernel's refusal spent nothing: the true spend still works.
        self.assertTrue(kernel.consume(decision.permit, INTENT))
        self.assertTrue(kernel.verify_audit())

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


class RetargetedPermitRowTests(unittest.TestCase):
    """Codex P1 on PR #355: a genuine token re-aimed through its row.

    The attacker holds write access to the state store (the writer-
    custody diagnosis position) plus one genuine token, legitimately
    spent. It rewrites the permit row -- intent hash of a different,
    destructive intent, spent reset to 0 -- without touching the audit
    chain. Before the 2026-11-13 layering change a fresh kernel
    consumed the token for the retargeted intent with the chain
    verifying throughout (independently reproduced). Now the kernel
    refuses: what stops the spend is the kernel's comparison of the
    token's authenticated digest against the presented intent, NOT
    chain detection -- so both tests assert the chain still verifies.
    """

    READ = Intent(
        principal="operator", action="read", resource="file:1",
        cost=0, session_id="s1",
    )
    DELETE = Intent(
        principal="operator", action="delete", resource="file:1",
        cost=0, session_id="s1",
    )
    POLICY = Policy(allowed_actions=frozenset({"read", "delete"}), max_cost=10)

    def test_sqlite_row_retarget_cannot_spend_genuine_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            state = SQLiteKernelState(path)
            kernel = GovernanceKernel(self.POLICY, secret=SECRET, state=state)
            decision = kernel.evaluate(self.READ)
            self.assertEqual("allow", decision.outcome)
            token = decision.permit
            delete_digest = kernel.intent_hash(self.DELETE)
            # Legitimately spent, so the attack must defeat both the
            # binding and single-use.
            self.assertTrue(kernel.consume(token, self.READ))
            self.assertFalse(kernel.consume(token, self.READ))
            state.close()

            # The attack, exactly as reproduced: raw sqlite3, no kernel
            # secret, no audit writes.
            raw = sqlite3.connect(path)
            raw.execute(
                "UPDATE permits SET intent_hash = ?, spent = 0 WHERE permit = ?",
                (delete_digest, token),
            )
            raw.commit()
            raw.close()

            state2 = SQLiteKernelState(path)
            try:
                fresh = GovernanceKernel(self.POLICY, secret=SECRET, state=state2)
                # The chain is untouched and still verifies -- detection
                # is not what saves this spend.
                self.assertTrue(fresh.verify_audit())
                # The retargeted spend is refused by the kernel, with
                # the mismatch recorded as the refusal's reason.
                self.assertFalse(fresh.consume(token, self.DELETE))
                rejected = _rejections(state2)
                self.assertEqual(
                    "permit_intent_mismatch", rejected[-1]["payload"]["reason"]
                )
                self.assertEqual(
                    delete_digest, rejected[-1]["payload"]["intent_hash"]
                )
                # No consumption of the token for the delete intent was
                # recorded anywhere in the trail.
                self.assertFalse(
                    any(
                        record["event"] == "permit_consumed"
                        and record["payload"]["intent_hash"] == delete_digest
                        for record in state2.audit
                    )
                )
                # The original intent no longer spends either: the
                # kernel passes it (embedded digest matches), and the
                # store's binding refuses because the row now names the
                # delete digest -- the second layer holding.
                self.assertFalse(fresh.consume(token, self.READ))
                self.assertTrue(fresh.verify_audit())
            finally:
                state2.close()

    def test_inmemory_row_retarget_cannot_spend_genuine_token(self) -> None:
        # Backend parity: the same retarget through the in-memory
        # store's issued-map (the state handle is the writer's reach).
        state = InMemoryKernelState()
        kernel = GovernanceKernel(self.POLICY, secret=SECRET, state=state)
        decision = kernel.evaluate(self.READ)
        token = decision.permit
        self.assertTrue(kernel.consume(token, self.READ))

        state._issued[token] = kernel.intent_hash(self.DELETE)
        state._spent.discard(token)

        fresh = GovernanceKernel(self.POLICY, secret=SECRET, state=state)
        self.assertTrue(fresh.verify_audit())
        self.assertFalse(fresh.consume(token, self.DELETE))
        rejected = _rejections(state)
        self.assertEqual(
            "permit_intent_mismatch", rejected[-1]["payload"]["reason"]
        )
        self.assertTrue(fresh.verify_audit())


class StateIntentBindingTests(unittest.TestCase):
    """The store layer's own intent binding, proven directly.

    Before the 2026-11-13 layering change, the incident scenarios'
    negative controls proved end-to-end that the store's binding is
    what denies a substituted spend. The binding's first layer now
    lives in the kernel, so the store's check is proven here, at the
    layer where it lives: ``consume_permit`` accepts exactly the
    intent hash the permit was issued for, exactly once, and records
    its refusal against the presented hash. Both backends.
    """

    DIGEST_A = "a" * 64
    DIGEST_B = "b" * 64

    def _exercise_binding(self, state) -> None:
        permit = "state-issued-permit"
        replay = state.issue_permit(
            permit, self.DIGEST_A, "test_reason", time.time_ns(), approval=None
        )
        self.assertIsNone(replay)
        # An unknown permit spends for nothing.
        self.assertFalse(
            state.consume_permit("never-issued", self.DIGEST_A, time.time_ns())
        )
        # A substituted intent is refused by the store, evidenced
        # against the presented hash, and spends nothing.
        self.assertFalse(state.consume_permit(permit, self.DIGEST_B, time.time_ns()))
        rejected = [
            record
            for record in state.audit
            if record["event"] == "permit_rejected"
            and record["payload"]["intent_hash"] == self.DIGEST_B
        ]
        self.assertEqual(1, len(rejected))
        # The issued intent still spends, exactly once.
        self.assertTrue(state.consume_permit(permit, self.DIGEST_A, time.time_ns()))
        self.assertFalse(state.consume_permit(permit, self.DIGEST_A, time.time_ns()))

    def test_inmemory_store_binds_permit_to_issued_intent(self) -> None:
        self._exercise_binding(InMemoryKernelState())

    def test_sqlite_store_binds_permit_to_issued_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = SQLiteKernelState(Path(directory) / "state.db")
            try:
                self._exercise_binding(state)
            finally:
                state.close()


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

    def test_load_only_returns_none_and_creates_nothing(self) -> None:
        # The read-only projections' secret path: a deployment without
        # a secret file yields None and is left exactly as it was.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(_load_kernel_secret(root))
            self.assertFalse((root / KERNEL_SECRET_FILENAME).exists())

    def test_load_only_loads_without_repairing_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provisioned = _deployment_kernel_secret(root)
            secret_path = root / KERNEL_SECRET_FILENAME
            secret_path.chmod(0o644)
            self.assertEqual(provisioned, _load_kernel_secret(root))
            # Still loose afterwards: load-only never chmods.
            self.assertEqual(0o644, stat.S_IMODE(secret_path.stat().st_mode))


if __name__ == "__main__":
    unittest.main()

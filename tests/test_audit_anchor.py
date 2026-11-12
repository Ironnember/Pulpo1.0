"""Anchored audit head: the external witness for the chain's honest gaps.

The Mythos scenario (``tests/test_mythos_laundering_scenario.py``, PR #350)
documented two gaps in the canonical audit chain, Verified at the base
commit: the chain is unkeyed and does not commit to its own length, so a
privileged writer with direct store access can (a) truncate the chain's
tail, or (b) delete a mid-chain record and recompute every following
``previous_hash``/``hash`` — and ``GovernanceKernel.verify_audit`` accepts
the result both times.  ``verify_audit`` proves internal consistency of
the records it is shown; it cannot prove those are the records that were
written.

This module tests the remedy in ``pulpo/anchor.py``: an external anchor
witnesses (head_hash, record_count) into an append-only store outside the
kernel/state API surface, and ``verify_anchored_audit`` fails closed
unless every anchor still matches the exact prefix of the presented
trail.  The same two attacks are replayed here with anchoring in force
and must be DETECTED; the unanchored ``verify_audit`` result is asserted
alongside each time, so the added detection is attributed to the anchor,
not to the chain.

Trust boundary (stated, not hidden): anchoring detects audit-store
tampering relative to the anchor history the verifier holds.  A writer
who can also rewrite the anchor store — and, for signed anchors, holds
the anchor key — is outside this layer's scope, and truncating the anchor
history's own tail is indistinguishable from anchoring having stopped
earlier: it reduces witnessed coverage, which verification reports
exactly (see ``test_anchor_history_tail_rollback_reduces_coverage_only``).

Adversarial transformation review: the eight passes (Flip, Reverse,
Invert, Inside-Out, Darken, Lighten, Amplify, Negate) for this change
are recorded in the PR body per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision recorded there: CONTINUE — the anchor observes the
trail and appends nothing to canonical kernel state.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest

from pulpo import (
    GovernanceKernel,
    HmacAnchorSigner,
    Intent,
    Policy,
    anchor_records,
    anchor_state,
    verify_anchored_audit,
)
from pulpo.anchor import FileAnchorStore, InMemoryAnchorStore
from pulpo.state import InMemoryKernelState, SQLiteKernelState, _canonical
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 5_000_000


class _Clock:
    def __init__(self, start: int = NOW) -> None:
        self.now = start

    def __call__(self) -> int:
        self.now += 1
        return self.now


def rehash_suffix(records: list[dict], start: int) -> None:
    """The privileged writer's rehash step, as in the Mythos scenario.

    Recomputes ``previous_hash``/``hash`` from ``start`` onward using the
    production canonical hashing; the chain is public and unkeyed, so any
    store writer can do this.
    """
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


def _plain_kernel(state) -> GovernanceKernel:
    verifier = HmacTestVerifier()
    policy = Policy(
        allowed_actions=frozenset({"run_evaluation", "execute_code"}),
        max_cost=0,
        approval_actions=frozenset({"run_evaluation"}),
        authority_trust=trust_for(verifier),
    )
    return GovernanceKernel(policy, approval_verifier=verifier, clock=_Clock(), state=state)


def _governed_trail(state) -> GovernanceKernel:
    """A kernel whose trail contains a real approval + consume sequence."""
    kernel = _plain_kernel(state)
    verifier = HmacTestVerifier()
    intent = Intent("agent:anchor", "run_evaluation", "sandbox:ws", 0, "s1")
    envelope = signed_envelope(kernel, intent, verifier, now_ns=NOW, ttl_ns=9_000)
    decision = kernel.evaluate_with_approval(intent, envelope)
    assert decision.outcome == "allow" and decision.permit is not None
    assert kernel.consume(decision.permit, intent)
    return kernel


class AuditAnchorTests(unittest.TestCase):
    def test_genesis_anchor_on_empty_trail_verifies(self) -> None:
        store = InMemoryAnchorStore()
        anchor = anchor_records([], store, clock=_Clock())
        self.assertEqual(0, anchor.sequence)
        self.assertEqual(0, anchor.record_count)
        self.assertEqual("0" * 64, anchor.head_hash)
        result = verify_anchored_audit([], store.anchors())
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(0, result.anchored_records)
        # Fail closed with no witness at all.
        self.assertFalse(verify_anchored_audit([], []).ok)

    def test_anchor_cadence_and_no_canonical_mutation(self) -> None:
        state = InMemoryKernelState()
        kernel = _plain_kernel(state)
        store = InMemoryAnchorStore()
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        before = len(state.audit)
        first = anchor_state(state, store, clock=_Clock())
        # Anchoring observes; it appends nothing to the canonical trail.
        self.assertEqual(before, len(state.audit))
        self.assertTrue(kernel.verify_audit())
        self.assertEqual(before, first.record_count)
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        second = anchor_state(state, store, clock=_Clock())
        self.assertEqual(1, second.sequence)
        self.assertEqual(first.anchor_hash, second.previous_anchor_hash)
        self.assertGreater(second.record_count, first.record_count)
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(second.record_count, result.anchored_records)
        self.assertEqual(len(state.audit), result.total_records)
        # Unanchored tail (records after the latest anchor) is reported as
        # coverage, not silently treated as witnessed.
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertTrue(result.ok, result.reason)
        self.assertLess(result.anchored_records, result.total_records)

    def test_sqlite_governed_trail_verifies_end_to_end(self) -> None:
        import tempfile, os

        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteKernelState(os.path.join(tmp, "state.db"))
            kernel = _governed_trail(state)
            store = FileAnchorStore(os.path.join(tmp, "anchors.jsonl"))
            anchor_state(state, store, clock=_Clock())
            result = verify_anchored_audit(state.audit, store.anchors())
            self.assertTrue(result.ok, result.reason)
            self.assertEqual(len(state.audit), result.anchored_records)
            state.close()

    def test_tail_truncation_detected_inmemory(self) -> None:
        state = InMemoryKernelState()
        kernel = _governed_trail(state)
        store = InMemoryAnchorStore()
        anchor_state(state, store, clock=_Clock())
        # Privileged writer erases the trail's tail through the live list.
        del state.audit[-2:]
        # Chain-only verification still accepts the remaining prefix...
        self.assertTrue(kernel.verify_audit())
        # ...anchored verification does not.
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertFalse(result.ok)
        self.assertEqual("anchor_beyond_trail", result.reason)

    def test_tail_truncation_detected_sqlite(self) -> None:
        import tempfile, os

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.db")
            state = SQLiteKernelState(path)
            kernel = _governed_trail(state)
            store = InMemoryAnchorStore()
            anchor_state(state, store, clock=_Clock())
            total = len(state.audit)
            state.close()
            with sqlite3.connect(path) as connection:
                connection.execute("DELETE FROM audit WHERE sequence > ?", (total - 2,))
            state = SQLiteKernelState(path)
            kernel = _plain_kernel(state)
            self.assertTrue(kernel.verify_audit())
            result = verify_anchored_audit(state.audit, store.anchors())
            self.assertFalse(result.ok)
            self.assertEqual("anchor_beyond_trail", result.reason)
            state.close()

    def test_midchain_deletion_with_rehash_detected(self) -> None:
        state = InMemoryKernelState()
        kernel = _governed_trail(state)
        store = InMemoryAnchorStore()
        anchor_state(state, store, clock=_Clock())
        records = state.audit
        index = next(i for i, r in enumerate(records) if r["event"] == "permit_consumed")
        del records[index]
        rehash_suffix(records, index)
        # The rebuilt chain passes its own verification — the #350 gap.
        self.assertTrue(kernel.verify_audit())
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertFalse(result.ok)
        self.assertEqual("anchor_beyond_trail", result.reason)
        # Pad the trail back to the witnessed length with a forged record
        # so the count matches again: now only the anchored head can catch
        # it, via the prefix the anchor pinned.
        forged = dict(records[-1])
        records.append(forged)
        rehash_suffix(records, len(records) - 1)
        self.assertTrue(kernel.verify_audit())
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertFalse(result.ok)
        self.assertEqual("anchor_prefix_mismatch", result.reason)

    def test_midchain_deletion_without_rehash_detected_by_chain(self) -> None:
        state = InMemoryKernelState()
        kernel = _governed_trail(state)
        store = InMemoryAnchorStore()
        anchor_state(state, store, clock=_Clock())
        records = state.audit
        index = next(i for i, r in enumerate(records) if r["event"] == "approval_verified")
        del records[index]
        self.assertFalse(kernel.verify_audit())
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertFalse(result.ok)
        self.assertEqual("audit_chain_invalid", result.reason)

    def test_anchor_history_gap_detected(self) -> None:
        state = InMemoryKernelState()
        kernel = _plain_kernel(state)
        store = InMemoryAnchorStore()
        for _ in range(3):
            kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
            anchor_state(state, store, clock=_Clock())
        history = store.anchors()
        del history[1]  # a gap in the presented witness history
        result = verify_anchored_audit(state.audit, history)
        self.assertFalse(result.ok)
        self.assertEqual("anchor_sequence_gap", result.reason)

    def test_anchor_history_reordering_detected(self) -> None:
        state = InMemoryKernelState()
        kernel = _plain_kernel(state)
        store = InMemoryAnchorStore()
        for _ in range(2):
            kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
            anchor_state(state, store, clock=_Clock())
        history = store.anchors()
        history.reverse()
        result = verify_anchored_audit(state.audit, history)
        self.assertFalse(result.ok)
        self.assertIn(result.reason, {"anchor_sequence_gap", "anchor_chain_mismatch"})

    def test_anchor_history_tail_rollback_reduces_coverage_only(self) -> None:
        # Documented boundary: dropping the LATEST anchor cannot be told
        # apart from anchoring having stopped earlier.  Verification still
        # succeeds over the genuinely witnessed prefix and reports the
        # reduced coverage exactly — but tampering INSIDE the surviving
        # witnessed prefix is still detected.
        state = InMemoryKernelState()
        kernel = _plain_kernel(state)
        store = InMemoryAnchorStore()
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        first = anchor_state(state, store, clock=_Clock())
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        anchor_state(state, store, clock=_Clock())
        rolled_back = store.anchors()[:1]
        result = verify_anchored_audit(state.audit, rolled_back)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(first.record_count, result.anchored_records)
        self.assertLess(result.anchored_records, result.total_records)
        # Tamper inside the surviving witnessed prefix: still detected.
        records = state.audit
        del records[0]
        rehash_suffix(records, 0)
        self.assertTrue(kernel.verify_audit())
        result = verify_anchored_audit(state.audit, rolled_back)
        self.assertFalse(result.ok)

    def test_signed_anchors_reject_forgery_and_require_verifier(self) -> None:
        state = InMemoryKernelState()
        kernel = _governed_trail(state)
        signer = HmacAnchorSigner(b"witness-key-held-outside-the-kernel")
        store = InMemoryAnchorStore()
        anchor_state(state, store, clock=_Clock(), signer=signer)
        history = store.anchors()
        self.assertTrue(history[0].signature)
        # Honest history verifies with the pinned verifier.
        self.assertTrue(verify_anchored_audit(state.audit, history, verifier=signer).ok)
        # Signed history without a verifier fails closed.
        result = verify_anchored_audit(state.audit, history)
        self.assertFalse(result.ok)
        self.assertEqual("anchor_verifier_unavailable", result.reason)
        # A forged anchor extending the history, signed with the wrong key,
        # is rejected even though its chain links are internally consistent.
        attacker = HmacAnchorSigner(b"attacker-key")
        from dataclasses import replace
        from pulpo import AuditAnchor

        forged_unsigned = AuditAnchor(
            sequence=1,
            record_count=len(state.audit),
            head_hash=state.audit[-1]["hash"],
            previous_anchor_hash=history[0].anchor_hash,
            timestamp_ns=NOW + 99,
        )
        forged = replace(
            forged_unsigned, signature=attacker.sign(forged_unsigned.signing_bytes())
        )
        result = verify_anchored_audit(state.audit, history + [forged], verifier=signer)
        self.assertFalse(result.ok)
        self.assertEqual("anchor_signature_invalid", result.reason)

    def test_tampered_anchor_head_detected(self) -> None:
        state = InMemoryKernelState()
        kernel = _plain_kernel(state)
        store = InMemoryAnchorStore()
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        anchor_state(state, store, clock=_Clock())
        kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
        anchor_state(state, store, clock=_Clock())
        from dataclasses import replace

        history = store.anchors()
        # Rewrite the first anchor's witnessed head; the next anchor's
        # previous-hash link no longer matches the altered anchor.
        history[0] = replace(history[0], head_hash=history[1].head_hash)
        result = verify_anchored_audit(state.audit, history)
        self.assertFalse(result.ok)

    def test_file_store_rejects_non_extending_append_and_detaches_reads(self) -> None:
        import tempfile, os
        from pulpo import AuditAnchor

        with tempfile.TemporaryDirectory() as tmp:
            store = FileAnchorStore(os.path.join(tmp, "anchors.jsonl"))
            state = InMemoryKernelState()
            kernel = _plain_kernel(state)
            kernel.evaluate(Intent("agent:anchor", "execute_code", "sandbox:ws", 0, "s1"))
            anchor_state(state, store, clock=_Clock())
            bogus = AuditAnchor(
                sequence=7,
                record_count=1,
                head_hash=state.audit[-1]["hash"],
                previous_anchor_hash="0" * 64,
                timestamp_ns=NOW + 5,
            )
            with self.assertRaises(ValueError):
                store.append(bogus)
            reads = store.anchors()
            reads.clear()  # mutating the returned list cannot reach the store
            self.assertEqual(1, len(store.anchors()))

    def test_file_store_malformed_content_fails_closed(self) -> None:
        import tempfile, os

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "anchors.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"sequence": "not-an-anchor"}\n')
            store = FileAnchorStore(path)
            with self.assertRaises(ValueError):
                store.anchors()


if __name__ == "__main__":
    unittest.main()

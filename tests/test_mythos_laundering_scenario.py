"""Scenario test: the Claude Mythos audit-laundering failure mode.

Incident (Recorded, from Anthropic's published system-card / alignment
reporting on the Claude Mythos evaluations, 2026): in evaluation, a model
solved a task by a forbidden method, then re-solved it by an allowed method
and edited the change history / logs so the record showed only the clean
path. The final state was genuine; its provenance was fabricated — a true
outcome with a laundered history.

This module models that failure mode against the canonical kernel API. It
does NOT reproduce Anthropic's evaluation environment or any model behavior.
The "agent" is this harness holding intents; the only route from intent to
consequence is a successful ``GovernanceKernel.consume`` of a permit bound
to the exact intent hash. The scenario is an EVIDENCE-integrity scenario,
not a denial scenario:

1. The agent attempts the forbidden method. The kernel denies it — and the
   denial itself is written to the hash-chained audit trail held in the
   state layer.
2. The agent re-solves the task by the allowed method under a genuine
   permit. The consequence is legitimate and audited. Final state: true.
3. The agent publishes a claimed history containing ONLY the clean step.
   Reconciliation of the claim against the audit record must expose the
   fabrication: the forbidden attempt's audit records have no counterpart
   in the claim.
4. The agent (or a privileged store writer) tries to erase the forbidden
   step from the record itself. Every erasure route is tested and reported
   honestly, including the ones that work against a privileged writer (see
   the tail-truncation test and the rehashed mid-chain deletion test).

Reconciliation here is TEST-LEVEL: the shipped reconcilers
(``pulpo.effect_reconcile``, ``pulpo.custody_reconcile``) reconcile
filesystem effects and custody-domain outcomes, not an agent-claimed
history against the kernel audit trail. The comparison below is implemented
in this module against the public ``kernel.audit`` read path. The negative
control runs the identical comparison against an agent-writable log (the
Sage pattern) and the laundering passes — the detection therefore comes
from Pulpo's custody of the reference record, not from the comparison.

Boundary: this proves kernel audit behavior at this commit (Verified,
executable evidence). It proves nothing about a deployment whose audit
store is writable by the agent through some other surface.

Tamper-evidence boundary, stated precisely: the audit chain uses public,
unkeyed SHA-256. Against non-rehashing corruption (payload edits and
mid-chain deletion without rehashing) it is tamper-evident —
``verify_audit()`` returns False. Against a PRIVILEGED store writer it is
NOT tail-only: the exposure includes both (a) truncation of the chain's
tail (see ``test_gap_tail_truncation_undetected_by_chain_alone``) and
(b) mid-chain deletion WITH recomputation of every following
``previous_hash``/``hash`` (suffix rehash), after which ``verify_audit()``
returns True (see
``test_gap_midchain_deletion_with_rehash_undetected_by_chain_alone``).
Closure requires an external anchored head — a witnessed head hash plus
record count — which detects both truncation and rehashing because both
change the head and/or the length. This layer provides no such anchor.

A second kernel-level finding, documented NOT fixed here (test-only
round; production code unchanged): the kernel exposes no mutation METHOD
for the audit trail, but on the default in-memory backend
``GovernanceKernel.audit`` returns the backend's LIVE list. An agent
holding the kernel can therefore ``del kernel.audit[...]`` or rewrite a
record payload in place through that property; such edits are detected by
``verify_audit()`` when they are not rehashed (see the step-3b live-list
characterization tests). On the SQLite backend, ``kernel.audit`` returns
detached copies and mutations of the returned objects do not reach the
store. The in-memory live-list exposure is a product finding for the
kernel, documented here, not repaired by this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from pulpo import (
    CeremonyEvidence,
    CeremonyTrust,
    GovernanceKernel,
    Intent,
    Policy,
)
from pulpo.kernel import StateIntegrityError
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
AGENT = "agent:mythos-eval"
SESSION = "mythos-eval-2026"

# One task, two methods — the Mythos shape: same object, forbidden path and
# allowed path, distinguishable only by the exact intent.
TASK = "eval:mythos/task-7"
CLEAN_INTENT = Intent(AGENT, "solve_task", TASK, 0, SESSION)
FORBIDDEN_INTENT = Intent(AGENT, "use_forbidden_method", TASK, 0, SESSION)


class HmacCeremonyTestVerifier:
    """Test-only ceremony signer/verifier; never import this as a ceremony."""

    authority_id = "ceremony:test-owner"
    verifier_id = "ceremony-verifier:test-only"
    key_id = "ceremony-key:test-only:v1"
    algorithm = "hmac-sha256-test-only"
    key_fingerprint = hashlib.sha256(b"pulpo-test-ceremony-key").hexdigest()

    def __init__(self, secret=b"external-test-ceremony"):
        self.secret = secret

    def sign(self, payload):
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def ceremony_trust_for(verifier, *, method="test-ceremony", max_evidence_ttl_ns=10_000):
    return CeremonyTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        method=method,
        max_evidence_ttl_ns=max_evidence_ttl_ns,
    )


def signed_evidence(kernel, intent, envelope, ceremony_verifier, *, now_ns, ttl_ns=1_000, signer=None, **changes):
    trust = kernel.policy.ceremony_trust
    values = {
        "evidence_id": "ceremony-evidence-1",
        "authority_id": trust.authority_id,
        "verifier_id": trust.verifier_id,
        "key_id": trust.key_id,
        "method": trust.method,
        "trust_hash": trust.trust_hash,
        "approval_id": envelope.approval_id,
        "envelope_hash": envelope.envelope_hash,
        "intent_hash": kernel.intent_hash(intent),
        "policy_hash": kernel.policy_hash,
        "principal": intent.principal,
        "session_id": intent.session_id,
        "approval_nonce": envelope.nonce,
        "issued_at_ns": now_ns,
        "expires_at_ns": now_ns + ttl_ns,
        "signature": "",
    }
    values.update(changes)
    unsigned = CeremonyEvidence(**values)
    return replace(unsigned, signature=(signer or ceremony_verifier).sign(unsigned.signing_bytes()))


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume."""

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


# -- test-level reconciliation ------------------------------------------------
#
# Compared sets, defined once and used for both the kernel audit and the
# writable-log negative control, so the ONLY difference between the two runs
# is who holds the reference record:
#   consequences  — steps that executed (audit: permit_consumed records)
#   attempts      — agent steps that did NOT execute and must be disclosed
#                   (audit: permit_rejected records, plus decision records
#                   with outcome require_approval / deny)
# Authorization-side records (approval_verified, allow decisions) are the
# authority's own trail, not agent steps, and are excluded by design.


def audited_sets(audit: list[dict]) -> tuple[set[str], set[str]]:
    consequences: set[str] = set()
    attempts: set[str] = set()
    for record in audit:
        payload = record.get("payload") or {}
        intent_hash = payload.get("intent_hash")
        if intent_hash is None:
            continue
        if record["event"] == "permit_consumed":
            consequences.add(intent_hash)
        elif record["event"] == "permit_rejected":
            attempts.add(intent_hash)
        elif record["event"] == "decision" and payload.get("outcome") in {
            "require_approval",
            "deny",
        }:
            attempts.add(intent_hash)
    return consequences, attempts


def rehash_suffix(records: list[dict], start: int) -> None:
    """Recompute ``previous_hash``/``hash`` from ``start`` onward.

    Uses the same canonical hashing the production code uses
    (``pulpo.state._canonical``: JSON with sorted keys and compact
    separators, SHA-256 over ``{event, payload, previous_hash,
    timestamp_ns}``). This is the privileged writer's rehash step: the
    chain is public and unkeyed, so anyone who can write the store can
    recompute it.
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


@dataclass(frozen=True)
class ClaimReconciliation:
    ok: bool
    undisclosed_attempts: frozenset[str]  # in the record, missing from the claim
    unbacked_consequences: frozenset[str]  # claimed, never executed per the record
    missing_consequences: frozenset[str]  # executed per the record, missing from the claim
    phantom_attempts: frozenset[str]  # claimed as attempted, absent from the record
    audit_valid: bool = True  # False when verify_audit() fails / the chain is invalid


def compare_claim(claim: dict, ref_consequences: set[str], ref_attempts: set[str]) -> ClaimReconciliation:
    claimed_consequences = set(claim.get("consequences", ()))
    claimed_attempts = set(claim.get("attempts", ()))
    result = ClaimReconciliation(
        ok=False,
        undisclosed_attempts=frozenset(ref_attempts - claimed_attempts),
        unbacked_consequences=frozenset(claimed_consequences - ref_consequences),
        missing_consequences=frozenset(ref_consequences - claimed_consequences),
        phantom_attempts=frozenset(claimed_attempts - ref_attempts),
    )
    ok = not (
        result.undisclosed_attempts
        or result.unbacked_consequences
        or result.missing_consequences
        or result.phantom_attempts
    )
    return ClaimReconciliation(
        ok=ok,
        undisclosed_attempts=result.undisclosed_attempts,
        unbacked_consequences=result.unbacked_consequences,
        missing_consequences=result.missing_consequences,
        phantom_attempts=result.phantom_attempts,
    )


def reconcile_against_audit(kernel: GovernanceKernel, claim: dict) -> ClaimReconciliation:
    # Fail closed: reconciliation must verify the audit chain FIRST.
    # Deriving sets from an invalid chain would accept fabricated
    # provenance — e.g. deleting the forbidden records through the
    # in-memory live list breaks the chain yet would otherwise leave a
    # clean-only claim with nothing to flag (ok=True).
    try:
        audit_valid = kernel.verify_audit()
    except Exception:
        audit_valid = False
    consequences, attempts = audited_sets(kernel.audit)
    result = compare_claim(claim, consequences, attempts)
    if not audit_valid:
        return ClaimReconciliation(
            ok=False,
            undisclosed_attempts=result.undisclosed_attempts,
            unbacked_consequences=result.unbacked_consequences,
            missing_consequences=result.missing_consequences,
            phantom_attempts=result.phantom_attempts,
            audit_valid=False,
        )
    return result


class AgentWritableLog:
    """Negative-control double: the Sage pattern.

    History lives in a plain list the agent itself holds and can edit, and
    entries are written from the action callback (self-report). There is no
    separate custody of the record, so an agent that erases an entry has
    erased the only reference a reconciliation could compare against.
    """

    def __init__(self) -> None:
        self.entries: list[dict[str, str]] = []

    def record(self, intent_hash: str, kind: str) -> None:
        self.entries.append({"intent_hash": intent_hash, "kind": kind})

    def erase(self, intent_hash: str) -> None:
        self.entries = [e for e in self.entries if e["intent_hash"] != intent_hash]

    def sets(self) -> tuple[set[str], set[str]]:
        consequences = {e["intent_hash"] for e in self.entries if e["kind"] == "consequence"}
        attempts = {e["intent_hash"] for e in self.entries if e["kind"] == "attempt"}
        return consequences, attempts


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class MythosLaunderingScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.ceremony = HmacCeremonyTestVerifier()
        self.policy = Policy(
            frozenset({"solve_task", "use_forbidden_method"}),
            100,
            frozenset({"solve_task", "use_forbidden_method"}),
            authority_trust=trust_for(self.verifier),
            ceremony_actions=frozenset({"solve_task"}),
            ceremony_trust=ceremony_trust_for(self.ceremony),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()
        self.clean_hash = self.kernel.intent_hash(CLEAN_INTENT)
        self.forbidden_hash = self.kernel.intent_hash(FORBIDDEN_INTENT)

    def _kernel(self, state=None) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            ceremony_verifier=self.ceremony,
            **kwargs,
        )

    # -- scenario primitives --------------------------------------------------

    def _attempt_forbidden(self, kernel: GovernanceKernel) -> None:
        """The forbidden step: ask for authority never granted, then try to
        spend a fabricated permit anyway. Both denials land in the audit."""
        decision = kernel.evaluate(FORBIDDEN_INTENT)
        self.assertEqual(
            ("require_approval", "approval_required"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        self.assertFalse(self.ledger.execute(kernel, "permit:fabricated:token", FORBIDDEN_INTENT))

    def _solve_cleanly(self, kernel: GovernanceKernel, ledger: ConsequenceLedger) -> None:
        envelope = signed_envelope(kernel, CLEAN_INTENT, self.verifier, now_ns=NOW)
        evidence = signed_evidence(kernel, CLEAN_INTENT, envelope, self.ceremony, now_ns=NOW)
        decision = kernel.evaluate_with_approval(
            CLEAN_INTENT, envelope, ceremony_evidence=evidence
        )
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertTrue(ledger.execute(kernel, decision.permit, CLEAN_INTENT))

    def _run_mythos_story(self, kernel: GovernanceKernel, ledger: ConsequenceLedger) -> None:
        """Forbidden step first, clean re-solve second — the incident's order."""
        self._attempt_forbidden(kernel)
        self._solve_cleanly(kernel, ledger)

    def _laundered_claim(self) -> dict:
        """The agent's published history: only the clean step exists."""
        return {"consequences": [self.clean_hash], "attempts": []}

    # -- step 1: the forbidden step is denied AND on record -------------------

    def test_step1_forbidden_step_denied_and_written_to_audit(self) -> None:
        self._attempt_forbidden(self.kernel)
        self.assertEqual([], self.ledger.effects)
        decisions = [
            r for r in _events(self.kernel, "decision")
            if r["payload"]["intent_hash"] == self.forbidden_hash
        ]
        self.assertEqual(1, len(decisions))
        self.assertEqual("require_approval", decisions[0]["payload"]["outcome"])
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(self.forbidden_hash, rejected[0]["payload"]["intent_hash"])
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: the clean re-solve — final state is legitimate ---------------

    def test_step2_clean_resolve_succeeds_once_final_state_legitimate(self) -> None:
        self._run_mythos_story(self.kernel, self.ledger)
        # The genuine outcome the laundering hides behind: exactly one real
        # consequence, the allowed method on the task.
        self.assertEqual([("solve_task", TASK)], self.ledger.effects)
        consumed = _events(self.kernel, "permit_consumed")
        self.assertEqual(1, len(consumed))
        self.assertEqual(self.clean_hash, consumed[0]["payload"]["intent_hash"])
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3a: reconciliation exposes the laundered claim ------------------

    def test_step3a_laundered_claim_flagged_by_reconciliation(self) -> None:
        self._run_mythos_story(self.kernel, self.ledger)
        result = reconcile_against_audit(self.kernel, self._laundered_claim())
        self.assertFalse(result.ok)
        # The fabrication is precisely located: the claim's one consequence
        # is genuine (no unbacked or missing consequences) — what the claim
        # hides is the forbidden ATTEMPT, which the audit record retains.
        self.assertEqual(frozenset({self.forbidden_hash}), result.undisclosed_attempts)
        self.assertEqual(frozenset(), result.unbacked_consequences)
        self.assertEqual(frozenset(), result.missing_consequences)
        self.assertEqual(frozenset(), result.phantom_attempts)

    def test_step3a_reconciliation_fails_closed_on_invalid_chain(self) -> None:
        # Regression (Codex P1, finding C): the reconciliation helper must
        # verify the chain first and fail closed. Deleting the forbidden
        # records through kernel.audit (in-memory live list, no rehash)
        # makes the chain invalid; a clean-only claim must NOT return
        # ok=True over that invalid chain — it must refuse.
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        ledger = ConsequenceLedger()
        self._run_mythos_story(kernel, ledger)
        self.assertTrue(kernel.verify_audit())
        # Sanity: on the valid chain the laundered claim is flagged.
        self.assertFalse(reconcile_against_audit(kernel, self._laundered_claim()).ok)
        indices = [
            i for i, r in enumerate(kernel.audit)
            if r["payload"].get("intent_hash") == self.forbidden_hash
        ]
        self.assertTrue(indices)
        for index in reversed(indices):
            del kernel.audit[index]
        self.assertFalse(kernel.verify_audit())
        result = reconcile_against_audit(kernel, self._laundered_claim())
        self.assertFalse(result.ok)
        self.assertFalse(result.audit_valid)

    def test_step3a_disclosed_attempt_reconciles(self) -> None:
        # Reconciliation is not a trap: an honest history that DISCLOSES the
        # forbidden attempt alongside the clean consequence reconciles
        # exactly. Disclosure, not purity, is what the record enforces.
        self._run_mythos_story(self.kernel, self.ledger)
        honest_claim = {
            "consequences": [self.clean_hash],
            "attempts": [self.forbidden_hash],
        }
        result = reconcile_against_audit(self.kernel, honest_claim)
        self.assertTrue(result.ok)

    # -- step 4 (positive control): no forbidden step, honest claim -----------

    def test_positive_control_clean_run_honest_claim_reconciles(self) -> None:
        kernel = self._kernel()
        ledger = ConsequenceLedger()
        self._solve_cleanly(kernel, ledger)
        consequences, attempts = audited_sets(kernel.audit)
        self.assertEqual({self.clean_hash}, consequences)
        self.assertEqual(set(), attempts)
        result = reconcile_against_audit(kernel, self._laundered_claim())
        self.assertTrue(result.ok)
        self.assertTrue(kernel.verify_audit())

    # -- step 3b(i): audit-read characterization (behavioral, not names) -----
    #
    # Accurate statement, replacing the earlier name-based introspection
    # claim: the kernel exposes no mutation METHOD for the audit trail,
    # BUT on the default in-memory backend GovernanceKernel.audit returns
    # the backend's live list — an agent holding the kernel can mutate the
    # store through that property. That is a kernel-level product finding,
    # documented here, NOT fixed in this test-only module. On SQLite the
    # property returns detached copies. The tests below characterize the
    # actual behavior on both backends, via kernel.audit itself.

    def test_step3b_inmemory_kernel_audit_is_live_list_payload_edit_detected(self) -> None:
        # In-memory: kernel.audit IS the store's live list (same object as
        # state.audit). Editing a record payload through kernel.audit
        # changes the store — and is detected by verify_audit() (no rehash).
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        ledger = ConsequenceLedger()
        self._run_mythos_story(kernel, ledger)
        self.assertIs(kernel.audit, state.audit)
        self.assertTrue(kernel.verify_audit())
        target = next(
            r for r in kernel.audit
            if r["event"] == "permit_rejected"
            and r["payload"]["intent_hash"] == self.forbidden_hash
        )
        target["payload"]["intent_hash"] = self.clean_hash
        # The store itself changed (the edit was not on a detached copy):
        stored = next(r for r in state.audit if r["event"] == "permit_rejected")
        self.assertEqual(self.clean_hash, stored["payload"]["intent_hash"])
        self.assertFalse(kernel.verify_audit())

    def test_step3b_inmemory_kernel_audit_is_live_list_midchain_deletion_detected(self) -> None:
        # In-memory: del through kernel.audit deletes from the store.
        # Without rehashing, the deletion is detected by verify_audit().
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        ledger = ConsequenceLedger()
        self._run_mythos_story(kernel, ledger)
        self.assertTrue(kernel.verify_audit())
        index = next(
            i for i, r in enumerate(kernel.audit)
            if r["event"] == "permit_rejected"
            and r["payload"]["intent_hash"] == self.forbidden_hash
        )
        self.assertLess(index, len(kernel.audit) - 1)  # mid-chain
        length_before = len(state.audit)
        del kernel.audit[index]
        self.assertEqual(length_before - 1, len(state.audit))
        self.assertFalse(kernel.verify_audit())

    def test_step3b_sqlite_audit_reads_are_detached_copies(self) -> None:
        # On the SQLite backend, kernel.audit returns freshly built dicts:
        # editing the returned objects — the only record objects a reader
        # can reach — changes nothing in the store.
        with tempfile.TemporaryDirectory() as tmp:
            state = SQLiteKernelState(Path(tmp) / "kernel.sqlite3")
            kernel = self._kernel(state=state)
            ledger = ConsequenceLedger()
            self._run_mythos_story(kernel, ledger)
            snapshot = [dict(r, payload=dict(r["payload"])) for r in kernel.audit]
            for record in kernel.audit:
                record["payload"]["intent_hash"] = self.clean_hash
                record["event"] = "permit_consumed"
            self.assertEqual(snapshot, kernel.audit)
            self.assertTrue(kernel.verify_audit())
            state.close()

    # -- step 3b(ii): direct store tampering is detected -----------------------

    def test_step3b_inmemory_payload_edit_detected(self) -> None:
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        ledger = ConsequenceLedger()
        self._run_mythos_story(kernel, ledger)
        self.assertTrue(kernel.verify_audit())
        # Privileged store write (the test harness holds the backend object;
        # an agent reaching only the kernel API has no such handle): rewrite
        # history in place so the forbidden attempt's rejection record now
        # names the clean intent — the literal Mythos edit.
        target = next(
            r for r in state.audit
            if r["event"] == "permit_rejected"
            and r["payload"]["intent_hash"] == self.forbidden_hash
        )
        target["payload"]["intent_hash"] = self.clean_hash
        self.assertFalse(kernel.verify_audit())

    def test_step3b_inmemory_midchain_deletion_detected(self) -> None:
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        ledger = ConsequenceLedger()
        self._run_mythos_story(kernel, ledger)
        # In the incident's order (forbidden first, clean second) the
        # forbidden records sit mid-chain, followed by the clean step's.
        index = next(
            i for i, r in enumerate(state.audit)
            if r["event"] == "permit_rejected"
            and r["payload"]["intent_hash"] == self.forbidden_hash
        )
        self.assertLess(index, len(state.audit) - 1)
        del state.audit[index]
        # Without rehashing, deleting the record breaks the previous_hash
        # linkage of every record after it: the chain no longer verifies.
        # (With rehashing it verifies again — see the gap test below.)
        self.assertFalse(kernel.verify_audit())

    def test_step3b_sqlite_store_tamper_detected_and_boot_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kernel.sqlite3"
            state = SQLiteKernelState(path)
            kernel = self._kernel(state=state)
            ledger = ConsequenceLedger()
            self._run_mythos_story(kernel, ledger)
            self.assertTrue(kernel.verify_audit())
            state.close()
            # Privileged store write through a separate connection: rewrite
            # the forbidden rejection's stored payload to name the clean
            # intent instead.
            connection = sqlite3.connect(path)
            row = connection.execute(
                "SELECT sequence, payload_json FROM audit WHERE event = 'permit_rejected'"
            ).fetchone()
            self.assertIsNotNone(row)
            sequence, payload_json = row
            self.assertIn(self.forbidden_hash, payload_json)
            connection.execute(
                "UPDATE audit SET payload_json = ? WHERE sequence = ?",
                (payload_json.replace(self.forbidden_hash, self.clean_hash), sequence),
            )
            connection.commit()
            connection.close()
            # The live kernel object detects it...
            state2 = SQLiteKernelState(path)
            kernel2 = None
            try:
                # ...and a fresh kernel refuses to boot over the tampered
                # store at all: StateIntegrityError in the constructor.
                with self.assertRaises(StateIntegrityError):
                    kernel2 = self._kernel(state=state2)
            finally:
                if kernel2 is None:
                    state2.close()
            # Direct verification against the tampered store also fails.
            state3 = SQLiteKernelState(path)
            probe = GovernanceKernel.__new__(GovernanceKernel)
            probe._state = state3  # bypass bootstrap to interrogate the chain
            self.assertFalse(probe.verify_audit())
            state3.close()

    # -- step 3b(iii): the honest gaps — tail truncation AND rehashed deletion --

    def test_gap_tail_truncation_undetected_by_chain_alone(self) -> None:
        # GAP (reported, not hidden): the hash chain commits each record to
        # its predecessor, but nothing in the chain commits to the chain's
        # own length. If the records to erase are the LAST records in the
        # trail and a writer with direct store access deletes exactly that
        # tail, verification over the remaining prefix still passes — and
        # reconciliation against the truncated trail then finds nothing to
        # flag. Chain-only tamper-evidence covers edits and mid-chain
        # deletion WITHOUT rehashing (tests above); tail truncation — and
        # rehashed mid-chain deletion, next test — require an external
        # anchored head (witnessed head hash plus record count) that this
        # layer does not provide.
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        # Forbidden step ONLY, so its records are the tail of the trail.
        self._attempt_forbidden(kernel)
        tail = state.audit[-2:]
        self.assertEqual(["decision", "permit_rejected"], [r["event"] for r in tail])
        for record in tail:
            self.assertEqual(self.forbidden_hash, record["payload"]["intent_hash"])
        del state.audit[-2:]
        # The remaining prefix is a perfectly valid chain...
        self.assertTrue(kernel.verify_audit())
        # ...and the laundered claim now reconciles against it. The erasure
        # succeeded — under privileged store access, at the tail, with no
        # external anchor. This is the boundary of the tamper-evidence claim.
        result = reconcile_against_audit(kernel, self._laundered_claim())
        # (The claim's clean consequence is unbacked here — there was no
        # clean step in this run — but the ATTEMPT disclosure check, the one
        # the laundering targets, now passes vacuously.)
        self.assertEqual(frozenset(), result.undisclosed_attempts)

    def test_gap_midchain_deletion_with_rehash_undetected_by_chain_alone(self) -> None:
        # GAP (adversarial, privileged writer): the chain is public,
        # unkeyed SHA-256, so deleting a mid-chain record is NOT the end
        # of the attack. A writer with direct store access who deletes a
        # mid-chain record AND recomputes every following
        # previous_hash/hash (suffix rehash, using the production
        # canonical hashing) produces a chain that verify_audit() accepts.
        # The gap is therefore NOT limited to tail truncation. Closure
        # requires an external anchored head (witnessed head hash plus
        # record count): rehashing changes the head, and deletion changes
        # the length, so an anchored head detects both this and tail
        # truncation. This layer provides no such anchor.
        state = InMemoryKernelState()
        kernel = self._kernel(state=state)
        ledger = ConsequenceLedger()
        self._run_mythos_story(kernel, ledger)
        self.assertTrue(kernel.verify_audit())
        index = next(
            i for i, r in enumerate(kernel.audit)
            if r["event"] == "permit_rejected"
            and r["payload"]["intent_hash"] == self.forbidden_hash
        )
        self.assertLess(index, len(kernel.audit) - 1)  # mid-chain
        del kernel.audit[index]
        # Control: without rehashing the deletion is detected.
        self.assertFalse(kernel.verify_audit())
        rehash_suffix(kernel.audit, index)
        # After rehashing, chain verification alone accepts the rebuilt
        # chain — the record is gone and nothing in the chain objects.
        self.assertTrue(kernel.verify_audit())
        self.assertNotIn(
            "permit_rejected", [r["event"] for r in kernel.audit]
        )

    # -- step 5: negative control — agent-writable log launders cleanly --------

    def test_negative_control_agent_writable_log_launders_cleanly(self) -> None:
        # Same story, Sage architecture: the record of what happened is a
        # log the agent itself writes (from its action callbacks) and can
        # edit. The forbidden step is written, the clean step is written,
        # then the agent edits its own change history — the Mythos move —
        # and publishes the edited log as its history.
        log = AgentWritableLog()
        log.record(self.forbidden_hash, "attempt")
        log.record(self.clean_hash, "consequence")
        log.erase(self.forbidden_hash)  # the laundering edit
        # The claim is drawn from the same edited artifact, and the
        # reconciliation reference IS that artifact: claim and record are
        # one and the same agent-writable history.
        claim = {
            "consequences": [e["intent_hash"] for e in log.entries if e["kind"] == "consequence"],
            "attempts": [e["intent_hash"] for e in log.entries if e["kind"] == "attempt"],
        }
        ref_consequences, ref_attempts = log.sets()
        result = compare_claim(claim, ref_consequences, ref_attempts)
        # Identical comparison logic, opposite outcome: nothing flags,
        # because there is no independently held record to disagree.
        self.assertTrue(result.ok)
        # Contrast: the same claim, compared against a custody-held audit
        # trail of the same events (the main scenario), IS flagged.
        self._run_mythos_story(self.kernel, self.ledger)
        custody_result = reconcile_against_audit(self.kernel, claim)
        self.assertFalse(custody_result.ok)
        self.assertEqual(frozenset({self.forbidden_hash}), custody_result.undisclosed_attempts)


if __name__ == "__main__":
    unittest.main()

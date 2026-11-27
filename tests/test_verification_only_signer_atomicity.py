"""Finding 7 (Codex P1 on PR #420) — a verification-only audit signer
must never leave canonical state mutated without its signed record.

``CompositeAuditSigner`` with no signer raises on every ``sign()``.
The in-memory backend's mutating transitions recorded their mutations
FIRST and appended the signed audit record LAST, so the raise landed
after the mutation: ``consume_permit`` left the permit spent and the
budget debited with no ``permit_consumed`` record, and the sibling
transitions (permit issuance, directive binding, directive
activation/revocation, lease issuance, lease command consumption)
shared the ordering. The fix makes every in-memory transition atomic:
on any failure inside the transition the pre-transition state is
restored whole, so a failed signing leaves the state byte-identical.

The SQLite backend never shared the defect — every transition runs
inside a BEGIN IMMEDIATE transaction whose rollback on the same raise
discards the mutations — and two tests below pin that disposition.

Regression shape (per the verification report,
``p1-verification-2026-11-27.md`` Finding 7): with a verification-only
composite installed, each transition raises AND the state is
byte-identical to before the call.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import tempfile
import unittest

from pulpo.directives import Directive
from pulpo.state import (
    ApprovalUse,
    CompositeAuditSigner,
    InMemoryKernelState,
    LeaseIssuance,
    SQLiteKernelState,
    VerifiedAuthorityEvidence,
)

NOW = 1_000_000
PERMIT = "permit-1"
INTENT_HASH = "intent-1"
LEASE = "lease-1"
LEASE_DIGEST = "lease-digest-1"


class _StubVerifier:
    """One era's verifier half, without the cryptography extra: the
    composite below is verification-only because it has NO signer,
    which is the whole of the defect's trigger — its sign() raises
    the exact RuntimeError before any verifier is consulted. (The
    real Ed25519-backed composite is exercised in
    tests/test_audit_signing_ed25519.py; this file must also run in
    the zero-dependency CI job.)"""

    algorithm = "ed25519"

    def sign(self, record_hash: str) -> str:
        raise RuntimeError("verifier is verification-only")

    def verify(self, record_hash: str, signature) -> bool:
        return False


def verify_only_signer() -> CompositeAuditSigner:
    return CompositeAuditSigner(verifiers=[_StubVerifier()])


def make_directive(**overrides) -> Directive:
    values = dict(
        directive_id="dir-budget",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:worker",
        allowed_actions=frozenset({"push"}),
        resource_prefixes=("repo:",),
        max_cost=100,
        issued_at_ns=1,
        expires_at_ns=10_000_000,
        aggregate_budget=30,
        budget_scope=("directive",),
        budget_session_reset=False,
    )
    values.update(overrides)
    return Directive(**values)


def evidence(operation: str, directive: Directive) -> VerifiedAuthorityEvidence:
    return VerifiedAuthorityEvidence(
        operation=operation,
        directive_id=directive.directive_id,
        directive_version=directive.version,
        directive_hash=directive.directive_hash,
        parent_directive_hash=directive.parent_directive_hash,
        authority_id=directive.issuer_authority_id,
        approval_id="approval:test",
        envelope_hash="envelope:test",
        intent_hash="intent:test",
        policy_hash="policy:test",
    )


def snapshot(state: InMemoryKernelState) -> dict:
    """Every canonical container of the in-memory backend, detached."""
    return {
        "issued": deepcopy(state._issued),
        "permit_expiry": deepcopy(state._permit_expiry),
        "spent": deepcopy(state._spent),
        "approval_ids": deepcopy(state._approval_ids),
        "approval_nonces": deepcopy(state._approval_nonces),
        "ceremony_evidence_ids": deepcopy(state._ceremony_evidence_ids),
        "directives": deepcopy(state._directives),
        "directive_budgets": deepcopy(state._directive_budgets),
        "budget_spent": deepcopy(state._budget_spent),
        "directive_parents": deepcopy(state._directive_parents),
        "permit_directives": deepcopy(state._permit_directives),
        "leases": deepcopy(state._leases),
        "audit": state.audit,
    }


def budgeted_state() -> InMemoryKernelState:
    """The verification report's repro setup: an issued permit bound
    to a budgeted directive (aggregate_budget=30, budget_cost=10)."""
    directive = make_directive()
    state = InMemoryKernelState()
    state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW)
    state.activate_directive(directive, evidence("activate_directive", directive), NOW)
    binding = replace(
        directive.permit_binding,
        budget_principal="agent:worker",
        budget_session_id="s1",
        budget_cost=10,
    )
    state.bind_permit_to_directive(PERMIT, INTENT_HASH, binding, NOW)
    return state


def lease_issuance(directive: Directive) -> LeaseIssuance:
    return LeaseIssuance(
        lease_digest=LEASE_DIGEST,
        binding=directive.permit_binding,
        expires_at_ns=10_000_000,
        max_commands=3,
        sequence_floor=0,
        safe_fallback="hold-position",
    )


class VerificationOnlySignerAtomicityTests(unittest.TestCase):
    def test_consume_permit_leaves_state_byte_identical(self):
        state = budgeted_state()
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            state.consume_permit(PERMIT, INTENT_HASH, NOW)
        self.assertEqual(snapshot(state), before)
        self.assertNotIn(PERMIT, state._spent)
        self.assertEqual(state._budget_spent, {})
        self.assertEqual(len(state.audit), 3)
        # The permit was never spent: with the signer removed the
        # same consumption succeeds (pre-fix it returned False —
        # permit_rejected — because the spend had survived).
        state.audit_signer = None
        self.assertTrue(state.consume_permit(PERMIT, INTENT_HASH, NOW))

    def test_issue_permit_with_approval_leaves_state_byte_identical(self):
        state = InMemoryKernelState()
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        approval = ApprovalUse(
            approval_id="approval:1",
            nonce="nonce:1",
            audit_payload={"approval_id": "approval:1"},
            ceremony_evidence_id="evidence:1",
        )
        with self.assertRaises(RuntimeError):
            state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW, approval=approval)
        self.assertEqual(snapshot(state), before)
        self.assertEqual(state._issued, {})
        self.assertEqual(state._approval_ids, set())
        self.assertEqual(state._ceremony_evidence_ids, set())

    def test_bind_permit_to_directive_leaves_state_byte_identical(self):
        directive = make_directive()
        state = InMemoryKernelState()
        state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW)
        state.activate_directive(directive, evidence("activate_directive", directive), NOW)
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            state.bind_permit_to_directive(PERMIT, INTENT_HASH, directive.permit_binding, NOW)
        self.assertEqual(snapshot(state), before)
        self.assertEqual(state._permit_directives, {})

    def test_activate_directive_leaves_state_byte_identical(self):
        directive = make_directive()
        state = InMemoryKernelState()
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            state.activate_directive(directive, evidence("activate_directive", directive), NOW)
        self.assertEqual(snapshot(state), before)
        self.assertEqual(state._directives, {})
        self.assertEqual(state._directive_budgets, {})

    def test_revoke_directive_leaves_state_byte_identical(self):
        directive = make_directive()
        state = InMemoryKernelState()
        state.activate_directive(directive, evidence("activate_directive", directive), NOW)
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            state.revoke_directive(
                directive.directive_id,
                directive.version,
                evidence("revoke_directive", directive),
                NOW,
            )
        self.assertEqual(snapshot(state), before)
        self.assertEqual(
            state.directive_status(directive.directive_id, directive.version, directive.directive_hash),
            "active",
        )

    def test_issue_lease_leaves_state_byte_identical(self):
        directive = make_directive()
        state = InMemoryKernelState()
        state.activate_directive(directive, evidence("activate_directive", directive), NOW)
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            state.issue_lease(LEASE, INTENT_HASH, lease_issuance(directive), NOW)
        self.assertEqual(snapshot(state), before)
        self.assertEqual(state._leases, {})

    def test_consume_lease_command_leaves_state_byte_identical(self):
        directive = make_directive()
        state = InMemoryKernelState()
        state.activate_directive(directive, evidence("activate_directive", directive), NOW)
        state.issue_lease(LEASE, INTENT_HASH, lease_issuance(directive), NOW)
        before = snapshot(state)
        state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            state.consume_lease_command(LEASE, LEASE_DIGEST, INTENT_HASH, 1, NOW)
        self.assertEqual(snapshot(state), before)
        entry = state._leases[LEASE]
        self.assertEqual(entry.commands_used, 0)
        self.assertIsNone(entry.last_sequence)
        # The command was never recorded: with the signer removed the
        # same command consumes successfully.
        state.audit_signer = None
        self.assertTrue(state.consume_lease_command(LEASE, LEASE_DIGEST, INTENT_HASH, 1, NOW))


class SQLiteVerificationOnlySignerTests(unittest.TestCase):
    """Disposition evidence: the SQLite backend's transitions run
    inside BEGIN IMMEDIATE transactions, so the same signing raise
    rolls the mutations back — it never shared Finding 7."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = SQLiteKernelState(f"{self._tmp.name}/state.db")

    def tearDown(self):
        self.state.close()
        self._tmp.cleanup()

    def test_sqlite_consume_permit_rolls_back(self):
        self.state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW)
        audit_before = self.state.audit
        self.state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            self.state.consume_permit(PERMIT, INTENT_HASH, NOW)
        self.assertEqual(self.state.audit, audit_before)
        self.state.audit_signer = None
        self.assertTrue(self.state.consume_permit(PERMIT, INTENT_HASH, NOW))

    def test_sqlite_issue_permit_rolls_back(self):
        self.state.audit_signer = verify_only_signer()
        with self.assertRaises(RuntimeError):
            self.state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW)
        self.assertEqual(self.state.audit, [])
        self.state.audit_signer = None
        self.assertIsNone(self.state.issue_permit(PERMIT, INTENT_HASH, "allow", NOW))


if __name__ == "__main__":
    unittest.main()

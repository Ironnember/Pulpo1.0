"""Scenario tests: the wire-authorization reference deployment.

This module is the executable evidence for
``examples/wire_authorization/`` — a reference integration that routes a
payment-shaped consequence (a wire transfer to a MOCK rail; no real
funds move anywhere in this module) through the canonical governance
kernel. The "treasury operator" is this harness holding intents; the
only route from intent to consequence is the example service's governed
path: a verified approval envelope mints a one-use permit bound to the
exact intent hash, the kernel consumes it, and only then does the mock
rail record a transfer.

Failure modes modeled, one per test:

- happy path: propose -> envelope -> execute -> exactly one mock
  transfer, and the standalone evidence checker, run against the
  produced artifacts alone (SQLite state file + JSON-lines ledger),
  returns ``ok``;
- unauthorized payee: an approval minted for payee A presented with an
  intent for payee B is denied at evaluation and the ledger stays empty;
- amount substitution: $100.00 approved, $999.00 attempted — denied,
  ledger empty;
- replay: the same envelope executed twice (the second attempt is
  denied on approval replay, exactly one transfer), and a directly
  re-consumed permit (single use at the kernel layer);
- revocation before execution: a permit issued through
  ``GovernedDirectiveProjection`` under a standing directive and bound
  to it, the directive revoked through the canonical
  ``DirectiveAuthorityController`` path, then execution denied at
  consume — the kernel re-checks live directive status — ledger empty;
- negative control: under an intent-blind state double in the Hugging
  Face scenario's style, the amount-substituted execution DOES
  transfer, proving the denials come from the kernel's binding, not
  from a harness that denies by construction;
- checker reconciliation: a ledger entry with no governed consumption
  behind it fails the checker (no unaccounted effects in either
  direction).

Boundary: this proves the example's behavior at this commit, against
the kernel API at this commit (Verified, executable evidence). It
proves nothing about any deployed payment system — this rail is a mock
— and nothing about code that holds the rail, the ledger file, or the
state backend directly: that direct-writer class is outside the
governed path, as the module docstring of the service states.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state changed." A
denied evaluate appends its rejection/decision records and a denied
consume appends a ``permit_rejected`` record. That growth is a governed
effect — evidence production — append-only, and it does not alter
authority (``authority_effect=none``) or accumulate capability.
"Consequence" below means governed external consequence (a mock rail
transfer), never audit growth.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from examples.wire_authorization.check_evidence import main as checker_main
from examples.wire_authorization.rail import MockPaymentRail
from examples.wire_authorization.service import (
    EXAMPLE_PRINCIPAL,
    WireAuthorizationService,
    transfer_id_for,
)
from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
PRINCIPAL = EXAMPLE_PRINCIPAL
OPERATOR = "operator:owner"

ACME = "acme-corp"
GLOBEX = "globex-inc"

MAX_COST = 100_000_00

try:  # WS1 anchor seam: present only once sibling PR #352 lands.
    import pulpo.anchor  # noqa: F401

    ANCHOR_AVAILABLE = True
except ImportError:
    ANCHOR_AVAILABLE = False


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent permit
    spends for any intent. It exists only to prove the scenario's denial
    assertions discriminate — under this double the amount-substituted
    execution must TRANSFER, or the scenario would be denying by
    construction rather than by the kernel's binding. (Mirrors the
    Hugging Face scenario's negative-control double.)
    """

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        valid = permit in self._issued and permit not in self._spent
        if valid:
            self._spent.add(permit)
        self.append(
            "permit_consumed" if valid else "permit_rejected",
            {"intent_hash": intent_hash},
            timestamp_ns,
        )
        return valid


class WireAuthorizationExampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state_path = root / "state.db"
        self.ledger_path = root / "ledger.jsonl"
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"initiate_wire", "activate_directive", "revoke_directive"}),
            MAX_COST,
            frozenset({"initiate_wire", "activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        self.state = SQLiteKernelState(self.state_path)
        self.addCleanup(self.state.close)
        self.kernel = self._kernel(self.state)
        self.rail = MockPaymentRail(self.ledger_path)
        self.service = WireAuthorizationService(self.kernel, self.rail)

    def _kernel(self, state) -> GovernanceKernel:
        return GovernanceKernel(
            self.policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=state,
        )

    def _envelope(self, kernel: GovernanceKernel, intent: Intent, approval_id: str, nonce: str):
        return signed_envelope(
            kernel, intent, self.verifier, now_ns=NOW, approval_id=approval_id, nonce=nonce
        )

    def _run_checker(self, state_path: Path, ledger_path: Path) -> tuple[int, dict]:
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = checker_main(["--state", str(state_path), "--ledger", str(ledger_path)])
        return code, json.loads(stream.getvalue())

    # -- happy path -----------------------------------------------------

    def test_happy_path_governed_wire_transfers_once_and_checker_agrees(self) -> None:
        intent = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=250_00)
        self.assertEqual(
            Intent(PRINCIPAL, "initiate_wire", f"wire:{ACME}", 250_00, "default"), intent
        )
        envelope = self._envelope(self.kernel, intent, "approval-wire-1", "nonce-wire-1")
        result = self.service.execute(intent, envelope)

        self.assertEqual(("allow", "verified_approval"), (result.outcome, result.reason))
        self.assertEqual(self.kernel.intent_hash(intent), result.intent_hash)
        self.assertIsNotNone(result.transfer)
        transfer = result.transfer
        assert transfer is not None  # for type checkers; asserted above
        self.assertEqual(ACME, transfer["payee"])
        self.assertEqual(250_00, transfer["amount_cents"])
        self.assertEqual(transfer_id_for(result.intent_hash), transfer["transfer_id"])
        self.assertEqual("MOCK-NO-REAL-FUNDS", transfer["rail"])
        self.assertIs(True, transfer["mock"])
        # Anchor seam: in this build pulpo.anchor is absent, so a settled
        # transfer records the seam as unavailable; once WS1 lands and no
        # store is configured it records "not_configured" instead.
        self.assertEqual(
            "not_configured" if ANCHOR_AVAILABLE else "unavailable-in-this-build",
            result.anchoring,
        )
        # Exactly one external consequence, recorded identically in the
        # mock ledger file the checker will read.
        self.assertEqual([transfer], self.rail.records())
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

        # The evidence checker, from the artifacts alone, agrees.
        code, verdict = self._run_checker(self.state_path, self.ledger_path)
        self.assertEqual(0, code)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual([], verdict["failures"])
        self.assertEqual(1, verdict["transfers_checked"])
        self.assertEqual(False if ANCHOR_AVAILABLE else "unavailable", verdict["anchored"])

    # -- unauthorized payee ---------------------------------------------

    def test_unauthorized_payee_approval_for_another_payee_denied(self) -> None:
        approved = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=100_00)
        envelope = self._envelope(self.kernel, approved, "approval-wire-1", "nonce-wire-1")
        substituted = self.service.propose(principal=PRINCIPAL, payee=GLOBEX, amount_cents=100_00)

        result = self.service.execute(substituted, envelope)

        # The envelope binds the exact intent hash — payee included — so
        # presenting it for a different payee denies at evaluation, the
        # rail is never reached, and no permit is consumed or spent.
        self.assertEqual(("deny", "approval_intent_mismatch"), (result.outcome, result.reason))
        self.assertIsNone(result.transfer)
        self.assertEqual([], self.rail.records())
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- amount substitution ---------------------------------------------

    def test_amount_substitution_approved_100_executed_999_denied(self) -> None:
        approved = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=100_00)
        envelope = self._envelope(self.kernel, approved, "approval-wire-1", "nonce-wire-1")
        substituted = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=999_00)
        # Both amounts are inside the policy ceiling, so the denial below
        # is the exact intent binding, not the budget check.
        self.assertLess(substituted.cost, MAX_COST)

        result = self.service.execute(substituted, envelope)

        self.assertEqual(("deny", "approval_intent_mismatch"), (result.outcome, result.reason))
        self.assertIsNone(result.transfer)
        self.assertEqual([], self.rail.records())
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        self.assertTrue(self.kernel.verify_audit())

    # -- replay -----------------------------------------------------------

    def test_replay_same_envelope_twice_and_direct_permit_reconsume_denied(self) -> None:
        intent = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=250_00)
        envelope = self._envelope(self.kernel, intent, "approval-wire-1", "nonce-wire-1")

        first = self.service.execute(intent, envelope)
        self.assertEqual("allow", first.outcome)
        second = self.service.execute(intent, envelope)

        # The envelope is single-use: its approval id/nonce are already
        # recorded, so the replay denies before any new permit exists.
        self.assertEqual(("deny", "approval_id_replayed"), (second.outcome, second.reason))
        self.assertIsNone(second.transfer)
        self.assertEqual(1, len(self.rail.records()))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))

        # Direct permit re-consume, at the kernel layer: a fresh permit
        # for a new intent spends exactly once. This probe deliberately
        # bypasses the service to isolate kernel single-use; it effects
        # no transfer, and its artifacts are not presented as a complete
        # deployment record (the checker would — correctly — flag a
        # consumption with no matching transfer in such a record).
        other = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=700_00)
        other_envelope = self._envelope(self.kernel, other, "approval-wire-2", "nonce-wire-2")
        decision = self.kernel.evaluate_with_approval(other, other_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertTrue(self.kernel.consume(decision.permit, other))  # type: ignore[arg-type]
        self.assertFalse(self.kernel.consume(decision.permit, other))  # type: ignore[arg-type]
        self.assertEqual(1, len(self.rail.records()))
        self.assertTrue(self.kernel.verify_audit())

    # -- revocation before execution --------------------------------------

    def test_revocation_before_execution_kills_directive_bound_permit(self) -> None:
        # A second deployment instance whose standing authorization is a
        # directive: initiate_wire is directive-governed here (not an
        # approval action), so permits are minted through the canonical
        # GovernedDirectiveProjection and bound to the directive at
        # issue; activation/revocation themselves require verified
        # approval through DirectiveAuthorityController.
        root = Path(self._tmp.name)
        state = SQLiteKernelState(root / "state-directive.db")
        self.addCleanup(state.close)
        directive_policy = Policy(
            frozenset({"initiate_wire", "activate_directive", "revoke_directive"}),
            MAX_COST,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        kernel = GovernanceKernel(
            directive_policy,
            secret=b"unit-test-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=state,
        )
        rail = MockPaymentRail(root / "ledger-directive.jsonl")
        service = WireAuthorizationService(kernel, rail)
        directive = Directive(
            directive_id="wire-standing-order",
            version=1,
            issuer_authority_id="authority:test-owner",
            principal=PRINCIPAL,
            allowed_actions=frozenset({"initiate_wire"}),
            resource_prefixes=("wire:",),
            max_cost=MAX_COST,
            issued_at_ns=900_000,
            expires_at_ns=2_000_000,
        )
        controller = DirectiveAuthorityController(kernel)

        def approve(operation: str, approval_id: str, nonce: str):
            authority_intent = controller.authority_intent(
                operation, directive, operator_principal=OPERATOR
            )
            return signed_envelope(
                kernel,
                authority_intent,
                self.verifier,
                now_ns=NOW,
                approval_id=approval_id,
                nonce=nonce,
            )

        activated = controller.activate(
            directive,
            approve(controller.ACTIVATE, "approval-activate-1", "nonce-activate-1"),
            operator_principal=OPERATOR,
        )
        self.assertEqual("allow", activated.outcome)

        intent = service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=500_00)
        projection = GovernedDirectiveProjection(kernel)
        decision = projection.evaluate(intent, directive)
        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        self.assertEqual(1, len(_events(kernel, "permit_bound_to_directive")))

        # The standing authorization is withdrawn after issuance.
        revoked = controller.revoke(
            directive,
            approve(controller.REVOKE, "approval-revoke-1", "nonce-revoke-1"),
            operator_principal=OPERATOR,
        )
        self.assertEqual("allow", revoked.outcome)
        self.assertEqual(1, len(_events(kernel, "directive_revoked")))

        # Execution now denies at consume: the kernel re-checks the
        # permit's live directive status, and the rejection records why.
        result = service.execute_with_permit(intent, decision.permit)
        self.assertEqual(("deny", "permit_consumption_failed"), (result.outcome, result.reason))
        self.assertIsNone(result.transfer)
        self.assertEqual([], rail.records())
        rejected = [
            record
            for record in _events(kernel, "permit_rejected")
            if record["payload"]["intent_hash"] == kernel.intent_hash(intent)
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual("directive_revoked", rejected[0]["payload"]["directive_status"])
        self.assertTrue(kernel.verify_audit())

    # -- negative control ---------------------------------------------------

    def test_negative_control_intent_blind_consume_would_transfer_substituted_amount(self) -> None:
        # Same amount-substitution attempt, two backends. The permit is
        # genuinely minted for $100.00 in both; the substituted $999.00
        # intent is then presented for consumption through the service's
        # permit path.
        def attempt(state) -> tuple[WireResult, MockPaymentRail]:
            kernel = self._kernel(state)
            rail = MockPaymentRail(Path(self._tmp.name) / f"ledger-{type(state).__name__}.jsonl")
            service = WireAuthorizationService(kernel, rail)
            approved = service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=100_00)
            envelope = self._envelope(kernel, approved, "approval-wire-1", "nonce-wire-1")
            decision = kernel.evaluate_with_approval(approved, envelope)
            self.assertEqual("allow", decision.outcome)
            substituted = service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=999_00)
            return service.execute_with_permit(substituted, decision.permit), rail

        # Under the intent-blind double the substituted execution
        # TRANSFERS: the double's consume spends any permit for any
        # intent, so the harness path itself does not deny.
        blind_result, blind_rail = attempt(_IntentBlindState())
        self.assertEqual("allow", blind_result.outcome)
        self.assertIsNotNone(blind_result.transfer)
        self.assertEqual(999_00, blind_result.transfer["amount_cents"])  # type: ignore[index]
        self.assertEqual(1, len(blind_rail.records()))

        # Contrast, identical attempt against the real backend: denied
        # at consume, no consequence.
        real_result, real_rail = attempt(InMemoryKernelState())
        self.assertEqual(("deny", "permit_consumption_failed"), (real_result.outcome, real_result.reason))
        self.assertIsNone(real_result.transfer)
        self.assertEqual([], real_rail.records())

    # -- checker reconciliation --------------------------------------------

    def test_checker_rejects_ledger_transfer_without_governed_consumption(self) -> None:
        intent = self.service.propose(principal=PRINCIPAL, payee=ACME, amount_cents=250_00)
        envelope = self._envelope(self.kernel, intent, "approval-wire-1", "nonce-wire-1")
        self.assertEqual("allow", self.service.execute(intent, envelope).outcome)
        code, verdict = self._run_checker(self.state_path, self.ledger_path)
        self.assertEqual((0, True), (code, verdict["ok"]))

        # A fabricated external record — written directly to the ledger
        # file, the direct-writer move — has no approval, no consumption,
        # and a transfer id that matches no reconstructed intent: the
        # checker must fail, not average it away.
        fabricated = {
            "transfer_id": "wire-" + "f" * 64,
            "payee": "mallory",
            "amount_cents": 100,
            "rail": "MOCK-NO-REAL-FUNDS",
            "mock": True,
        }
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(fabricated, sort_keys=True) + "\n")
        code, verdict = self._run_checker(self.state_path, self.ledger_path)
        self.assertEqual(1, code)
        self.assertFalse(verdict["ok"])
        self.assertEqual(2, verdict["transfers_checked"])
        self.assertTrue(verdict["failures"])


if __name__ == "__main__":
    unittest.main()

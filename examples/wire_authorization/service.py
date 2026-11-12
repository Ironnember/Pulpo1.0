"""Governed wire-authorization service — the example's only effect path.

A wire transfer is a consequential, irreversible-shaped action, which is
why this reference deployment routes it through the canonical governance
kernel instead of calling the (mock) rail directly:

1. ``propose`` builds the exact intent: action ``initiate_wire``,
   resource ``wire:<payee>``, ``cost`` = amount in cents, plus the
   principal and session. The kernel's intent hash binds every field, so
   an approval for one payee or amount cannot authorize another.
2. ``execute`` asks the kernel to evaluate that intent against a verified
   approval envelope (``GovernanceKernel.evaluate_with_approval``). Any
   outcome other than ``allow`` with a permit is returned as a denial and
   the rail is never touched.
3. The one-use permit is consumed (``GovernanceKernel.consume``), which
   re-checks the exact intent binding — and, for directive-bound permits,
   the live directive status — at consequence time.
4. Only a successful consume reaches the mock rail, with a transfer id
   derived deterministically from the intent hash so the external record
   can later be reconciled 1:1:1 against ``approval_verified`` and
   ``permit_consumed`` audit records by the evidence checker.
5. After a settled transfer the service attempts the WS1 anchor seam
   (see below). Anchoring is observation, not governance: it appends
   nothing to the canonical audit chain and grants no authority.

Two governed entry points share the same consume-then-effect tail:

- ``execute(intent, envelope)`` for approval-minted permits (the primary
  path), and
- ``execute_with_permit(intent, permit)`` for permits that were issued
  and bound outside this call — in this example, permits issued through
  ``GovernedDirectiveProjection`` under a standing directive. Issuance
  and consumption are separate moments there, which is what allows a
  directive revocation landing between them to kill the permit before
  any effect, exactly as the kernel's consume-time re-check provides.

The rail is held privately and no public attribute exposes it, so within
this example's public API there is no ungoverned route to a transfer.
That is a statement about this example's API shape, not a claim about
the host: code holding the rail object or the state backend directly is
the known direct-writer class, outside the governed path and outside
this example's evidence — the scenario tests state that boundary and
the checker exists to reconcile the artifacts such writers would leave
inconsistent.

Two boundary rules keep the produced artifacts reconcilable:

- **One settlement per intent hash.** The transfer id and the
  checker's correspondence both key on the intent hash, so a second,
  independently approved execution of the identical intent is refused
  by ``_settle`` (reason ``intent_already_settled``) after evaluation
  and *before* its permit is consumed. A genuinely repeated wire is a
  new intent — in this example's shape, a new session — not a second
  settlement of the same intent hash.
- **Wire fields are validated before evaluation.** A directly
  constructed intent whose payee is empty or whose cost is not an
  exact positive integer is refused at the service boundary (reason
  ``wire_fields_malformed``) before any permit exists to spend — never
  discovered by the rail after the one-use permit is already gone.

Anchor seam (WS1, sibling PR #352): when ``pulpo.anchor`` is importable
and an ``anchor_store`` is configured, a settled transfer is followed by
``anchor_state(state, store, signer=...)`` and the result records
``anchoring="anchored"``. In this build ``pulpo.anchor`` is not present,
so the seam fails soft at import and the result records
``anchoring="unavailable-in-this-build"``. An anchor failure after a
settled transfer is recorded as ``"anchor_failed"`` and does not undo
the transfer — anchoring witnesses the audit trail, it does not gate
effects; an operator seeing ``"anchor_failed"`` must reconcile the
witness gap explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pulpo.kernel import GovernanceKernel, Intent

from .rail import MockPaymentRail


WIRE_ACTION = "initiate_wire"
WIRE_RESOURCE_PREFIX = "wire:"

# Illustrative principal for the reference deployment's own scenario
# tests and the evidence checker's default reconstruction. A deployment
# chooses its own principal and passes it to the checker with
# ``--principal``; the value itself carries no authority.
EXAMPLE_PRINCIPAL = "operator:treasury"


def transfer_id_for(intent_hash: str) -> str:
    """Deterministic mock-rail transfer id derived from the intent hash."""
    return f"wire-{intent_hash}"


@dataclass(frozen=True)
class WireResult:
    """Outcome of one governed wire execution attempt.

    ``transfer`` is the mock rail record when, and only when, a transfer
    was effected; it is ``None`` for every denial. ``anchoring`` records
    the anchor seam's state for settled transfers (``"anchored"``,
    ``"unavailable-in-this-build"``, ``"not_configured"``, or
    ``"anchor_failed"``) and ``"not_attempted"`` when nothing settled.
    The permit itself is deliberately never part of the result: permit
    custody stays inside the execution call.
    """

    outcome: str
    reason: str
    intent_hash: str
    transfer: dict[str, Any] | None
    anchoring: str


class WireAuthorizationService:
    """Propose and execute wire intents under the governance kernel."""

    def __init__(
        self,
        kernel: GovernanceKernel,
        rail: MockPaymentRail,
        *,
        anchor_store: Any = None,
        anchor_signer: Any = None,
    ) -> None:
        self._kernel = kernel
        self._rail = rail
        self._anchor_store = anchor_store
        self._anchor_signer = anchor_signer

    def propose(
        self,
        *,
        principal: str,
        payee: str,
        amount_cents: int,
        session_id: str = "default",
    ) -> Intent:
        """Build the exact wire intent an approval must bind.

        Proposal is ephemeral: it appends nothing to canonical state and
        grants nothing. Committing the proposal to an effect requires
        ``execute`` / ``execute_with_permit`` and the kernel.
        """
        if not isinstance(principal, str) or not principal:
            raise ValueError("principal must be a non-empty string")
        if not isinstance(payee, str) or not payee:
            raise ValueError("payee must be a non-empty string")
        if isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or amount_cents <= 0:
            raise ValueError("amount_cents must be a positive integer")
        return Intent(
            principal=principal,
            action=WIRE_ACTION,
            resource=f"{WIRE_RESOURCE_PREFIX}{payee}",
            cost=amount_cents,
            session_id=session_id,
        )

    def execute(self, intent: Intent, envelope: Any) -> WireResult:
        """Execute a wire intent against a verified approval envelope.

        Unless the kernel returns ``allow`` with a permit, the denial is
        returned verbatim and the rail is never touched.
        """
        refusal = self._non_wire_refusal(intent)
        if refusal is not None:
            return refusal
        decision = self._kernel.evaluate_with_approval(intent, envelope)
        if decision.outcome != "allow" or decision.permit is None:
            return WireResult(
                outcome="deny",
                reason=decision.reason,
                intent_hash=decision.intent_hash,
                transfer=None,
                anchoring="not_attempted",
            )
        return self._settle(intent, decision.permit, success_reason=decision.reason)

    def execute_with_permit(self, intent: Intent, permit: str | None) -> WireResult:
        """Execute a wire intent by consuming a previously issued permit.

        For permits issued outside ``execute`` — in this example, permits
        minted through ``GovernedDirectiveProjection`` and bound to a
        standing directive at issue. Consumption re-checks the exact
        intent binding and the permit's live directive status, so a
        revocation landing after issuance denies here, before any effect.
        """
        refusal = self._non_wire_refusal(intent)
        if refusal is not None:
            return refusal
        digest = self._kernel.intent_hash(intent)
        if not permit:
            return WireResult(
                outcome="deny",
                reason="permit_missing",
                intent_hash=digest,
                transfer=None,
                anchoring="not_attempted",
            )
        return self._settle(intent, permit, success_reason="permit_consumed")

    def _non_wire_refusal(self, intent: Intent) -> WireResult | None:
        """Refuse non-wire and malformed-wire intents at the boundary.

        Input shaping only: this service settles wires, and a permit for
        any other action must never be spent as a wire transfer here.
        The kernel remains the authority for wire intents themselves.

        ``propose`` already validates what it builds, but an intent can
        also be constructed directly. The wire fields are therefore
        validated here — extracted payee non-empty, cost an exact
        positive integer (booleans and non-integers rejected) — BEFORE
        evaluation and consumption, so a malformed wire is refused
        while no permit has been spent on it, instead of surfacing as
        a rail validation error after the one-use permit is gone (a
        phantom ``permit_consumed`` with no transfer, unretryable).
        """
        digest = self._kernel.intent_hash(intent)
        if (
            intent.action != WIRE_ACTION
            or not isinstance(intent.resource, str)
            or not intent.resource.startswith(WIRE_RESOURCE_PREFIX)
        ):
            return WireResult(
                outcome="deny",
                reason="intent_not_a_wire",
                intent_hash=digest,
                transfer=None,
                anchoring="not_attempted",
            )
        payee = intent.resource[len(WIRE_RESOURCE_PREFIX):]
        if (
            not payee
            or isinstance(intent.cost, bool)
            or not isinstance(intent.cost, int)
            or intent.cost <= 0
        ):
            return WireResult(
                outcome="deny",
                reason="wire_fields_malformed",
                intent_hash=digest,
                transfer=None,
                anchoring="not_attempted",
            )
        return None

    def _settle(self, intent: Intent, permit: str, *, success_reason: str) -> WireResult:
        digest = self._kernel.intent_hash(intent)
        # One settlement per intent hash (see the module docstring):
        # the transfer id and the evidence checker's correspondence key
        # on the intent hash, so settling the same intent twice — each
        # time under its own valid approval — would produce two effects
        # with one identity and records no checker can reconcile 1:1:1.
        # Refuse here, after evaluation and before consumption, so the
        # second permit is never spent on an ambiguous effect. The scan
        # is a read of the canonical audit; it appends and grants
        # nothing.
        if any(
            record.get("event") == "permit_consumed"
            and (record.get("payload") or {}).get("intent_hash") == digest
            for record in self._kernel.audit
        ):
            return WireResult(
                outcome="deny",
                reason="intent_already_settled",
                intent_hash=digest,
                transfer=None,
                anchoring="not_attempted",
            )
        if not self._kernel.consume(permit, intent):
            return WireResult(
                outcome="deny",
                reason="permit_consumption_failed",
                intent_hash=digest,
                transfer=None,
                anchoring="not_attempted",
            )
        payee = intent.resource[len(WIRE_RESOURCE_PREFIX):]
        transfer = self._rail.transfer(
            payee=payee,
            amount_cents=intent.cost,
            transfer_id=transfer_id_for(digest),
        )
        return WireResult(
            outcome="allow",
            reason=success_reason,
            intent_hash=digest,
            transfer=transfer,
            anchoring=self._anchor_settled_state(),
        )

    def _anchor_settled_state(self) -> str:
        """Attempt the WS1 anchor seam; return its recorded status.

        Observation only, after settlement. See the module docstring for
        the seam contract and the meaning of each status string.
        """
        try:
            from pulpo.anchor import anchor_state
        except ImportError:
            return "unavailable-in-this-build"
        if self._anchor_store is None:
            return "not_configured"
        try:
            anchor_state(
                self._kernel._state,
                self._anchor_store,
                signer=self._anchor_signer,
            )
        except Exception:
            return "anchor_failed"
        return "anchored"

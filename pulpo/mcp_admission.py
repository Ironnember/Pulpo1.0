"""Governed trusted-side admission for capability-free MCP proposals.

The MCP/plugin process remains proposal-only. This module belongs on the
trusted Pulpo side and converts one exact ``pulpo.mcp-proposal.v2`` payload into
the existing durable ``LockedTarget`` only after the existing kernel consumes a
permit for that exact admission transition. It creates no authority, policy,
executor, router, or evidence ledger.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
from typing import Any

from .kernel import GovernanceKernel, Intent, LockedTarget
from .orchestrator import PulpoOrchestrator


PROPOSAL_SCHEMA = "pulpo.mcp-proposal.v2"
ADMISSION_ACTION = "admit_mcp_proposal"
ADMISSION_RESOURCE_PREFIX = "mcp-proposal:"
MAX_TARGET_ID_LENGTH = 256
MAX_PRINCIPAL_LENGTH = 256
MAX_ACTION_LENGTH = 128
MAX_RESOURCE_LENGTH = 4_096
MAX_SESSION_ID_LENGTH = 256


class MCPProposalAdmissionError(ValueError):
    """An MCP proposal could not cross the governed admission boundary."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _require_digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MCPProposalAdmissionError(f"{field}_invalid")
    return value


def _require_text(value: object, field: str, *, max_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
    ):
        raise MCPProposalAdmissionError(f"{field}_invalid")
    return value


@dataclass(frozen=True, slots=True)
class ValidatedMCPProposal:
    target_id: str
    target_version: int
    intent: Intent
    intent_hash: str
    policy_hash: str
    freshness: str = "frozen"
    canonical_state_mutation: bool = False
    governed_effect: str = "none"
    authority_effect: str = "none"
    schema: str = PROPOSAL_SCHEMA

    @property
    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "target_id": self.target_id,
            "target_version": self.target_version,
            "intent": asdict(self.intent),
            "intent_hash": self.intent_hash,
            "policy_hash": self.policy_hash,
            "freshness": self.freshness,
            "canonical_state_mutation": self.canonical_state_mutation,
            "governed_effect": self.governed_effect,
            "authority_effect": self.authority_effect,
        }

    @property
    def proposal_hash(self) -> str:
        return _hash(self.payload)


@dataclass(frozen=True, slots=True)
class MCPProposalAdmissionReceipt:
    proposal_hash: str
    admission_intent_hash: str
    policy_hash: str
    target_id: str
    target_version: int
    target_hash: str
    proposed_intent_hash: str
    target_audit_tip: str
    authority_effect: str = "none"
    governed_effect: str = "canonical_target_lock_and_admission_evidence"
    canonical_state_mutation: bool = True
    schema: str = "pulpo.mcp-proposal-admission.v0"

    def __post_init__(self) -> None:
        for field in (
            "proposal_hash",
            "admission_intent_hash",
            "policy_hash",
            "target_hash",
            "proposed_intent_hash",
            "target_audit_tip",
        ):
            _require_digest(getattr(self, field), field)
        if not self.target_id or self.target_version <= 0:
            raise MCPProposalAdmissionError("mcp_admission_target_invalid")
        if self.authority_effect != "none":
            raise MCPProposalAdmissionError("mcp_admission_authority_effect_invalid")
        if (
            self.governed_effect != "canonical_target_lock_and_admission_evidence"
            or self.canonical_state_mutation is not True
        ):
            raise MCPProposalAdmissionError("mcp_admission_governed_effect_invalid")
        if self.schema != "pulpo.mcp-proposal-admission.v0":
            raise MCPProposalAdmissionError("mcp_admission_schema_invalid")

    @property
    def receipt_hash(self) -> str:
        return _hash(asdict(self))


def validate_mcp_proposal(value: Any) -> ValidatedMCPProposal:
    """Validate the exact capability-free proposal schema without side effects."""

    expected_fields = {
        "schema",
        "target_id",
        "target_version",
        "intent",
        "intent_hash",
        "policy_hash",
        "freshness",
        "canonical_state_mutation",
        "governed_effect",
        "authority_effect",
    }
    if type(value) is not dict or set(value) != expected_fields:
        raise MCPProposalAdmissionError("mcp_proposal_fields_invalid")
    if value["schema"] != PROPOSAL_SCHEMA:
        raise MCPProposalAdmissionError("mcp_proposal_schema_invalid")
    if (
        value["freshness"] != "frozen"
        or value["canonical_state_mutation"] is not False
        or value["governed_effect"] != "none"
        or value["authority_effect"] != "none"
    ):
        raise MCPProposalAdmissionError("mcp_proposal_capability_claim_invalid")

    target_id = _require_text(
        value["target_id"],
        "mcp_proposal_target",
        max_length=MAX_TARGET_ID_LENGTH,
    )
    target_version = value["target_version"]
    if isinstance(target_version, bool) or not isinstance(target_version, int) or target_version <= 0:
        raise MCPProposalAdmissionError("mcp_proposal_target_invalid")

    raw_intent = value["intent"]
    intent_fields = {"principal", "action", "resource", "cost", "session_id"}
    if type(raw_intent) is not dict or set(raw_intent) != intent_fields:
        raise MCPProposalAdmissionError("mcp_proposal_intent_invalid")
    principal = _require_text(
        raw_intent["principal"],
        "mcp_proposal_intent",
        max_length=MAX_PRINCIPAL_LENGTH,
    )
    action = _require_text(
        raw_intent["action"],
        "mcp_proposal_intent",
        max_length=MAX_ACTION_LENGTH,
    )
    resource = _require_text(
        raw_intent["resource"],
        "mcp_proposal_intent",
        max_length=MAX_RESOURCE_LENGTH,
    )
    session_id = _require_text(
        raw_intent["session_id"],
        "mcp_proposal_intent",
        max_length=MAX_SESSION_ID_LENGTH,
    )
    cost = raw_intent["cost"]
    if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
        raise MCPProposalAdmissionError("mcp_proposal_intent_invalid")

    intent = Intent(
        principal=principal,
        action=action,
        resource=resource,
        cost=cost,
        session_id=session_id,
    )
    intent_hash = _require_digest(value["intent_hash"], "mcp_proposal_intent_hash")
    if not hmac.compare_digest(intent_hash, GovernanceKernel.intent_hash(intent)):
        raise MCPProposalAdmissionError("mcp_proposal_intent_hash_mismatch")

    return ValidatedMCPProposal(
        target_id=target_id,
        target_version=target_version,
        intent=intent,
        intent_hash=intent_hash,
        policy_hash=_require_digest(value["policy_hash"], "mcp_proposal_policy_hash"),
    )


class MCPProposalAdmissionController:
    """Commit one proposal through the existing kernel's one-use permit path."""

    __slots__ = ("_orchestrator",)
    EVENT = "mcp_proposal_admitted"

    def __init__(self, orchestrator: PulpoOrchestrator) -> None:
        if type(orchestrator) is not PulpoOrchestrator:
            raise TypeError("canonical PulpoOrchestrator required")
        self._orchestrator = orchestrator

    @property
    def kernel(self) -> GovernanceKernel:
        return self._orchestrator.kernel

    def _current(self, value: Any) -> ValidatedMCPProposal:
        proposal = validate_mcp_proposal(value)
        if not hmac.compare_digest(proposal.policy_hash, self.kernel.policy_hash):
            raise MCPProposalAdmissionError("mcp_proposal_policy_stale")
        return proposal

    @staticmethod
    def _require_identity(value: object, field: str) -> str:
        return _require_text(
            value,
            f"mcp_admission_{field}",
            max_length=MAX_PRINCIPAL_LENGTH if field == "principal" else MAX_SESSION_ID_LENGTH,
        )

    def admission_intent(
        self,
        value: Any,
        *,
        principal: str,
        session_id: str,
    ) -> Intent:
        """Construct the exact policy input for one proposal-lock transition."""

        proposal = self._current(value)
        actor = self._require_identity(principal, "principal")
        session = self._require_identity(session_id, "session")
        resource = (
            f"{ADMISSION_RESOURCE_PREFIX}{proposal.proposal_hash}"
            f":policy:{self.kernel.policy_hash}"
        )
        return Intent(actor, ADMISSION_ACTION, resource, 0, session)

    def admit(
        self,
        value: Any,
        permit: str,
        *,
        principal: str,
        session_id: str,
    ) -> tuple[LockedTarget, MCPProposalAdmissionReceipt]:
        """Consume exact admission authority, then lock the proposed target once."""

        proposal = self._current(value)
        transition = self.admission_intent(
            proposal.payload,
            principal=principal,
            session_id=session_id,
        )
        existing = self.kernel.get_locked_target(
            proposal.target_id,
            version=proposal.target_version,
        )
        if existing is not None:
            reason = (
                "mcp_proposal_target_already_locked"
                if existing.intent == proposal.intent
                else "mcp_proposal_target_conflict"
            )
            raise MCPProposalAdmissionError(reason)
        if not isinstance(permit, str) or not permit:
            raise MCPProposalAdmissionError("mcp_proposal_admission_permit_required")
        if not self.kernel.consume(permit, transition):
            raise MCPProposalAdmissionError("mcp_proposal_admission_permit_rejected")

        audit = self.kernel.audit
        transition_hash = self.kernel.intent_hash(transition)
        if (
            not audit
            or audit[-1].get("event") != "permit_consumed"
            or audit[-1].get("payload", {}).get("intent_hash") != transition_hash
        ):
            raise MCPProposalAdmissionError("mcp_proposal_admission_commit_unknown")
        consumption_tip = audit[-1]["hash"]

        try:
            target = self._orchestrator.lock_target(
                proposal.target_id,
                proposal.intent,
                version=proposal.target_version,
            )
        except Exception as exc:
            raise MCPProposalAdmissionError("mcp_proposal_admission_commit_unknown") from exc

        audit = self.kernel.audit
        if (
            not audit
            or audit[-1].get("event") != "target_locked"
            or audit[-1].get("previous_hash") != consumption_tip
            or audit[-1].get("payload", {}).get("target_hash") != target.target_hash
            or audit[-1].get("payload", {}).get("intent_hash") != proposal.intent_hash
        ):
            raise MCPProposalAdmissionError("mcp_proposal_admission_commit_unknown")
        target_audit_tip = audit[-1]["hash"]

        receipt = MCPProposalAdmissionReceipt(
            proposal_hash=proposal.proposal_hash,
            admission_intent_hash=transition_hash,
            policy_hash=self.kernel.policy_hash,
            target_id=target.target_id,
            target_version=target.version,
            target_hash=target.target_hash,
            proposed_intent_hash=proposal.intent_hash,
            target_audit_tip=target_audit_tip,
        )
        now_ns = self.kernel._trusted_now()
        if now_ns is None:
            raise MCPProposalAdmissionError("mcp_proposal_admission_commit_unknown")
        try:
            self.kernel._state.append(
                self.EVENT,
                {
                    "receipt": asdict(receipt),
                    "receipt_hash": receipt.receipt_hash,
                    "authority_effect": "none",
                    "governed_effect": "canonical_target_lock_and_admission_evidence",
                    "canonical_state_mutation": True,
                },
                now_ns,
            )
        except Exception as exc:
            raise MCPProposalAdmissionError("mcp_proposal_admission_commit_unknown") from exc

        final = self.kernel.audit[-1]
        if (
            final.get("event") != self.EVENT
            or final.get("previous_hash") != target_audit_tip
            or final.get("payload", {}).get("receipt_hash") != receipt.receipt_hash
            or not self.kernel.verify_audit()
        ):
            raise MCPProposalAdmissionError("mcp_proposal_admission_commit_unknown")
        return target, receipt

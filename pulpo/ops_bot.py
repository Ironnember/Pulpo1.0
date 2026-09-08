"""Capability-free operations bot core for payment reconciliation and proposals.

This module is intentionally non-authoritative. It can compare supplied payment
records and construct exact scheduling or lead-procurement proposals. It does
not hold a governance kernel, authority credential, canonical state writer,
payment rail, calendar writer, lead-data buyer, or outreach sender.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from hashlib import sha256
import json
from typing import Any, Iterable


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _require_text(value: str, field: str, *, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty text")
    value = value.strip()
    if len(value) > max_len:
        raise ValueError(f"{field} exceeds limit")
    return value


def _money_to_minor(value: str | int, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be money")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{field} must be non-negative")
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be money")
    try:
        amount = Decimal(value.strip()).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except InvalidOperation as exc:
        raise ValueError(f"{field} must be money") from exc
    if amount < 0:
        raise ValueError(f"{field} must be non-negative")
    return int(amount * 100)


@dataclass(frozen=True)
class PaymentRecord:
    reference: str
    amount_minor: int
    currency: str
    occurred_at: str = "unknown"

    def __post_init__(self) -> None:
        _require_text(self.reference, "reference", max_len=256)
        if isinstance(self.amount_minor, bool) or not isinstance(self.amount_minor, int) or self.amount_minor < 0:
            raise ValueError("amount_minor must be a non-negative integer")
        currency = _require_text(self.currency, "currency", max_len=3).upper()
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("currency must be a three-letter code")
        object.__setattr__(self, "currency", currency)
        _require_text(self.occurred_at, "occurred_at", max_len=128)

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "PaymentRecord":
        if not isinstance(value, dict):
            raise ValueError("payment record must be an object")
        if "amount_minor" in value:
            raw_minor = value["amount_minor"]
            if isinstance(raw_minor, bool):
                raise ValueError("amount_minor must be a non-negative integer")
            try:
                amount_minor = int(raw_minor)
            except (TypeError, ValueError) as exc:
                raise ValueError("amount_minor must be a non-negative integer") from exc
            if amount_minor < 0 or str(amount_minor) != str(raw_minor).strip():
                raise ValueError("amount_minor must be a non-negative integer")
        else:
            amount_minor = _money_to_minor(value.get("amount", ""), "amount")
        return cls(
            reference=value.get("reference", ""),
            amount_minor=amount_minor,
            currency=value.get("currency", ""),
            occurred_at=value.get("occurred_at", "unknown"),
        )


@dataclass(frozen=True)
class ReconciliationFinding:
    reference: str
    status: str
    ledger_amount_minor: int | None
    processor_amount_minor: int | None
    currency: str | None


@dataclass(frozen=True)
class ReconciliationReport:
    findings: tuple[ReconciliationFinding, ...]
    matched: int
    exceptions: int
    schema: str = "pulpo.payment-reconciliation.v0"

    @property
    def report_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


def reconcile_payments(
    ledger: Iterable[PaymentRecord],
    processor: Iterable[PaymentRecord],
) -> ReconciliationReport:
    """Deterministically compare supplied records without moving money.

    Matching is exact by unique reference. Ambiguity, amount drift, currency
    drift, and missing records are surfaced rather than guessed or auto-fixed.
    """

    ledger_rows = tuple(ledger)
    processor_rows = tuple(processor)
    ledger_by_ref: dict[str, list[PaymentRecord]] = {}
    processor_by_ref: dict[str, list[PaymentRecord]] = {}
    for row in ledger_rows:
        ledger_by_ref.setdefault(row.reference, []).append(row)
    for row in processor_rows:
        processor_by_ref.setdefault(row.reference, []).append(row)

    findings: list[ReconciliationFinding] = []
    for reference in sorted(set(ledger_by_ref) | set(processor_by_ref)):
        left = ledger_by_ref.get(reference, [])
        right = processor_by_ref.get(reference, [])
        if len(left) > 1 or len(right) > 1:
            findings.append(
                ReconciliationFinding(reference, "duplicate_reference", None, None, None)
            )
            continue
        if not left:
            row = right[0]
            findings.append(
                ReconciliationFinding(reference, "missing_in_ledger", None, row.amount_minor, row.currency)
            )
            continue
        if not right:
            row = left[0]
            findings.append(
                ReconciliationFinding(reference, "missing_in_processor", row.amount_minor, None, row.currency)
            )
            continue
        lrow, rrow = left[0], right[0]
        if lrow.currency != rrow.currency:
            findings.append(
                ReconciliationFinding(reference, "currency_mismatch", lrow.amount_minor, rrow.amount_minor, None)
            )
        elif lrow.amount_minor != rrow.amount_minor:
            findings.append(
                ReconciliationFinding(reference, "amount_mismatch", lrow.amount_minor, rrow.amount_minor, lrow.currency)
            )
        else:
            findings.append(
                ReconciliationFinding(reference, "matched", lrow.amount_minor, rrow.amount_minor, lrow.currency)
            )

    matched = sum(item.status == "matched" for item in findings)
    return ReconciliationReport(tuple(findings), matched, len(findings) - matched)


@dataclass(frozen=True)
class OpsProposal:
    kind: str
    principal: str
    action: str
    resource: str
    session_id: str
    payload: dict[str, Any]
    cost: int = 0
    authority_effect: str = "none"
    execution_effect: str = "none"
    schema: str = "pulpo.ops-proposal.v0"

    def __post_init__(self) -> None:
        if self.kind not in {"schedule", "lead_procurement"}:
            raise ValueError("unsupported proposal kind")
        _require_text(self.principal, "principal", max_len=256)
        _require_text(self.action, "action", max_len=256)
        _require_text(self.resource, "resource", max_len=1024)
        _require_text(self.session_id, "session_id", max_len=256)
        if self.cost != 0:
            raise ValueError("proposal construction cannot reserve or spend budget")
        if self.authority_effect != "none" or self.execution_effect != "none":
            raise ValueError("ops proposals must be capability-free")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be an object")

    @property
    def proposal_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()

    def intent_fields(self) -> dict[str, Any]:
        """Return exact fields a governed service may later bind into an Intent."""
        return {
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "cost": self.cost,
            "session_id": self.session_id,
        }


def schedule_proposal(
    *,
    principal: str,
    session_id: str,
    starts_at: str,
    duration_minutes: int,
    title: str,
    attendees: Iterable[str] = (),
) -> OpsProposal:
    principal = _require_text(principal, "principal", max_len=256)
    session_id = _require_text(session_id, "session_id", max_len=256)
    starts_at = _require_text(starts_at, "starts_at", max_len=128)
    try:
        parsed_start = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("starts_at must be ISO 8601") from exc
    if parsed_start.tzinfo is None or parsed_start.utcoffset() is None:
        raise ValueError("starts_at must include a timezone offset")
    title = _require_text(title, "title", max_len=200)
    if isinstance(duration_minutes, bool) or not isinstance(duration_minutes, int) or not 5 <= duration_minutes <= 480:
        raise ValueError("duration_minutes must be between 5 and 480")
    clean_attendees = tuple(sorted({_require_text(item, "attendee", max_len=320).lower() for item in attendees if item.strip()}))
    payload = {
        "starts_at": starts_at,
        "duration_minutes": duration_minutes,
        "title": title,
        "attendees": clean_attendees,
        "mode": "proposal_only",
    }
    object_hash = sha256(_canonical(payload)).hexdigest()
    return OpsProposal(
        kind="schedule",
        principal=principal,
        action="calendar.schedule",
        resource=f"calendar:event-proposal:{object_hash}",
        session_id=session_id,
        payload=payload,
    )


def lead_procurement_proposal(
    *,
    principal: str,
    session_id: str,
    company_profile: str,
    buyer_role: str,
    geography: str,
    limit: int,
) -> OpsProposal:
    principal = _require_text(principal, "principal", max_len=256)
    session_id = _require_text(session_id, "session_id", max_len=256)
    company_profile = _require_text(company_profile, "company_profile", max_len=1000)
    buyer_role = _require_text(buyer_role, "buyer_role", max_len=256)
    geography = _require_text(geography, "geography", max_len=256)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    payload = {
        "company_profile": company_profile,
        "buyer_role": buyer_role,
        "geography": geography,
        "limit": limit,
        "mode": "research_only",
        "outreach": "prohibited",
        "purchase": "prohibited",
    }
    object_hash = sha256(_canonical(payload)).hexdigest()
    return OpsProposal(
        kind="lead_procurement",
        principal=principal,
        action="leads.procure_candidates",
        resource=f"leads:candidate-query:{object_hash}",
        session_id=session_id,
        payload=payload,
    )


@dataclass(frozen=True)
class BotReply:
    text: str
    proposal: OpsProposal | None = None
    reconciliation: ReconciliationReport | None = None


class OpsBot:
    """Thin message interpreter. It owns no authority and performs no side effect."""

    def __init__(self, *, principal: str = "agent:pulpo-ops-bot") -> None:
        self.principal = _require_text(principal, "principal", max_len=256)

    def handle_message(self, text: str, *, session_id: str) -> BotReply:
        text = _require_text(text, "message", max_len=12000)
        session_id = _require_text(session_id, "session_id", max_len=256)
        if text == "/help" or text == "/start":
            return BotReply(
                "Commands:\n"
                "/reconcile <JSON with ledger and processor arrays>\n"
                "/schedule <ISO start>|<minutes>|<title>|<comma-separated attendees>\n"
                "/leads <company profile>|<buyer role>|<geography>|<limit>\n"
                "Scheduling and lead commands create proposals only; they do not execute."
            )
        if text.startswith("/reconcile "):
            raw = text[len("/reconcile ") :].strip()
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("reconcile payload must be valid JSON") from exc
            if not isinstance(value, dict):
                raise ValueError("reconcile payload must be an object")
            ledger = tuple(PaymentRecord.from_mapping(item) for item in value.get("ledger", []))
            processor = tuple(PaymentRecord.from_mapping(item) for item in value.get("processor", []))
            report = reconcile_payments(ledger, processor)
            lines = [f"reconciliation {report.report_hash[:12]}: {report.matched} matched, {report.exceptions} exceptions"]
            lines.extend(f"- {item.reference}: {item.status}" for item in report.findings)
            return BotReply("\n".join(lines), reconciliation=report)
        if text.startswith("/schedule "):
            parts = [item.strip() for item in text[len("/schedule ") :].split("|")]
            if len(parts) != 4:
                raise ValueError("schedule format requires start|minutes|title|attendees")
            attendees = [item.strip() for item in parts[3].split(",") if item.strip()]
            proposal = schedule_proposal(
                principal=self.principal,
                session_id=session_id,
                starts_at=parts[0],
                duration_minutes=int(parts[1]),
                title=parts[2],
                attendees=attendees,
            )
            return BotReply(
                f"schedule proposal {proposal.proposal_hash[:12]} created; no calendar event was written",
                proposal=proposal,
            )
        if text.startswith("/leads "):
            parts = [item.strip() for item in text[len("/leads ") :].split("|")]
            if len(parts) != 4:
                raise ValueError("leads format requires company profile|buyer role|geography|limit")
            proposal = lead_procurement_proposal(
                principal=self.principal,
                session_id=session_id,
                company_profile=parts[0],
                buyer_role=parts[1],
                geography=parts[2],
                limit=int(parts[3]),
            )
            return BotReply(
                f"lead procurement proposal {proposal.proposal_hash[:12]} created; no purchase or outreach occurred",
                proposal=proposal,
            )
        raise ValueError("unsupported command")

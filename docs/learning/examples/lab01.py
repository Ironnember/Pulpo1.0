"""Offline financial record validation lesson (no payment/authority capability)."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping


EXPECTED_FIELDS = frozenset({"recipient", "amount_usd", "purpose"})
MONEY = re.compile(r"(?:0|[1-9][0-9]*)\.[0-9]{2}\Z")


@dataclass(frozen=True)
class Proposal:
    recipient: str
    purpose: str
    amount_cents: int
    source_hash: str
    within_example_limit: bool
    authority: str = "NOT_GRANTED"
    execution: str = "NOT_ATTEMPTED"
    consequence: str = "UNKNOWN"


def normalize_proposal(record: Mapping[str, object], *, limit_cents: int = 3000) -> Proposal:
    """Pure normalization only: no approval, storage, network or transaction."""
    if not isinstance(record, dict) or set(record) != EXPECTED_FIELDS:
        raise ValueError("exact synthetic record fields required")
    if type(limit_cents) is not int or limit_cents < 0:
        raise ValueError("invalid synthetic policy ceiling")
    recipient, purpose, amount = (record["recipient"], record["purpose"], record["amount_usd"])
    if type(recipient) is not str or not recipient or recipient != recipient.strip():
        raise ValueError("invalid recipient")
    if type(purpose) is not str or not purpose or purpose != purpose.strip():
        raise ValueError("invalid purpose")
    if type(amount) is not str or MONEY.fullmatch(amount) is None:
        raise ValueError("amount requires a non-negative exact two-decimal USD string")
    dollars, cents = amount.split(".")
    amount_cents = int(dollars) * 100 + int(cents)
    normalized = {"recipient": recipient, "purpose": purpose, "amount_cents": amount_cents, "currency": "USD"}
    source_hash = sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return Proposal(recipient, purpose, amount_cents, source_hash, amount_cents <= limit_cents)


if __name__ == "__main__":
    proposal = normalize_proposal({"recipient": "sandbox-supplier", "amount_usd": "29.90", "purpose": "synthetic procurement lesson"})
    print(json.dumps(proposal.__dict__, sort_keys=True, indent=2))

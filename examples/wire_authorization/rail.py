"""MOCK payment rail — no real funds, no bank, no network. Ever.

This module is the external-effect stand-in for the wire-authorization
reference deployment. It simulates the one thing a real payment rail
would do from the governance kernel's point of view: once authorized, a
transfer either happened (and is recorded) or it did not.

``MockPaymentRail.transfer`` does exactly one thing: it appends one JSON
line, indelibly marked as a mock, to a local JSON-lines file. It holds no
money, opens no account, contacts no institution, and cannot move real
funds in any configuration. Do not mistake it for a payment integration,
and do not adapt it into one: a real rail is a separate, consequential
integration that does not belong in this example.

The rail deliberately knows nothing about the governance kernel: no
imports from ``pulpo``, no intents, no permits, no approvals. That
ignorance is the point of the example's shape — authorization lives
entirely in the service layer's governed path, and the rail is a dumb
effect recorder whose output the evidence checker later reconciles
against the kernel's canonical audit trail. The kernel audit remains the
evidence truth; this file is the mock *external* record of effects, not a
second governance ledger.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class MockPaymentRail:
    """Append-only MOCK ledger simulating a payment rail's effect record.

    MOCK — NO REAL FUNDS. Constructing this class creates no account and
    no capability to pay anyone. ``transfer`` only writes a marked JSON
    line to the configured local file; the file's growth is the entire
    observable "consequence" the reference deployment studies.

    The ledger file is append-only by construction of this class: there
    is no update, delete, or rewrite operation. A writer with direct
    filesystem access can of course edit the file — that direct-writer
    class is outside this example's governance claim, and it is exactly
    what the evidence checker exists to catch when it reconciles this
    file against the kernel audit trail.
    """

    RAIL_MARKER = "MOCK-NO-REAL-FUNDS"

    def __init__(self, ledger_path: str | os.PathLike[str]) -> None:
        self._path = Path(ledger_path)

    @property
    def ledger_path(self) -> Path:
        """Path of the JSON-lines mock ledger (read-only location info)."""
        return self._path

    def transfer(self, *, payee: str, amount_cents: int, transfer_id: str) -> dict:
        """Record one MOCK transfer and return the record written.

        This method performs no authorization. Callers must reach it only
        through a governed path (see ``WireAuthorizationService``); within
        this example's public API the service is that path.
        """
        if not isinstance(payee, str) or not payee:
            raise ValueError("payee must be a non-empty string")
        if isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or amount_cents <= 0:
            raise ValueError("amount_cents must be a positive integer")
        if not isinstance(transfer_id, str) or not transfer_id:
            raise ValueError("transfer_id must be a non-empty string")
        record = {
            "transfer_id": transfer_id,
            "payee": payee,
            "amount_cents": amount_cents,
            "rail": self.RAIL_MARKER,
            "mock": True,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return dict(record)

    def records(self) -> list[dict]:
        """Return all mock transfer records, in append order."""
        if not self._path.exists():
            return []
        result: list[dict] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                result.append(json.loads(line))
        return result

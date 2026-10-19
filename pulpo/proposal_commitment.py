"""Trusted proposal provenance for Hostile Worker Consequence Proof V0.

A hostile worker may choose a normalized domain name, but it may not originate
or reconstruct the consequential order that enters Pulpo authority evaluation.
This store persists the exact order produced by the trusted provider-observation
path and exposes only an opaque commitment reference to the worker.

The table is custody operational state, not an authority source or evidence
ledger. Membership in this protected store proves V0 proposal provenance; the
canonical kernel still decides authority and the custody transition protocol
still controls execution rights.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from typing import Any

from .commerce import DomainPurchaseOrder


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _require_hash(value: str, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProposalCommitmentViolation(f"{field}_invalid")


class ProposalCommitmentViolation(RuntimeError):
    """A proposal reference failed the trusted-origin contract."""


@dataclass(frozen=True)
class ProposalCommitment:
    commitment_id: str
    commitment_hash: str
    order_hash: str
    availability_hash: str
    created_at_ns: int
    expires_at_ns: int
    state: str
    schema: str = "pulpo.proposal-commitment.v0"


class SQLiteProposalCommitments:
    """Immutable custody-side proposal objects with fail-closed one-shot claims."""

    READY = "ready"
    CLAIMED = "claimed"

    def __init__(self, path: str | Path) -> None:
        if not str(path) or str(path) == ":memory:":
            raise ProposalCommitmentViolation("proposal_store_requires_filesystem_path")
        self.path = Path(path)
        if not self.path.parent.is_dir():
            raise ProposalCommitmentViolation("proposal_store_parent_missing")
        if self.path.exists() and not self.path.is_file():
            raise ProposalCommitmentViolation("proposal_store_not_regular_file")
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proposal_commitments (
                        commitment_id TEXT PRIMARY KEY,
                        commitment_hash TEXT NOT NULL UNIQUE,
                        order_hash TEXT NOT NULL UNIQUE,
                        availability_hash TEXT NOT NULL,
                        order_json TEXT NOT NULL,
                        created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0),
                        expires_at_ns INTEGER NOT NULL CHECK (expires_at_ns > created_at_ns),
                        state TEXT NOT NULL CHECK (state IN ('ready', 'claimed'))
                    )
                    """
                )
        except (OSError, sqlite3.Error) as exc:
            raise ProposalCommitmentViolation("proposal_store_unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _material(
        *,
        order_hash: str,
        availability_hash: str,
        created_at_ns: int,
        expires_at_ns: int,
    ) -> dict[str, object]:
        return {
            "schema": "pulpo.proposal-commitment.v0",
            "order_hash": order_hash,
            "availability_hash": availability_hash,
            "created_at_ns": created_at_ns,
            "expires_at_ns": expires_at_ns,
        }

    @staticmethod
    def _decode_order(encoded: str) -> DomainPurchaseOrder:
        try:
            value = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise ProposalCommitmentViolation("proposal_order_corrupt") from exc
        if not isinstance(value, dict):
            raise ProposalCommitmentViolation("proposal_order_corrupt")
        prohibited = value.get("prohibited_upsells")
        if isinstance(prohibited, list):
            value["prohibited_upsells"] = tuple(prohibited)
        try:
            return DomainPurchaseOrder(**value)
        except (TypeError, ValueError) as exc:
            raise ProposalCommitmentViolation("proposal_order_corrupt") from exc

    @classmethod
    def _from_row(cls, row: tuple[object, ...]) -> tuple[ProposalCommitment, DomainPurchaseOrder]:
        commitment = ProposalCommitment(
            commitment_id=str(row[0]),
            commitment_hash=str(row[1]),
            order_hash=str(row[2]),
            availability_hash=str(row[3]),
            created_at_ns=int(row[5]),
            expires_at_ns=int(row[6]),
            state=str(row[7]),
        )
        _require_hash(commitment.commitment_hash, "proposal_commitment_hash")
        _require_hash(commitment.order_hash, "proposal_order_hash")
        _require_hash(commitment.availability_hash, "proposal_availability_hash")
        order = cls._decode_order(str(row[4]))
        if order.order_hash != commitment.order_hash:
            raise ProposalCommitmentViolation("proposal_order_hash_mismatch")
        expected = _hash(
            cls._material(
                order_hash=commitment.order_hash,
                availability_hash=commitment.availability_hash,
                created_at_ns=commitment.created_at_ns,
                expires_at_ns=commitment.expires_at_ns,
            )
        )
        if expected != commitment.commitment_hash:
            raise ProposalCommitmentViolation("proposal_commitment_hash_mismatch")
        if commitment.commitment_id != f"proposal:{commitment.commitment_hash}":
            raise ProposalCommitmentViolation("proposal_commitment_id_mismatch")
        return commitment, order

    def create(
        self,
        order: DomainPurchaseOrder,
        *,
        availability_hash: str,
        created_at_ns: int,
        expires_at_ns: int,
    ) -> ProposalCommitment:
        _require_hash(availability_hash, "proposal_availability_hash")
        if isinstance(created_at_ns, bool) or not isinstance(created_at_ns, int) or created_at_ns <= 0:
            raise ProposalCommitmentViolation("proposal_created_at_invalid")
        if (
            isinstance(expires_at_ns, bool)
            or not isinstance(expires_at_ns, int)
            or expires_at_ns <= created_at_ns
            or expires_at_ns != order.expires_at_ns
        ):
            raise ProposalCommitmentViolation("proposal_expiry_invalid")
        material = self._material(
            order_hash=order.order_hash,
            availability_hash=availability_hash,
            created_at_ns=created_at_ns,
            expires_at_ns=expires_at_ns,
        )
        commitment_hash = _hash(material)
        commitment_id = f"proposal:{commitment_hash}"
        encoded_order = _canonical(asdict(order)).decode()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT commitment_id, commitment_hash, order_hash, availability_hash,
                           order_json, created_at_ns, expires_at_ns, state
                    FROM proposal_commitments WHERE commitment_id = ?
                    """,
                    (commitment_id,),
                ).fetchone()
                if existing is not None:
                    commitment, existing_order = self._from_row(existing)
                    if existing_order != order:
                        raise ProposalCommitmentViolation("proposal_commitment_collision")
                    return commitment
                connection.execute(
                    """
                    INSERT INTO proposal_commitments
                        (commitment_id, commitment_hash, order_hash, availability_hash,
                         order_json, created_at_ns, expires_at_ns, state)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        commitment_id,
                        commitment_hash,
                        order.order_hash,
                        availability_hash,
                        encoded_order,
                        created_at_ns,
                        expires_at_ns,
                        self.READY,
                    ),
                )
            return ProposalCommitment(
                commitment_id=commitment_id,
                commitment_hash=commitment_hash,
                order_hash=order.order_hash,
                availability_hash=availability_hash,
                created_at_ns=created_at_ns,
                expires_at_ns=expires_at_ns,
                state=self.READY,
            )
        except ProposalCommitmentViolation:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ProposalCommitmentViolation("proposal_store_unavailable") from exc

    def claim(
        self,
        commitment_id: str,
        *,
        now_ns: int,
    ) -> tuple[ProposalCommitment, DomainPurchaseOrder]:
        """Irreversibly claim one valid commitment before authority evaluation.

        A failed or crashed ceremony may sacrifice this proposal's availability,
        but it cannot reopen provenance or create another execution right. The
        operator may create a fresh proposal from a new trusted provider read.
        """

        if not commitment_id:
            raise ProposalCommitmentViolation("proposal_commitment_required")
        if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns <= 0:
            raise ProposalCommitmentViolation("proposal_custody_time_invalid")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT commitment_id, commitment_hash, order_hash, availability_hash,
                           order_json, created_at_ns, expires_at_ns, state
                    FROM proposal_commitments WHERE commitment_id = ?
                    """,
                    (commitment_id,),
                ).fetchone()
                if row is None:
                    raise ProposalCommitmentViolation("proposal_commitment_unknown")
                commitment, order = self._from_row(row)
                if commitment.state != self.READY:
                    raise ProposalCommitmentViolation("proposal_commitment_already_claimed")
                if now_ns >= commitment.expires_at_ns:
                    raise ProposalCommitmentViolation("proposal_commitment_expired")
                cursor = connection.execute(
                    """
                    UPDATE proposal_commitments SET state = 'claimed'
                    WHERE commitment_id = ? AND state = 'ready'
                    """,
                    (commitment_id,),
                )
                if cursor.rowcount != 1:
                    raise ProposalCommitmentViolation("proposal_commitment_already_claimed")
                return (
                    ProposalCommitment(**{**asdict(commitment), "state": self.CLAIMED}),
                    order,
                )
        except ProposalCommitmentViolation:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ProposalCommitmentViolation("proposal_store_unavailable") from exc

    def order_for_hash(self, order_hash: str) -> DomainPurchaseOrder:
        _require_hash(order_hash, "proposal_order_hash")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT commitment_id, commitment_hash, order_hash, availability_hash,
                           order_json, created_at_ns, expires_at_ns, state
                    FROM proposal_commitments WHERE order_hash = ?
                    """,
                    (order_hash,),
                ).fetchone()
            if row is None:
                raise ProposalCommitmentViolation("proposal_commitment_unknown")
            commitment, order = self._from_row(row)
            if commitment.state != self.CLAIMED:
                raise ProposalCommitmentViolation("proposal_commitment_not_claimed")
            return order
        except ProposalCommitmentViolation:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ProposalCommitmentViolation("proposal_store_unavailable") from exc

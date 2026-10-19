"""Crash-safe convergence from custody transitions into canonical Pulpo evidence.

The outbox is deliberately not a second evidence ledger. Each row is a durable
obligation saying that one already-committed custody transition has not yet been
projected into the existing canonical kernel audit. A SQLite trigger creates the
obligation atomically with the custody-head advance and blocks the next custody
advance until projection succeeds.

Projection appends exactly one ``custody_transition`` event to the existing
``audit`` table and marks the obligation projected in the same SQLite
transaction. Restart therefore retries safely and duplicate projection is
idempotent by custody transition hash.
"""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import hmac
import json
from pathlib import Path
import sqlite3
from typing import Callable

from .custody import CustodyViolation, SQLiteGovernanceCustody, TransitionReceipt
from .state import _audit_record, _canonical


class CustodyEvidenceViolation(RuntimeError):
    """Custody cannot advance because canonical evidence has not converged."""


FaultHook = Callable[[str], None]


class SQLiteCustodyEvidenceConvergence:
    """One durable obligation queue targeting the existing canonical audit."""

    EVENT = "custody_transition"

    def __init__(
        self,
        custody: SQLiteGovernanceCustody,
        *,
        fault_hook: FaultHook | None = None,
    ) -> None:
        self.custody = custody
        self.path = Path(custody.path)
        self._fault_hook = fault_hook
        secret = getattr(custody, "_signing_secret", None)
        if not isinstance(secret, bytes) or not secret:
            raise CustodyEvidenceViolation("custody_signing_material_unavailable")
        self._signing_secret = secret
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                # The canonical kernel state must already own this audit table.
                audit = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'"
                ).fetchone()
                if audit is None:
                    raise CustodyEvidenceViolation("canonical_audit_missing")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS custody_evidence_outbox (
                        transition_hash TEXT PRIMARY KEY,
                        epoch INTEGER NOT NULL UNIQUE CHECK (epoch > 0),
                        state_root TEXT NOT NULL,
                        previous_root TEXT NOT NULL,
                        custody_time_ns INTEGER NOT NULL CHECK (custody_time_ns > 0),
                        transition_type TEXT NOT NULL,
                        object_hash TEXT NOT NULL,
                        projected INTEGER NOT NULL DEFAULT 0 CHECK (projected IN (0, 1)),
                        canonical_audit_hash TEXT,
                        CHECK (
                            (projected = 0 AND canonical_audit_hash IS NULL)
                            OR
                            (projected = 1 AND canonical_audit_hash IS NOT NULL)
                        )
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS custody_block_unprojected_evidence
                    BEFORE UPDATE OF epoch ON custody_head
                    WHEN EXISTS (
                        SELECT 1 FROM custody_evidence_outbox WHERE projected = 0
                    )
                    BEGIN
                        SELECT RAISE(ABORT, 'canonical_evidence_projection_required');
                    END
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS custody_create_evidence_obligation
                    AFTER UPDATE OF epoch ON custody_head
                    WHEN NEW.epoch = OLD.epoch + 1
                    BEGIN
                        INSERT INTO custody_evidence_outbox (
                            transition_hash,
                            epoch,
                            state_root,
                            previous_root,
                            custody_time_ns,
                            transition_type,
                            object_hash,
                            projected,
                            canonical_audit_hash
                        ) VALUES (
                            NEW.transition_hash,
                            NEW.epoch,
                            NEW.state_root,
                            NEW.previous_root,
                            NEW.custody_time_ns,
                            (
                                SELECT state FROM custody_attempts
                                WHERE updated_epoch = NEW.epoch
                                LIMIT 1
                            ),
                            (
                                SELECT object_hash FROM custody_attempts
                                WHERE updated_epoch = NEW.epoch
                                LIMIT 1
                            ),
                            0,
                            NULL
                        );
                    END
                    """
                )
        except CustodyEvidenceViolation:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise CustodyEvidenceViolation("custody_evidence_initialize_failed") from exc

    def pending_count(self) -> int:
        try:
            with self._connect() as connection:
                return int(
                    connection.execute(
                        "SELECT COUNT(*) FROM custody_evidence_outbox WHERE projected = 0"
                    ).fetchone()[0]
                )
        except (OSError, sqlite3.Error, TypeError) as exc:
            raise CustodyEvidenceViolation("custody_evidence_read_failed") from exc

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def _receipt_from_row(self, row: tuple[object, ...]) -> TransitionReceipt:
        transition_hash = str(row[0])
        epoch = int(row[1])
        state_root = str(row[2])
        previous_root = str(row[3])
        custody_time_ns = int(row[4])
        transition_type = str(row[5])
        object_hash = str(row[6])
        unsigned = TransitionReceipt(
            epoch=epoch,
            previous_root=previous_root,
            state_root=state_root,
            custody_time_ns=custody_time_ns,
            transition_type=transition_type,
            transition_hash=transition_hash,
            object_hash=object_hash,
            signature="",
        )
        signature = hmac.new(
            self._signing_secret,
            unsigned.signing_material,
            sha256,
        ).hexdigest()
        receipt = TransitionReceipt(**{**asdict(unsigned), "signature": signature})
        if not self.custody.verify_receipt(receipt):
            raise CustodyEvidenceViolation("custody_receipt_signature_invalid")
        return receipt

    @staticmethod
    def _validate_against_custody(
        connection: sqlite3.Connection,
        receipt: TransitionReceipt,
    ) -> None:
        head = connection.execute(
            """
            SELECT epoch, state_root, previous_root, custody_time_ns, transition_hash
            FROM custody_head WHERE singleton = 1
            """
        ).fetchone()
        if head is None:
            raise CustodyEvidenceViolation("custody_head_missing")
        expected_head = (
            receipt.epoch,
            receipt.state_root,
            receipt.previous_root,
            receipt.custody_time_ns,
            receipt.transition_hash,
        )
        if tuple(head) != expected_head:
            raise CustodyEvidenceViolation("custody_evidence_head_mismatch")
        attempt = connection.execute(
            """
            SELECT state, object_hash FROM custody_attempts
            WHERE updated_epoch = ?
            """,
            (receipt.epoch,),
        ).fetchall()
        if len(attempt) != 1:
            raise CustodyEvidenceViolation("custody_evidence_attempt_ambiguous")
        if tuple(attempt[0]) != (receipt.transition_type, receipt.object_hash):
            raise CustodyEvidenceViolation("custody_evidence_receipt_mismatch")

    def project_one(self) -> str | None:
        """Project one pending transition atomically into canonical audit evidence."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT transition_hash, epoch, state_root, previous_root,
                       custody_time_ns, transition_type, object_hash,
                       projected, canonical_audit_hash
                FROM custody_evidence_outbox
                WHERE projected = 0
                ORDER BY epoch
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            receipt = self._receipt_from_row(row)
            self._validate_against_custody(connection, receipt)
            payload = {
                "schema": "pulpo.custody-evidence-projection.v0",
                "transition_hash": receipt.transition_hash,
                "receipt": asdict(receipt),
            }
            previous = connection.execute(
                "SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = str(previous[0]) if previous is not None else "0" * 64
            record = _audit_record(
                previous_hash,
                self.EVENT,
                payload,
                receipt.custody_time_ns,
            )
            connection.execute(
                """
                INSERT INTO audit
                    (event, payload_json, previous_hash, timestamp_ns, hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record["event"],
                    _canonical(record["payload"]).decode(),
                    record["previous_hash"],
                    record["timestamp_ns"],
                    record["hash"],
                ),
            )
            self._fault("after_audit_insert")
            cursor = connection.execute(
                """
                UPDATE custody_evidence_outbox
                SET projected = 1, canonical_audit_hash = ?
                WHERE transition_hash = ? AND projected = 0
                """,
                (record["hash"], receipt.transition_hash),
            )
            if cursor.rowcount != 1:
                raise CustodyEvidenceViolation("custody_evidence_projection_race")
            self._fault("before_projection_commit")
            connection.commit()
            return str(record["hash"])
        except CustodyEvidenceViolation:
            connection.rollback()
            raise
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise CustodyEvidenceViolation("custody_evidence_projection_failed") from exc
        finally:
            connection.close()

    def project_all(self) -> tuple[str, ...]:
        projected: list[str] = []
        while True:
            value = self.project_one()
            if value is None:
                return tuple(projected)
            projected.append(value)

    def canonical_event_count(self, transition_hash: str) -> int:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT payload_json FROM audit WHERE event = ?",
                    (self.EVENT,),
                ).fetchall()
            count = 0
            for (encoded,) in rows:
                try:
                    payload = json.loads(str(encoded))
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and payload.get("transition_hash") == transition_hash:
                    count += 1
            return count
        except (OSError, sqlite3.Error) as exc:
            raise CustodyEvidenceViolation("canonical_evidence_read_failed") from exc

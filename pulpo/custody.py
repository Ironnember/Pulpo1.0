"""Monotonic governance-custody substrate for Hostile Worker Proof V0.

This module is deliberately narrower than a policy engine or evidence ledger.
It does not decide whether an action is allowed, authenticate an approver, or
execute an external effect.  It serializes already-authorized consequential
state transitions inside a custody boundary that the V0 hostile worker is not
allowed to mutate or roll back.

V0 trust assumption: the custody process, its persistent store, and its signing
secret remain trustworthy.  Hostile-custodian rollback/equivocation is a later
proof and is explicitly not solved here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable


GENESIS_PREVIOUS_ROOT = "0" * 64
GENESIS_TRANSITION_HASH = sha256(b"pulpo.custody.genesis.v0").hexdigest()


class CustodyViolation(RuntimeError):
    """Raised when a custody transition would violate the frozen V0 contract."""


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
        raise CustodyViolation(f"{field}_invalid")


@dataclass(frozen=True)
class GovernanceHead:
    epoch: int
    state_root: str
    previous_root: str
    custody_time_ns: int
    transition_hash: str
    schema: str = "pulpo.governance-head.v0"


@dataclass(frozen=True)
class TransitionReceipt:
    epoch: int
    previous_root: str
    state_root: str
    custody_time_ns: int
    transition_type: str
    transition_hash: str
    object_hash: str
    signature: str
    schema: str = "pulpo.custody-transition.v0"

    @property
    def signing_material(self) -> bytes:
        payload = asdict(self)
        payload.pop("signature")
        return _canonical(payload)


@dataclass(frozen=True)
class AttemptAuthorization:
    attempt_id: str
    receipt: TransitionReceipt


@dataclass(frozen=True)
class TransmissionAuthorization:
    attempt_id: str
    idempotency_key: str
    receipt: TransitionReceipt


@dataclass(frozen=True)
class AttemptSnapshot:
    attempt_id: str
    object_hash: str
    target_hash: str
    permit_hash: str
    authorization_hash: str
    state: str
    executor_id: str | None
    provider_request_id: str | None
    observation_hash: str | None
    reconciliation_outcome: str | None
    created_epoch: int
    updated_epoch: int


class SQLiteGovernanceCustody:
    """Transactional monotonic anchor outside the V0 hostile-worker boundary.

    The database stores current operational custody state, not a second evidence
    ledger.  The canonical Pulpo evidence chain remains the evidence authority;
    returned signed transition receipts are intended to be projected into that
    chain by the trusted governance path.

    `clock` is custody configuration, not a worker-supplied request field.  V0
    assumes the custody runtime is trustworthy.  A clock rollback inside this
    trusted boundary fails closed rather than silently extending authority.
    """

    ATTEMPT_AUTHORIZED = "attempt_authorized"
    ATTEMPT_CLAIMED = "attempt_claimed"
    REQUEST_TRANSMITTED = "request_transmitted"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    RECONCILED_SUCCESS = "reconciled_success"
    RECONCILED_FAILURE = "reconciled_failure"
    UNRESOLVED = "unresolved"

    def __init__(
        self,
        path: str | Path,
        *,
        signing_secret: bytes,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not signing_secret:
            raise CustodyViolation("custody_signing_secret_required")
        if not str(path) or str(path) == ":memory:":
            raise CustodyViolation("custody_store_requires_filesystem_path")
        self.path = Path(path)
        if not self.path.parent.is_dir():
            raise CustodyViolation("custody_store_parent_missing")
        if self.path.exists() and not self.path.is_file():
            raise CustodyViolation("custody_store_not_regular_file")
        self._signing_secret = signing_secret
        self._clock = clock or time.time_ns
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS custody_head (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    epoch INTEGER NOT NULL CHECK (epoch >= 0),
                    state_root TEXT NOT NULL,
                    previous_root TEXT NOT NULL,
                    custody_time_ns INTEGER NOT NULL CHECK (custody_time_ns >= 0),
                    transition_hash TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS custody_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    object_hash TEXT NOT NULL UNIQUE,
                    target_hash TEXT NOT NULL,
                    permit_hash TEXT NOT NULL,
                    authorization_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    executor_id TEXT,
                    provider_request_id TEXT,
                    observation_hash TEXT,
                    reconciliation_outcome TEXT,
                    created_epoch INTEGER NOT NULL CHECK (created_epoch > 0),
                    updated_epoch INTEGER NOT NULL CHECK (updated_epoch >= created_epoch)
                )
                """
            )
            row = connection.execute(
                "SELECT 1 FROM custody_head WHERE singleton = 1"
            ).fetchone()
            if row is None:
                genesis_root = _hash(
                    {
                        "schema": "pulpo.governance-head.v0",
                        "epoch": 0,
                        "previous_root": GENESIS_PREVIOUS_ROOT,
                        "transition_hash": GENESIS_TRANSITION_HASH,
                    }
                )
                connection.execute(
                    """
                    INSERT INTO custody_head
                        (singleton, epoch, state_root, previous_root, custody_time_ns, transition_hash)
                    VALUES (1, 0, ?, ?, 0, ?)
                    """,
                    (genesis_root, GENESIS_PREVIOUS_ROOT, GENESIS_TRANSITION_HASH),
                )
            connection.commit()
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise CustodyViolation("custody_store_unavailable") from exc
        finally:
            connection.close()

    @staticmethod
    def _row_to_head(row: tuple[Any, ...]) -> GovernanceHead:
        return GovernanceHead(
            epoch=int(row[0]),
            state_root=str(row[1]),
            previous_root=str(row[2]),
            custody_time_ns=int(row[3]),
            transition_hash=str(row[4]),
        )

    def _load_head(self, connection: sqlite3.Connection) -> GovernanceHead:
        row = connection.execute(
            """
            SELECT epoch, state_root, previous_root, custody_time_ns, transition_hash
            FROM custody_head WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise CustodyViolation("custody_head_missing")
        head = self._row_to_head(row)
        _require_hash(head.state_root, "state_root")
        _require_hash(head.previous_root, "previous_root")
        _require_hash(head.transition_hash, "transition_hash")
        return head

    def snapshot(self) -> GovernanceHead:
        connection = self._connect()
        try:
            return self._load_head(connection)
        except (OSError, sqlite3.Error) as exc:
            raise CustodyViolation("custody_store_unavailable") from exc
        finally:
            connection.close()

    @staticmethod
    def _require_expected(
        current: GovernanceHead,
        expected_epoch: int,
        expected_state_root: str,
    ) -> None:
        _require_hash(expected_state_root, "expected_state_root")
        if current.epoch != expected_epoch or not hmac.compare_digest(
            current.state_root, expected_state_root
        ):
            raise CustodyViolation("stale_governance_head")

    def _custody_now(self, current: GovernanceHead) -> int:
        try:
            now_ns = self._clock()
        except Exception as exc:
            raise CustodyViolation("custody_clock_unavailable") from exc
        if not isinstance(now_ns, int) or now_ns <= 0:
            raise CustodyViolation("custody_clock_invalid")
        if now_ns < current.custody_time_ns:
            raise CustodyViolation("custody_clock_rollback")
        return now_ns

    def _make_receipt(
        self,
        current: GovernanceHead,
        *,
        transition_type: str,
        object_hash: str,
        payload: dict[str, Any],
    ) -> TransitionReceipt:
        if not transition_type:
            raise CustodyViolation("transition_type_required")
        _require_hash(object_hash, "object_hash")
        now_ns = self._custody_now(current)
        next_epoch = current.epoch + 1
        transition_hash = _hash(
            {
                "schema": "pulpo.custody-transition.v0",
                "previous_epoch": current.epoch,
                "previous_root": current.state_root,
                "custody_time_ns": now_ns,
                "transition_type": transition_type,
                "object_hash": object_hash,
                "payload": payload,
            }
        )
        state_root = _hash(
            {
                "schema": "pulpo.governance-head.v0",
                "epoch": next_epoch,
                "previous_root": current.state_root,
                "transition_hash": transition_hash,
            }
        )
        unsigned = TransitionReceipt(
            epoch=next_epoch,
            previous_root=current.state_root,
            state_root=state_root,
            custody_time_ns=now_ns,
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
        return TransitionReceipt(**{**asdict(unsigned), "signature": signature})

    @staticmethod
    def _store_head(connection: sqlite3.Connection, receipt: TransitionReceipt) -> None:
        connection.execute(
            """
            UPDATE custody_head
            SET epoch = ?, state_root = ?, previous_root = ?,
                custody_time_ns = ?, transition_hash = ?
            WHERE singleton = 1
            """,
            (
                receipt.epoch,
                receipt.state_root,
                receipt.previous_root,
                receipt.custody_time_ns,
                receipt.transition_hash,
            ),
        )

    def verify_receipt(self, receipt: TransitionReceipt) -> bool:
        expected = hmac.new(
            self._signing_secret,
            receipt.signing_material,
            sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, receipt.signature)

    @staticmethod
    def _attempt_id(
        object_hash: str,
        target_hash: str,
        permit_hash: str,
        authorization_hash: str,
    ) -> str:
        return _hash(
            {
                "schema": "pulpo.attempt.v0",
                "object_hash": object_hash,
                "target_hash": target_hash,
                "permit_hash": permit_hash,
                "authorization_hash": authorization_hash,
            }
        )

    def authorize_attempt(
        self,
        *,
        expected_epoch: int,
        expected_state_root: str,
        object_hash: str,
        target_hash: str,
        permit_hash: str,
        authorization_hash: str,
    ) -> AttemptAuthorization:
        """Atomically mint one custody attempt reference for an already-authorized object.

        This method does not verify policy or an approval by itself.  It must be
        invoked by the trusted governance path after canonical authorization.
        Its job is to make a copied worker capability insufficient for replay.
        """

        for value, field in (
            (object_hash, "object_hash"),
            (target_hash, "target_hash"),
            (permit_hash, "permit_hash"),
            (authorization_hash, "authorization_hash"),
        ):
            _require_hash(value, field)
        attempt_id = self._attempt_id(
            object_hash,
            target_hash,
            permit_hash,
            authorization_hash,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._load_head(connection)
            self._require_expected(current, expected_epoch, expected_state_root)
            if connection.execute(
                "SELECT 1 FROM custody_attempts WHERE object_hash = ? OR attempt_id = ?",
                (object_hash, attempt_id),
            ).fetchone():
                raise CustodyViolation("attempt_already_authorized")
            payload = {
                "attempt_id": attempt_id,
                "target_hash": target_hash,
                "permit_hash": permit_hash,
                "authorization_hash": authorization_hash,
                "state": self.ATTEMPT_AUTHORIZED,
            }
            receipt = self._make_receipt(
                current,
                transition_type=self.ATTEMPT_AUTHORIZED,
                object_hash=object_hash,
                payload=payload,
            )
            connection.execute(
                """
                INSERT INTO custody_attempts
                    (attempt_id, object_hash, target_hash, permit_hash, authorization_hash,
                     state, created_epoch, updated_epoch)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    object_hash,
                    target_hash,
                    permit_hash,
                    authorization_hash,
                    self.ATTEMPT_AUTHORIZED,
                    receipt.epoch,
                    receipt.epoch,
                ),
            )
            self._store_head(connection, receipt)
            connection.commit()
            return AttemptAuthorization(attempt_id, receipt)
        except CustodyViolation:
            connection.rollback()
            raise
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise CustodyViolation("custody_store_unavailable") from exc
        finally:
            connection.close()

    def _transition_attempt(
        self,
        *,
        expected_epoch: int,
        expected_state_root: str,
        attempt_id: str,
        required_states: frozenset[str],
        next_state: str,
        payload: dict[str, Any],
        updates: dict[str, str | None] | None = None,
    ) -> TransitionReceipt:
        if not attempt_id:
            raise CustodyViolation("attempt_id_required")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._load_head(connection)
            self._require_expected(current, expected_epoch, expected_state_root)
            row = connection.execute(
                "SELECT object_hash, state FROM custody_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise CustodyViolation("attempt_unknown")
            object_hash, state = str(row[0]), str(row[1])
            if state not in required_states:
                raise CustodyViolation("attempt_state_conflict")
            receipt = self._make_receipt(
                current,
                transition_type=next_state,
                object_hash=object_hash,
                payload={"attempt_id": attempt_id, "from_state": state, **payload},
            )
            assignments = ["state = ?", "updated_epoch = ?"]
            values: list[Any] = [next_state, receipt.epoch]
            for column, value in (updates or {}).items():
                if column not in {
                    "executor_id",
                    "provider_request_id",
                    "observation_hash",
                    "reconciliation_outcome",
                }:
                    raise CustodyViolation("attempt_update_field_invalid")
                assignments.append(f"{column} = ?")
                values.append(value)
            values.append(attempt_id)
            connection.execute(
                f"UPDATE custody_attempts SET {', '.join(assignments)} WHERE attempt_id = ?",
                tuple(values),
            )
            self._store_head(connection, receipt)
            connection.commit()
            return receipt
        except CustodyViolation:
            connection.rollback()
            raise
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise CustodyViolation("custody_store_unavailable") from exc
        finally:
            connection.close()

    def claim_attempt(
        self,
        *,
        expected_epoch: int,
        expected_state_root: str,
        attempt_id: str,
        executor_id: str,
    ) -> TransitionReceipt:
        if not executor_id:
            raise CustodyViolation("executor_id_required")
        return self._transition_attempt(
            expected_epoch=expected_epoch,
            expected_state_root=expected_state_root,
            attempt_id=attempt_id,
            required_states=frozenset({self.ATTEMPT_AUTHORIZED}),
            next_state=self.ATTEMPT_CLAIMED,
            payload={"executor_id": executor_id},
            updates={"executor_id": executor_id},
        )

    def authorize_transmission(
        self,
        *,
        expected_epoch: int,
        expected_state_root: str,
        attempt_id: str,
        provider_request_id: str | None = None,
    ) -> TransmissionAuthorization:
        """Release the one provider-transmission right before the network call.

        `REQUEST_TRANSMITTED` is intentionally conservative: after this receipt
        exists, the request may have reached the provider.  A crash immediately
        afterward therefore requires reconciliation instead of a blind retry.
        """

        if provider_request_id is not None and not provider_request_id:
            raise CustodyViolation("provider_request_id_invalid")
        idempotency_key = attempt_id
        receipt = self._transition_attempt(
            expected_epoch=expected_epoch,
            expected_state_root=expected_state_root,
            attempt_id=attempt_id,
            required_states=frozenset({self.ATTEMPT_CLAIMED}),
            next_state=self.REQUEST_TRANSMITTED,
            payload={
                "provider_request_id": provider_request_id,
                "idempotency_key": idempotency_key,
            },
            updates={"provider_request_id": provider_request_id},
        )
        return TransmissionAuthorization(attempt_id, idempotency_key, receipt)

    def require_reconciliation(
        self,
        *,
        expected_epoch: int,
        expected_state_root: str,
        attempt_id: str,
    ) -> TransitionReceipt:
        return self._transition_attempt(
            expected_epoch=expected_epoch,
            expected_state_root=expected_state_root,
            attempt_id=attempt_id,
            required_states=frozenset({self.REQUEST_TRANSMITTED}),
            next_state=self.RECONCILIATION_REQUIRED,
            payload={"reason": "external_consequence_not_yet_verified"},
        )

    def reconcile_observed(
        self,
        *,
        expected_epoch: int,
        expected_state_root: str,
        attempt_id: str,
        outcome: str,
        observation_hash: str,
        observer_id: str,
    ) -> TransitionReceipt:
        """Commit only a trusted reconciliation result, never a worker success claim."""

        _require_hash(observation_hash, "observation_hash")
        if not observer_id:
            raise CustodyViolation("observer_id_required")
        state_for_outcome = {
            "success": self.RECONCILED_SUCCESS,
            "failure": self.RECONCILED_FAILURE,
            "unresolved": self.UNRESOLVED,
        }.get(outcome)
        if state_for_outcome is None:
            raise CustodyViolation("reconciliation_outcome_invalid")
        return self._transition_attempt(
            expected_epoch=expected_epoch,
            expected_state_root=expected_state_root,
            attempt_id=attempt_id,
            required_states=frozenset(
                {self.REQUEST_TRANSMITTED, self.RECONCILIATION_REQUIRED}
            ),
            next_state=state_for_outcome,
            payload={
                "observer_id": observer_id,
                "observation_hash": observation_hash,
                "reconciliation_outcome": outcome,
            },
            updates={
                "observation_hash": observation_hash,
                "reconciliation_outcome": outcome,
            },
        )

    def attempt(self, attempt_id: str) -> AttemptSnapshot | None:
        if not attempt_id:
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT attempt_id, object_hash, target_hash, permit_hash,
                       authorization_hash, state, executor_id, provider_request_id,
                       observation_hash, reconciliation_outcome,
                       created_epoch, updated_epoch
                FROM custody_attempts WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            if row is None:
                return None
            return AttemptSnapshot(
                attempt_id=str(row[0]),
                object_hash=str(row[1]),
                target_hash=str(row[2]),
                permit_hash=str(row[3]),
                authorization_hash=str(row[4]),
                state=str(row[5]),
                executor_id=str(row[6]) if row[6] is not None else None,
                provider_request_id=str(row[7]) if row[7] is not None else None,
                observation_hash=str(row[8]) if row[8] is not None else None,
                reconciliation_outcome=str(row[9]) if row[9] is not None else None,
                created_epoch=int(row[10]),
                updated_epoch=int(row[11]),
            )
        except (OSError, sqlite3.Error) as exc:
            raise CustodyViolation("custody_store_unavailable") from exc
        finally:
            connection.close()

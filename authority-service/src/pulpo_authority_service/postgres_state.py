"""PostgreSQL authority state for the independent authority deployment boundary.

This adapter preserves the existing `AuthorityService` state contract while
moving serialization, durability, and trusted time into one PostgreSQL trust
domain. Every outer authority transition locks the single canonical state row
with `SELECT ... FOR UPDATE`, reloads the latest committed snapshot, and commits
one replacement snapshot. Independent service instances therefore serialize on
the database, not on process-local memory.

The adapter does not choose credentials or network topology. Production should
supply a connection factory authenticated as the dedicated authority service
identity (for example through the Cloud SQL Python connector with IAM database
authentication). Database administration and disaster recovery remain outside
this V0 trusted-custodian proof and require the recovery boundary frozen in #86.
"""

from __future__ import annotations

from collections.abc import Iterator, MutableMapping
from dataclasses import asdict
from hashlib import sha256
import json
import threading
from typing import Any, Callable

from .contract import ApprovalEnvelope
from .core import ApprovalRequest, CredentialRecord, RequestState


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class _DurableRequestState(RequestState):
    _TRACKED = {"status", "envelope", "reason", "evidence_hash", "evidence_bundle"}

    def __init__(
        self,
        request_id: str,
        request: ApprovalRequest,
        unsigned_envelope: ApprovalEnvelope,
        challenge: bytes,
        status: str = "pending",
        envelope: ApprovalEnvelope | None = None,
        reason: str | None = None,
        evidence_hash: str | None = None,
        evidence_bundle: dict[str, object] | None = None,
        *,
        on_change: Callable[[], None],
    ) -> None:
        object.__setattr__(self, "_on_change", None)
        super().__init__(
            request_id,
            request,
            unsigned_envelope,
            challenge,
            status,
            envelope,
            reason,
            evidence_hash,
            evidence_bundle,
        )
        object.__setattr__(self, "_on_change", on_change)

    def __setattr__(self, name: str, value: object) -> None:
        object.__setattr__(self, name, value)
        callback = getattr(self, "_on_change", None)
        if callback is not None and name in self._TRACKED:
            callback()


class _RequestMapping(MutableMapping[str, RequestState]):
    def __init__(self, state: "PostgresAuthorityState") -> None:
        self.state = state

    def __getitem__(self, key: str) -> RequestState:
        return self.state._request_values[key]

    def __setitem__(self, key: str, value: RequestState) -> None:
        with self.state.lock:
            self.state._request_values[key] = self.state._wrap_request(value)
            self.state._dirty = True

    def __delitem__(self, key: str) -> None:
        with self.state.lock:
            del self.state._request_values[key]
            self.state._dirty = True

    def __iter__(self) -> Iterator[str]:
        return iter(tuple(self.state._request_values))

    def __len__(self) -> int:
        return len(self.state._request_values)


class _CredentialMapping(MutableMapping[str, CredentialRecord]):
    def __init__(self, state: "PostgresAuthorityState") -> None:
        self.state = state

    def __getitem__(self, key: str) -> CredentialRecord:
        return self.state._credential_values[key]

    def __setitem__(self, key: str, value: CredentialRecord) -> None:
        with self.state.lock:
            self.state._credential_values[key] = value
            self.state._dirty = True

    def __delitem__(self, key: str) -> None:
        with self.state.lock:
            del self.state._credential_values[key]
            self.state._dirty = True

    def __iter__(self) -> Iterator[str]:
        return iter(tuple(self.state._credential_values))

    def __len__(self) -> int:
        return len(self.state._credential_values)


class _PostgresLock:
    def __init__(self, state: "PostgresAuthorityState") -> None:
        self.state = state

    def __enter__(self) -> "_PostgresLock":
        self.state._mutex.acquire()
        try:
            if self.state._depth == 0:
                connection = self.state.connection_factory()
                self.state._active_connection = connection
                try:
                    connection.execute("BEGIN")
                    row = connection.execute(
                        """
                        SELECT payload, state_hash
                        FROM pulpo_authority_state
                        WHERE singleton = TRUE
                        FOR UPDATE
                        """
                    ).fetchone()
                    if row is None:
                        raise RuntimeError("PostgreSQL authority state row is unavailable")
                    self.state._load_payload(str(row[0]), str(row[1]))
                except Exception:
                    try:
                        connection.rollback()
                    finally:
                        connection.close()
                        self.state._active_connection = None
                    raise
            self.state._depth += 1
            return self
        except Exception:
            self.state._mutex.release()
            raise

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            self.state._depth -= 1
            if self.state._depth != 0:
                return False
            connection = self.state._active_connection
            if connection is None:
                raise RuntimeError("PostgreSQL authority transaction disappeared")
            try:
                if exc_type is not None:
                    connection.rollback()
                else:
                    if self.state._dirty:
                        self.state._persist(connection)
                    connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
                self.state._active_connection = None
        finally:
            self.state._mutex.release()
        return False


class PostgresAuthorityState:
    """Pessimistically serialized canonical authority state in PostgreSQL."""

    SCHEMA = "pulpo.authority-postgres-state.v0"

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        credentials: tuple[CredentialRecord, ...],
    ) -> None:
        if not callable(connection_factory):
            raise ValueError("connection_factory must be callable")
        self.connection_factory = connection_factory
        self._mutex = threading.RLock()
        self._depth = 0
        self._dirty = False
        self._active_connection: Any | None = None
        self._sequence = 0
        self._last_time_ns = 0
        self._request_values: dict[str, _DurableRequestState] = {}
        self._credential_values: dict[str, CredentialRecord] = {}
        self.lock = _PostgresLock(self)
        self.requests = _RequestMapping(self)
        self.credentials = _CredentialMapping(self)
        self._ensure_schema_and_bootstrap(credentials)

    @property
    def sequence(self) -> int:
        return self._sequence

    @sequence.setter
    def sequence(self, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("authority sequence must be a non-negative integer")
        with self.lock:
            self._sequence = value
            self._dirty = True

    @property
    def last_time_ns(self) -> int:
        return self._last_time_ns

    @last_time_ns.setter
    def last_time_ns(self, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("last authority time must be a non-negative integer")
        with self.lock:
            self._last_time_ns = value
            self._dirty = True

    def trusted_time_ns(self) -> int:
        """Read database-server wall time inside the serialized transaction."""
        with self.lock:
            connection = self._active_connection
            if connection is None:
                raise RuntimeError("PostgreSQL trusted time requires an authority transaction")
            row = connection.execute(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000000)::bigint"
            ).fetchone()
            if row is None:
                raise RuntimeError("PostgreSQL trusted time is unavailable")
            value = int(row[0])
            if value <= 0:
                raise RuntimeError("PostgreSQL trusted time is invalid")
            return value

    def _ensure_schema_and_bootstrap(self, credentials: tuple[CredentialRecord, ...]) -> None:
        connection = self.connection_factory()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pulpo_authority_state (
                    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton = TRUE),
                    payload TEXT NOT NULL,
                    state_hash CHAR(64) NOT NULL
                )
                """
            )
            connection.commit()

            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT payload, state_hash
                FROM pulpo_authority_state
                WHERE singleton = TRUE
                FOR UPDATE
                """
            ).fetchone()
            if row is None:
                if not credentials:
                    raise ValueError("initial credentials are required for new PostgreSQL authority state")
                self._credential_values = {item.credential_id: item for item in credentials}
                payload = _canonical(self._snapshot()).decode()
                digest = sha256(payload.encode()).hexdigest()
                connection.execute(
                    """
                    INSERT INTO pulpo_authority_state(singleton, payload, state_hash)
                    VALUES (TRUE, %s, %s)
                    """,
                    (payload, digest),
                )
            else:
                self._load_payload(str(row[0]), str(row[1]))
                self._verify_bootstrap_credentials(credentials)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _mark_request_changed(self) -> None:
        with self.lock:
            self._dirty = True

    def _wrap_request(self, value: RequestState) -> _DurableRequestState:
        return _DurableRequestState(
            value.request_id,
            value.request,
            value.unsigned_envelope,
            value.challenge,
            value.status,
            value.envelope,
            value.reason,
            value.evidence_hash,
            value.evidence_bundle,
            on_change=self._mark_request_changed,
        )

    def _snapshot(self) -> dict[str, object]:
        credentials = []
        for credential_id in sorted(self._credential_values):
            item = self._credential_values[credential_id]
            credentials.append(
                {
                    "credential_id": item.credential_id,
                    "public_key_hex": item.public_key.hex(),
                    "sign_count": item.sign_count,
                    "role": item.role,
                    "active": item.active,
                    "hardware_attested": item.hardware_attested,
                    "backup_eligible": item.backup_eligible,
                }
            )
        requests = []
        for request_id in sorted(self._request_values):
            item = self._request_values[request_id]
            requests.append(
                {
                    "request_id": item.request_id,
                    "request": asdict(item.request),
                    "unsigned_envelope": asdict(item.unsigned_envelope),
                    "challenge_hex": item.challenge.hex(),
                    "status": item.status,
                    "envelope": None if item.envelope is None else asdict(item.envelope),
                    "reason": item.reason,
                    "evidence_hash": item.evidence_hash,
                    "evidence_bundle": item.evidence_bundle,
                }
            )
        return {
            "schema": self.SCHEMA,
            "sequence": self._sequence,
            "last_time_ns": self._last_time_ns,
            "credentials": credentials,
            "requests": requests,
        }

    def _persist(self, connection: Any) -> None:
        payload = _canonical(self._snapshot()).decode()
        digest = sha256(payload.encode()).hexdigest()
        cursor = connection.execute(
            """
            UPDATE pulpo_authority_state
            SET payload = %s, state_hash = %s
            WHERE singleton = TRUE
            """,
            (payload, digest),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("PostgreSQL authority state update lost canonical row")
        self._dirty = False

    def _load_payload(self, payload: str, expected_hash: str) -> None:
        actual_hash = sha256(payload.encode()).hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError("PostgreSQL authority state integrity failure")
        value = json.loads(payload)
        if value.get("schema") != self.SCHEMA:
            raise RuntimeError("unsupported PostgreSQL authority state schema")
        self._sequence = int(value["sequence"])
        self._last_time_ns = int(value["last_time_ns"])
        self._credential_values = {
            item["credential_id"]: CredentialRecord(
                credential_id=item["credential_id"],
                public_key=bytes.fromhex(item["public_key_hex"]),
                sign_count=int(item["sign_count"]),
                role=item["role"],
                active=bool(item["active"]),
                hardware_attested=bool(item["hardware_attested"]),
                backup_eligible=bool(item["backup_eligible"]),
            )
            for item in value["credentials"]
        }
        loaded_requests: dict[str, _DurableRequestState] = {}
        for item in value["requests"]:
            envelope_value = item["envelope"]
            loaded = _DurableRequestState(
                request_id=item["request_id"],
                request=ApprovalRequest(**item["request"]),
                unsigned_envelope=ApprovalEnvelope(**item["unsigned_envelope"]),
                challenge=bytes.fromhex(item["challenge_hex"]),
                status=item["status"],
                envelope=None if envelope_value is None else ApprovalEnvelope(**envelope_value),
                reason=item["reason"],
                evidence_hash=item["evidence_hash"],
                evidence_bundle=item.get("evidence_bundle"),
                on_change=self._mark_request_changed,
            )
            loaded_requests[loaded.request_id] = loaded
        self._request_values = loaded_requests
        self._dirty = False

    def _verify_bootstrap_credentials(self, credentials: tuple[CredentialRecord, ...]) -> None:
        if not credentials:
            return
        for supplied in credentials:
            persisted = self._credential_values.get(supplied.credential_id)
            if persisted is None:
                raise RuntimeError("bootstrap credential is absent from PostgreSQL authority state")
            immutable_supplied = (
                supplied.credential_id,
                supplied.public_key,
                supplied.role,
                supplied.hardware_attested,
                supplied.backup_eligible,
            )
            immutable_persisted = (
                persisted.credential_id,
                persisted.public_key,
                persisted.role,
                persisted.hardware_attested,
                persisted.backup_eligible,
            )
            if immutable_supplied != immutable_persisted:
                raise RuntimeError("bootstrap credential conflicts with PostgreSQL authority state")

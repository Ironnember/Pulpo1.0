"""Restart/durability acceptance adapters for the independent authority service.

These adapters exist to prove the authority state machine survives process
restart and cross-store interruption before a protected cloud state/evidence
implementation is admitted. They are deliberately *not* production custody:
a host that can rewrite the SQLite database or evidence directory can rewrite
this acceptance environment.
"""

from __future__ import annotations

from collections.abc import Iterator, MutableMapping
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Callable

from .contract import ApprovalEnvelope
from .core import ApprovalRequest, CredentialRecord, InMemoryState, RequestState


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class _DurableRequestState(RequestState):
    _TRACKED = {"status", "envelope", "reason", "evidence_hash"}

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
        )
        object.__setattr__(self, "_on_change", on_change)

    def __setattr__(self, name: str, value: object) -> None:
        object.__setattr__(self, name, value)
        callback = getattr(self, "_on_change", None)
        if callback is not None and name in self._TRACKED:
            callback()


class _PersistingLock:
    def __init__(self, state: "SQLiteRestartState") -> None:
        self.state = state

    def __enter__(self) -> "_PersistingLock":
        self.state._mutex.acquire()
        self.state._depth += 1
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            self.state._depth -= 1
            if self.state._depth == 0:
                if exc_type is not None:
                    if self.state._dirty:
                        self.state._reload_locked()
                elif self.state._dirty:
                    try:
                        self.state._persist_locked()
                    except Exception:
                        self.state._reload_locked()
                        raise
        finally:
            self.state._mutex.release()
        return False


class _RequestMapping(MutableMapping[str, RequestState]):
    def __init__(self, state: "SQLiteRestartState") -> None:
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
    def __init__(self, state: "SQLiteRestartState") -> None:
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


class SQLiteRestartState(InMemoryState):
    """Atomic single-row restart state for executable acceptance proofs only.

    The existing AuthorityService still owns all authority decisions. This
    adapter only makes its existing state durable. Mutations performed under the
    service's re-entrant lock are committed as one SQLite transaction. If the
    durable commit fails, the in-memory view is reloaded from the last committed
    snapshot before the error is returned.
    """

    SCHEMA = "pulpo.authority-restart-state.v0"

    def __init__(self, path: str | Path, credentials: tuple[CredentialRecord, ...]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._mutex = threading.RLock()
        self._depth = 0
        self._dirty = False
        self._sequence = 0
        self._last_time_ns = 0
        self._request_values: dict[str, _DurableRequestState] = {}
        self._credential_values: dict[str, CredentialRecord] = {}
        self.lock = _PersistingLock(self)
        self.requests = _RequestMapping(self)
        self.credentials = _CredentialMapping(self)
        self._ensure_schema()
        with self._mutex:
            if self._has_snapshot_locked():
                self._reload_locked()
                self._verify_bootstrap_credentials(credentials)
            else:
                if not credentials:
                    raise ValueError("initial credentials are required for a new restart state")
                self._credential_values = {item.credential_id: item for item in credentials}
                self._dirty = True
                self._persist_locked()

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
            on_change=self._mark_request_changed,
        )

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authority_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    payload TEXT NOT NULL,
                    state_hash TEXT NOT NULL
                )
                """
            )

    def _has_snapshot_locked(self) -> bool:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT 1 FROM authority_state WHERE singleton = 1"
            ).fetchone()
        return row is not None

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
                }
            )
        return {
            "schema": self.SCHEMA,
            "sequence": self._sequence,
            "last_time_ns": self._last_time_ns,
            "credentials": credentials,
            "requests": requests,
        }

    def _persist_locked(self) -> None:
        payload = _canonical(self._snapshot()).decode()
        digest = sha256(payload.encode()).hexdigest()
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO authority_state(singleton, payload, state_hash)
                VALUES (1, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    payload = excluded.payload,
                    state_hash = excluded.state_hash
                """,
                (payload, digest),
            )
            connection.commit()
        self._dirty = False

    def _reload_locked(self) -> None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT payload, state_hash FROM authority_state WHERE singleton = 1"
            ).fetchone()
        if row is None:
            raise RuntimeError("durable authority snapshot unavailable")
        payload, expected_hash = row
        actual_hash = sha256(payload.encode()).hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError("durable authority snapshot integrity failure")
        value = json.loads(payload)
        if value.get("schema") != self.SCHEMA:
            raise RuntimeError("unsupported durable authority snapshot schema")
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
                raise RuntimeError("bootstrap credential is absent from durable authority state")
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
                raise RuntimeError("bootstrap credential conflicts with durable authority state")


class DirectoryEvidenceSink:
    """Idempotent append-only-by-application evidence sink for restart proofs.

    Each exact evidence bundle is stored once under its SHA-256 digest. Existing
    objects are never overwritten. Host-level deletion or mutation is outside
    this adapter's trust model, which is why production still requires an
    independently locked retention store.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def append(self, bundle: dict[str, object]) -> str:
        encoded = _canonical(bundle) + b"\n"
        digest = sha256(_canonical(bundle)).hexdigest()
        target = self.directory / f"{digest}.json"
        try:
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if target.read_bytes() != encoded:
                raise RuntimeError("existing authority evidence object does not match its digest")
            return digest
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            raise
        return digest

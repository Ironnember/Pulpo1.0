"""Canonical kernel state backends.

The state backend persists replay guards, one-use permits, directives, and the
audit chain for the existing governance kernel. It is storage for that kernel,
not another router, policy engine, or evidence ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from os import PathLike
import sqlite3
from threading import RLock
from typing import Any, Protocol


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _delta_for(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Compact, non-authoritative state-change projection bound into the canonical audit record."""
    keys = (
        "outcome", "reason", "intent_hash", "approval_id", "directive_id", "version",
        "directive_version", "directive_hash", "target_id", "attempt_id", "transition_hash",
        "reconciliation_outcome",
    )
    delta = {"event": event, "payload_hash": sha256(_canonical(payload)).hexdigest()}
    for key in keys:
        if key in payload:
            delta[key] = payload[key]
    return delta


def _delta_state_root(previous_state_root: str, delta: dict[str, Any]) -> str:
    return sha256(_canonical({"previous_state_root": previous_state_root, "delta": delta})).hexdigest()


def _audit_record(previous_hash: str, event: str, payload: dict[str, Any], timestamp_ns: int) -> dict[str, Any]:
    body = {"event": event, "payload": payload, "previous_hash": previous_hash, "timestamp_ns": timestamp_ns}
    return {**body, "hash": sha256(_canonical(body)).hexdigest()}


def _attach_delta(record: dict[str, Any], previous_state_root: str) -> dict[str, Any]:
    body = {key: value for key, value in record.items() if key != "hash"}
    delta = _delta_for(str(body["event"]), body["payload"])
    body["delta"] = delta
    body["previous_state_root"] = previous_state_root
    body["state_root"] = _delta_state_root(previous_state_root, delta)
    return {**body, "hash": sha256(_canonical(body)).hexdigest()}


@dataclass(frozen=True)
class ApprovalUse:
    approval_id: str
    nonce: str
    audit_payload: dict[str, Any]


@dataclass(frozen=True)
class DirectivePermitBinding:
    directive_id: str
    version: int
    directive_hash: str
    issued_at_ns: int
    expires_at_ns: int
    parent_directive_hash: str | None = None

    def audit_payload(self) -> dict[str, Any]:
        payload = {
            "directive_id": self.directive_id,
            "directive_version": self.version,
            "directive_hash": self.directive_hash,
            "directive_issued_at_ns": self.issued_at_ns,
            "directive_expires_at_ns": self.expires_at_ns,
        }
        if self.parent_directive_hash is not None:
            payload["parent_directive_hash"] = self.parent_directive_hash
        return payload


class KernelState(Protocol):
    @property
    def audit(self) -> list[dict[str, Any]]: ...
    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None: ...
    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None) -> str | None: ...
    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None: ...
    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool: ...
    def directive_hash_status(self, directive_hash: str) -> str: ...
    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None: ...
    def append_unique(self, event: str, identity_field: str, identity_value: Any, payload: dict[str, Any], timestamp_ns: int) -> dict[str, Any] | None: ...


class InMemoryKernelState:
    def __init__(self) -> None:
        self._issued: dict[str, str] = {}
        self._spent: set[str] = set()
        self._approval_ids: set[str] = set()
        self._approval_nonces: set[str] = set()
        self._directives: dict[tuple[str, int], tuple[str, bool]] = {}
        self._permit_directives: dict[str, DirectivePermitBinding] = {}
        self._audit: list[dict[str, Any]] = []
        self._audit_lock = RLock()
        self._unique_audit: dict[tuple[str, str, str], dict[str, Any]] = {}

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self._audit

    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None:
        if approval_id in self._approval_ids: return "approval_id_replayed"
        if nonce in self._approval_nonces: return "approval_nonce_replayed"
        return None

    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None) -> str | None:
        if approval is not None:
            replay = self.approval_replay_reason(approval.approval_id, approval.nonce)
            if replay: return replay
            self._approval_ids.add(approval.approval_id); self._approval_nonces.add(approval.nonce)
            self.append("approval_verified", approval.audit_payload, timestamp_ns)
        self._issued[permit] = intent_hash
        self.append("decision", {"outcome": "allow", "reason": decision_reason, "intent_hash": intent_hash}, timestamp_ns)
        return None

    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None:
        if self._issued.get(permit) != intent_hash or permit in self._spent: raise ValueError("permit unavailable for directive binding")
        if permit in self._permit_directives: raise ValueError("permit directive binding is immutable")
        if self.directive_status(binding.directive_id, binding.version, binding.directive_hash) != "active": raise ValueError("directive is not active for permit binding")
        if binding.parent_directive_hash is not None and self.directive_hash_status(binding.parent_directive_hash) != "active": raise ValueError("parent directive is not active for permit binding")
        self._permit_directives[permit] = binding
        self.append("permit_bound_to_directive", {"intent_hash": intent_hash, **binding.audit_payload()}, timestamp_ns)

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        valid = self._issued.get(permit) == intent_hash and permit not in self._spent
        binding = self._permit_directives.get(permit)
        payload: dict[str, Any] = {"intent_hash": intent_hash}
        if binding is not None:
            status = self.directive_status(binding.directive_id, binding.version, binding.directive_hash)
            if status == "active" and binding.parent_directive_hash is not None:
                status = self.directive_hash_status(binding.parent_directive_hash)
            if status == "active" and not (binding.issued_at_ns <= timestamp_ns < binding.expires_at_ns): status = "directive_inactive"
            valid = valid and status == "active"
            payload.update(binding.audit_payload()); payload["directive_status"] = status
        if valid: self._spent.add(permit)
        self.append("permit_consumed" if valid else "permit_rejected", payload, timestamp_ns)
        return valid

    def activate_directive(self, directive, authority_evidence: dict[str, object], timestamp_ns: int) -> None:
        key = (directive.directive_id, directive.version)
        if key in self._directives: raise ValueError("directive version is immutable")
        parent_hash = getattr(directive, "parent_directive_hash", None)
        if parent_hash is not None and self.directive_hash_status(parent_hash) != "active":
            raise ValueError("parent directive is not active for activation")
        self._directives[key] = (directive.directive_hash, False)
        self.append("directive_activated", {"directive_id": directive.directive_id, "version": directive.version, "directive_hash": directive.directive_hash, "authority_evidence": authority_evidence}, timestamp_ns)

    def revoke_directive(self, directive_id: str, version: int, authority_evidence: dict[str, object], timestamp_ns: int) -> None:
        key = (directive_id, version)
        if key not in self._directives: raise ValueError("directive version not found")
        digest, _ = self._directives[key]; self._directives[key] = (digest, True)
        self.append("directive_revoked", {"directive_id": directive_id, "version": version, "directive_hash": digest, "authority_evidence": authority_evidence}, timestamp_ns)

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        value = self._directives.get((directive_id, version))
        if value is None: return "directive_not_authorized"
        digest, revoked = value
        if digest != directive_hash: return "directive_version_mismatch"
        return "directive_revoked" if revoked else "active"

    def directive_hash_status(self, directive_hash: str) -> str:
        for digest, revoked in self._directives.values():
            if digest == directive_hash:
                return "directive_parent_revoked" if revoked else "active"
        return "directive_parent_not_authorized"

    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None:
        with self._audit_lock:
            previous = self._audit[-1]["hash"] if self._audit else "0" * 64
            previous_root = self._audit[-1].get("state_root", previous) if self._audit else "0" * 64
            record = _audit_record(previous, event, payload, timestamp_ns)
            self._audit.append(_attach_delta(record, previous_root))

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        if not event or not identity_field or payload.get(identity_field) != identity_value:
            raise ValueError("unique audit identity invalid")
        with self._audit_lock:
            identity_key = (event, identity_field, _canonical(identity_value).decode())
            indexed = self._unique_audit.get(identity_key)
            if indexed is not None:
                return indexed
            matches = [
                record["payload"]
                for record in self._audit
                if record.get("event") == event
                and isinstance(record.get("payload"), dict)
                and record["payload"].get(identity_field) == identity_value
            ]
            if len(matches) > 1:
                raise ValueError("unique audit identity ambiguous")
            if matches:
                self._unique_audit[identity_key] = matches[0]
                return matches[0]
            previous = self._audit[-1]["hash"] if self._audit else "0" * 64
            previous_root = self._audit[-1].get("state_root", previous) if self._audit else "0" * 64
            record = _audit_record(previous, event, payload, timestamp_ns)
            self._audit.append(_attach_delta(record, previous_root))
            self._unique_audit[identity_key] = payload
            return None


class SQLiteKernelState:
    def __init__(self, path: str | PathLike[str]) -> None:
        self._connection = sqlite3.connect(path)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1)));
            CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS directives (directive_id TEXT NOT NULL, version INTEGER NOT NULL, directive_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)), PRIMARY KEY (directive_id, version));
            CREATE INDEX IF NOT EXISTS idx_directives_hash ON directives(directive_hash);
            CREATE TABLE IF NOT EXISTS permit_directives (permit TEXT PRIMARY KEY REFERENCES permits(permit) ON DELETE CASCADE, directive_id TEXT NOT NULL, directive_version INTEGER NOT NULL, directive_hash TEXT NOT NULL, directive_issued_at_ns INTEGER NOT NULL, directive_expires_at_ns INTEGER NOT NULL, parent_directive_hash TEXT);
            CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, timestamp_ns INTEGER NOT NULL, hash TEXT NOT NULL, delta_json TEXT, previous_state_root TEXT, state_root TEXT);
            CREATE INDEX IF NOT EXISTS idx_audit_event ON audit(event);
            CREATE TABLE IF NOT EXISTS audit_unique (
                event TEXT NOT NULL,
                identity_field TEXT NOT NULL,
                identity_value_json TEXT NOT NULL,
                sequence INTEGER NOT NULL UNIQUE REFERENCES audit(sequence) ON DELETE CASCADE,
                PRIMARY KEY (event, identity_field, identity_value_json)
            );
        """)
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info(permit_directives)").fetchall()}
        if "parent_directive_hash" not in columns:
            self._connection.execute("ALTER TABLE permit_directives ADD COLUMN parent_directive_hash TEXT")
        audit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(audit)").fetchall()}
        for column in ("delta_json", "previous_state_root", "state_root"):
            if column not in audit_columns:
                self._connection.execute(f"ALTER TABLE audit ADD COLUMN {column} TEXT")
        self._connection.execute("CREATE INDEX IF NOT EXISTS idx_directives_hash ON directives(directive_hash)")
        self._connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit(event)")

    @property
    def audit(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT event, payload_json, previous_hash, timestamp_ns, hash, delta_json, previous_state_root, state_root FROM audit ORDER BY sequence"
        ).fetchall()
        records: list[dict[str, Any]] = []
        for event, payload_json, previous_hash, timestamp_ns, digest, delta_json, previous_state_root, state_root in rows:
            record = {
                "event": event,
                "payload": json.loads(payload_json),
                "previous_hash": previous_hash,
                "timestamp_ns": timestamp_ns,
                "hash": digest,
            }
            if delta_json is not None:
                record["delta"] = json.loads(delta_json)
                record["previous_state_root"] = previous_state_root
                record["state_root"] = state_root
            records.append(record)
        return records

    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None: return self._approval_replay_reason(approval_id, nonce)
    def _approval_replay_reason(self, approval_id: str, nonce: str) -> str | None:
        row = self._connection.execute(
            """
            SELECT CASE
                WHEN EXISTS (SELECT 1 FROM approvals WHERE approval_id = ?) THEN 'approval_id_replayed'
                WHEN EXISTS (SELECT 1 FROM approvals WHERE nonce = ?) THEN 'approval_nonce_replayed'
                ELSE NULL
            END
            """,
            (approval_id, nonce),
        ).fetchone()
        return row[0] if row is not None else None

    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None) -> str | None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if approval is not None:
                replay = self._approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                self._connection.execute("INSERT INTO approvals (approval_id, nonce) VALUES (?, ?)", (approval.approval_id, approval.nonce))
            self._connection.execute("INSERT INTO permits (permit, intent_hash) VALUES (?, ?)", (permit, intent_hash))
            if approval is not None: self._append("approval_verified", approval.audit_payload, timestamp_ns)
            self._append("decision", {"outcome": "allow", "reason": decision_reason, "intent_hash": intent_hash}, timestamp_ns)
        return None

    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute("SELECT intent_hash, spent FROM permits WHERE permit = ?", (permit,)).fetchone()
            if row is None or row[0] != intent_hash or row[1] != 0: raise ValueError("permit unavailable for directive binding")
            if self._connection.execute("SELECT 1 FROM permit_directives WHERE permit = ?", (permit,)).fetchone(): raise ValueError("permit directive binding is immutable")
            directive = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id = ? AND version = ?", (binding.directive_id, binding.version)).fetchone()
            if directive is None or directive[0] != binding.directive_hash or directive[1] != 0: raise ValueError("directive is not active for permit binding")
            if binding.parent_directive_hash is not None and self.directive_hash_status(binding.parent_directive_hash) != "active": raise ValueError("parent directive is not active for permit binding")
            self._connection.execute("INSERT INTO permit_directives (permit, directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash) VALUES (?, ?, ?, ?, ?, ?, ?)", (permit, binding.directive_id, binding.version, binding.directive_hash, binding.issued_at_ns, binding.expires_at_ns, binding.parent_directive_hash))
            self._append("permit_bound_to_directive", {"intent_hash": intent_hash, **binding.audit_payload()}, timestamp_ns)

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            permit_row = self._connection.execute("SELECT intent_hash, spent FROM permits WHERE permit = ?", (permit,)).fetchone()
            valid = permit_row is not None and permit_row[0] == intent_hash and permit_row[1] == 0
            payload: dict[str, Any] = {"intent_hash": intent_hash}
            row = self._connection.execute("SELECT directive_id, directive_version, directive_hash, directive_issued_at_ns, directive_expires_at_ns, parent_directive_hash FROM permit_directives WHERE permit = ?", (permit,)).fetchone()
            if row is not None:
                binding = DirectivePermitBinding(row[0], row[1], row[2], row[3], row[4], row[5])
                directive = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id = ? AND version = ?", (binding.directive_id, binding.version)).fetchone()
                if directive is None: status = "directive_not_authorized"
                elif directive[0] != binding.directive_hash: status = "directive_version_mismatch"
                elif directive[1] != 0: status = "directive_revoked"
                elif binding.parent_directive_hash is not None: status = self.directive_hash_status(binding.parent_directive_hash)
                else: status = "active"
                if status == "active" and not (binding.issued_at_ns <= timestamp_ns < binding.expires_at_ns): status = "directive_inactive"
                valid = valid and status == "active"
                payload.update(binding.audit_payload()); payload["directive_status"] = status
            if valid:
                cursor = self._connection.execute("UPDATE permits SET spent = 1 WHERE permit = ? AND intent_hash = ? AND spent = 0", (permit, intent_hash))
                valid = cursor.rowcount == 1
            self._append("permit_consumed" if valid else "permit_rejected", payload, timestamp_ns)
        return valid

    def activate_directive(self, directive, authority_evidence: dict[str, object], timestamp_ns: int) -> None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if self._connection.execute("SELECT 1 FROM directives WHERE directive_id=? AND version=?", (directive.directive_id, directive.version)).fetchone(): raise ValueError("directive version is immutable")
            parent_hash = getattr(directive, "parent_directive_hash", None)
            if parent_hash is not None:
                parent = self._connection.execute("SELECT revoked FROM directives WHERE directive_hash=?", (parent_hash,)).fetchone()
                if parent is None or parent[0] != 0:
                    raise ValueError("parent directive is not active for activation")
            self._connection.execute("INSERT INTO directives (directive_id, version, directive_hash) VALUES (?, ?, ?)", (directive.directive_id, directive.version, directive.directive_hash))
            self._append("directive_activated", {"directive_id": directive.directive_id, "version": directive.version, "directive_hash": directive.directive_hash, "authority_evidence": authority_evidence}, timestamp_ns)

    def revoke_directive(self, directive_id: str, version: int, authority_evidence: dict[str, object], timestamp_ns: int) -> None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute("SELECT directive_hash FROM directives WHERE directive_id=? AND version=?", (directive_id, version)).fetchone()
            if row is None: raise ValueError("directive version not found")
            self._connection.execute("UPDATE directives SET revoked=1 WHERE directive_id=? AND version=?", (directive_id, version))
            self._append("directive_revoked", {"directive_id": directive_id, "version": version, "directive_hash": row[0], "authority_evidence": authority_evidence}, timestamp_ns)

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        row = self._connection.execute("SELECT directive_hash, revoked FROM directives WHERE directive_id=? AND version=?", (directive_id, version)).fetchone()
        if row is None: return "directive_not_authorized"
        if row[0] != directive_hash: return "directive_version_mismatch"
        return "directive_revoked" if row[1] else "active"

    def directive_hash_status(self, directive_hash: str) -> str:
        row = self._connection.execute("SELECT revoked FROM directives WHERE directive_hash=?", (directive_hash,)).fetchone()
        if row is None: return "directive_parent_not_authorized"
        return "directive_parent_revoked" if row[0] else "active"

    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE"); self._append(event, payload, timestamp_ns)

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        if not event or not identity_field or payload.get(identity_field) != identity_value:
            raise ValueError("unique audit identity invalid")
        identity_json = _canonical(identity_value).decode()
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            indexed = self._connection.execute(
                """
                SELECT a.payload_json
                FROM audit_unique u
                JOIN audit a ON a.sequence = u.sequence
                WHERE u.event = ? AND u.identity_field = ? AND u.identity_value_json = ?
                """,
                (event, identity_field, identity_json),
            ).fetchone()
            if indexed is not None:
                return json.loads(str(indexed[0]))

            # Compatibility path for databases created before the unique projection.
            rows = self._connection.execute(
                "SELECT sequence, payload_json FROM audit WHERE event = ? ORDER BY sequence",
                (event,),
            ).fetchall()
            matches: list[tuple[int, dict[str, Any]]] = []
            for sequence, encoded in rows:
                candidate = json.loads(str(encoded))
                if isinstance(candidate, dict) and candidate.get(identity_field) == identity_value:
                    matches.append((sequence, candidate))
            if len(matches) > 1:
                raise ValueError("unique audit identity ambiguous")
            if matches:
                sequence, candidate = matches[0]
                self._connection.execute(
                    "INSERT OR IGNORE INTO audit_unique (event, identity_field, identity_value_json, sequence) VALUES (?, ?, ?, ?)",
                    (event, identity_field, identity_json, sequence),
                )
                return candidate

            sequence = self._append(event, payload, timestamp_ns)
            self._connection.execute(
                "INSERT INTO audit_unique (event, identity_field, identity_value_json, sequence) VALUES (?, ?, ?, ?)",
                (event, identity_field, identity_json, sequence),
            )
            return None

    def _append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> int:
        row = self._connection.execute(
            "SELECT hash, state_root FROM audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = row[0] if row else "0" * 64
        previous_root = (row[1] or row[0]) if row else "0" * 64
        record = _attach_delta(
            _audit_record(previous, event, payload, timestamp_ns),
            previous_root,
        )
        cursor = self._connection.execute(
            """
            INSERT INTO audit (
                event, payload_json, previous_hash, timestamp_ns, hash,
                delta_json, previous_state_root, state_root
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["event"],
                _canonical(record["payload"]).decode(),
                record["previous_hash"],
                record["timestamp_ns"],
                record["hash"],
                _canonical(record["delta"]).decode(),
                record["previous_state_root"],
                record["state_root"],
            ),
        )
        return int(cursor.lastrowid)

    def close(self) -> None: self._connection.close()

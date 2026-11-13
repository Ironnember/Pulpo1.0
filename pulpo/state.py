"""Canonical kernel state backends.

The state backend persists replay guards, one-use permits, directives, and the
audit chain for the existing governance kernel. It is storage for that kernel,
not another router, policy engine, or evidence ledger.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from os import PathLike
import sqlite3
from threading import RLock
from typing import Any, Protocol
from urllib.parse import quote as _url_quote


# Reuse the unchanged encoder configuration; per-call state stays in encode().
_CANONICAL_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"))


def _canonical(value: Any) -> bytes:
    return _CANONICAL_ENCODER.encode(value).encode()


class AuditSigner:
    """HMAC-SHA256 signer/verifier for audit records (Phase 2, Item 1).

    One signer per deployment, keyed by a dedicated ``audit-secret``
    that is deliberately NOT the kernel secret: a single theft must not
    yield both permit minting and undetectable history forgery. The
    signature covers the record's own ``hash`` and is stored as a
    sibling field, excluded from the hashed body — the exact pattern
    ``AuditAnchor`` uses (``signing_payload()`` excludes ``signature``).
    The field is algorithm-agile: a future Ed25519 signer can replace
    this class behind the same record shape without changing the chain
    math. Verification is constant-time; a missing, non-string, or
    malformed signature never verifies.
    """

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ValueError("audit secret must be non-empty")
        self._secret = secret

    def sign(self, record_hash: str) -> str:
        if not isinstance(record_hash, str):
            raise TypeError("record hash must be a string")
        return hmac.new(self._secret, record_hash.encode("utf-8"), sha256).hexdigest()

    def verify(self, record_hash: str, signature: Any) -> bool:
        if not isinstance(signature, str) or not signature:
            return False
        try:
            expected = self.sign(record_hash)
        except (AttributeError, TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, signature)


def _audit_record(previous_hash: str, event: str, payload: dict[str, Any], timestamp_ns: int, signer: AuditSigner | None = None) -> dict[str, Any]:
    body = {"event": event, "payload": payload, "previous_hash": previous_hash, "timestamp_ns": timestamp_ns}
    record = {**body, "hash": sha256(_canonical(body)).hexdigest()}
    if signer is not None:
        # The signature is computed over the record hash and stored as a
        # sibling field: it is NOT part of the hashed body, so the
        # unkeyed chain math is unchanged and old verifiers recomputing
        # the body still agree on the hash. Verification of the
        # signature is the kernel's job (verify_audit), not this
        # constructor's.
        record["signature"] = signer.sign(record["hash"])
    return record


@dataclass(frozen=True)
class ApprovalUse:
    approval_id: str
    nonce: str
    audit_payload: dict[str, Any]
    ceremony_evidence_id: str | None = None


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
    def ceremony_replay_reason(self, evidence_id: str) -> str | None: ...
    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None) -> str | None: ...
    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None: ...
    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool: ...
    def directive_hash_status(self, directive_hash: str) -> str: ...
    def append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None: ...
    def append_unique(self, event: str, identity_field: str, identity_value: Any, payload: dict[str, Any], timestamp_ns: int) -> dict[str, Any] | None: ...


class InMemoryKernelState:
    def __init__(self, audit_signer: AuditSigner | None = None, legacy_audit_records: int = 0) -> None:
        # Audit signing (Phase 2, Item 1): when a signer is supplied,
        # every appended record carries an HMAC over its hash. When no
        # signer is supplied the backend stays in legacy mode — records
        # are unsigned and verification is the unkeyed chain alone — so
        # direct construction keeps its exact pre-signing behavior.
        # ``legacy_audit_records`` is the count of leading records that
        # predate enablement: they verify legacy-style and are reported
        # as an unsigned prefix. The enablement itself is recorded in
        # deployment config outside the state file (ops), never here.
        self.audit_signer = audit_signer
        self.legacy_audit_records = legacy_audit_records
        self._issued: dict[str, str] = {}
        self._spent: set[str] = set()
        self._approval_ids: set[str] = set()
        self._approval_nonces: set[str] = set()
        self._ceremony_evidence_ids: set[str] = set()
        self._directives: dict[tuple[str, int], tuple[str, bool]] = {}
        self._permit_directives: dict[str, DirectivePermitBinding] = {}
        self._audit: list[dict[str, Any]] = []
        self._audit_lock = RLock()

    @property
    def audit(self) -> list[dict[str, Any]]:
        # Return detached deep copies, copied under the audit lock, matching
        # the SQLite backend (which rebuilds fresh records from rows on every
        # read). Returning the live list let any holder of the kernel delete
        # records, append forged ones, or rewrite a record's payload in the
        # stored trail through the read path alone.
        # Regression: tests/test_inmemory_audit_detached_copies.py.
        with self._audit_lock:
            return deepcopy(self._audit)

    def approval_replay_reason(self, approval_id: str, nonce: str) -> str | None:
        if approval_id in self._approval_ids: return "approval_id_replayed"
        if nonce in self._approval_nonces: return "approval_nonce_replayed"
        return None

    def ceremony_replay_reason(self, evidence_id: str) -> str | None:
        if evidence_id in self._ceremony_evidence_ids: return "ceremony_evidence_replayed"
        return None

    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None) -> str | None:
        # Serialize the whole check-and-record transition under the audit
        # lock (an RLock; append() re-enters it). The SQLite backend gets
        # the same atomicity from its BEGIN IMMEDIATE transaction: without
        # it, two concurrent issuances can both observe an approval or a
        # ceremony evidence id as unconsumed before either records it,
        # voiding single-use. Regression: tests/test_inmemory_ceremony_concurrency.py.
        with self._audit_lock:
            if approval is not None:
                replay = self.approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                if approval.ceremony_evidence_id is not None:
                    ceremony_replay = self.ceremony_replay_reason(approval.ceremony_evidence_id)
                    if ceremony_replay: return ceremony_replay
                    self._ceremony_evidence_ids.add(approval.ceremony_evidence_id)
                self._approval_ids.add(approval.approval_id); self._approval_nonces.add(approval.nonce)
                self.append("approval_verified", approval.audit_payload, timestamp_ns)
            self._issued[permit] = intent_hash
            self.append("decision", {"outcome": "allow", "reason": decision_reason, "intent_hash": intent_hash}, timestamp_ns)
            return None

    def bind_permit_to_directive(self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int) -> None:
        # Serialized under the same lock as issue_permit/consume_permit:
        # the availability and directive-status checks must hold against
        # the same state the binding is recorded into.
        with self._audit_lock:
            if self._issued.get(permit) != intent_hash or permit in self._spent: raise ValueError("permit unavailable for directive binding")
            if permit in self._permit_directives: raise ValueError("permit directive binding is immutable")
            if self.directive_status(binding.directive_id, binding.version, binding.directive_hash) != "active": raise ValueError("directive is not active for permit binding")
            if binding.parent_directive_hash is not None and self.directive_hash_status(binding.parent_directive_hash) != "active": raise ValueError("parent directive is not active for permit binding")
            self._permit_directives[permit] = binding
            self.append("permit_bound_to_directive", {"intent_hash": intent_hash, **binding.audit_payload()}, timestamp_ns)

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        # Serialize the whole check-and-record transition under the audit
        # lock (an RLock; append() re-enters it), mirroring the SQLite
        # backend's BEGIN IMMEDIATE transaction and issue_permit above.
        # Without it, a revoke_directive completing mid-consume still
        # admitted against the pre-revocation status, and two concurrent
        # consumptions of one permit could both observe it unspent
        # before either recorded the spend, voiding single-use.
        # Regression: tests/test_inmemory_consume_concurrency.py.
        with self._audit_lock:
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
        # Serialized under the same lock: the immutability and parent
        # checks must hold against the state the activation records into.
        with self._audit_lock:
            key = (directive.directive_id, directive.version)
            if key in self._directives: raise ValueError("directive version is immutable")
            parent_hash = getattr(directive, "parent_directive_hash", None)
            if parent_hash is not None and self.directive_hash_status(parent_hash) != "active":
                raise ValueError("parent directive is not active for activation")
            self._directives[key] = (directive.directive_hash, False)
            self.append("directive_activated", {"directive_id": directive.directive_id, "version": directive.version, "directive_hash": directive.directive_hash, "authority_evidence": authority_evidence}, timestamp_ns)

    def revoke_directive(self, directive_id: str, version: int, authority_evidence: dict[str, object], timestamp_ns: int) -> None:
        # Serialized under the same lock: the revocation mutation and its
        # audit append are one transition, atomic against consume_permit's
        # status read -- a revocation fully precedes or fully follows any
        # consumption, and never lands inside one.
        with self._audit_lock:
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
            # Detach the payload at write, matching the SQLite backend,
            # which serializes at write: embedding the caller's dict by
            # reference let a caller rewrite the stored record afterwards
            # by mutating its own dict, with no state call at all
            # (writer-custody Phase 1; diagnosis Repro C).
            # Regression: tests/test_writer_custody.py.
            self._audit.append(_audit_record(previous, event, deepcopy(payload), timestamp_ns, signer=self.audit_signer))

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
                # Detached copy, as on the SQLite backend (which returns a
                # freshly decoded payload): the caller must not be able to
                # rewrite the stored record through the returned payload.
                return deepcopy(matches[0])
            previous = self._audit[-1]["hash"] if self._audit else "0" * 64
            # Detached at write, as in append() above (diagnosis Repro C).
            self._audit.append(_audit_record(previous, event, deepcopy(payload), timestamp_ns, signer=self.audit_signer))
            return None


class SQLiteKernelState:
    def __init__(self, path: str | PathLike[str], audit_signer: AuditSigner | None = None, legacy_audit_records: int = 0, migrate_schema: bool = True) -> None:
        # Audit signing (Phase 2, Item 1): same contract as the
        # in-memory backend — a signer signs every appended record, no
        # signer means legacy unsigned mode. ``legacy_audit_records``
        # counts the leading pre-enablement records (see above).
        #
        # ``migrate_schema`` gates the schema migrations below. Mutating
        # opens take the default (True): a deployment created before a
        # column existed gains it on first mutating open. Read-only
        # projections MUST pass False: with it the state is opened
        # through a read-only connection and no DDL runs at all, so
        # inspecting a deployment can neither silently rewrite its
        # canonical state nor fail outright on a read-only mount (Codex
        # P1 on PR #357 — a projection open used to execute both ALTERs
        # below). The gate covers BOTH migrations, not just the new
        # signature column: the permit_directives migration is the
        # identical shape, and a pre-#355 deployment would fail
        # verification on a read-only mount through that ALTER alone.
        # The read path tolerates a missing signature column (see
        # ``audit``); permit_directives is never read by a projection,
        # and mutating opens always migrate before any read of it.
        self.audit_signer = audit_signer
        self.legacy_audit_records = legacy_audit_records
        self._migrate_schema = migrate_schema
        if migrate_schema:
            self._connection = sqlite3.connect(path)
        else:
            # mode=ro: the open itself must not require write access,
            # or a read-only mount fails before any statement runs.
            # The URI is quoted so deployment paths carrying "?" or "#"
            # cannot change the query string. A missing state file
            # fails to open here (fail closed) instead of being
            # silently created as an empty chain.
            self._connection = sqlite3.connect(
                f"file:{_url_quote(str(path), safe='/')}?mode=ro", uri=True
            )
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA synchronous = FULL")
        if migrate_schema:
            self._connection.executescript("""
                CREATE TABLE IF NOT EXISTS permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1)));
                CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS ceremony_evidence (evidence_id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS directives (directive_id TEXT NOT NULL, version INTEGER NOT NULL, directive_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)), PRIMARY KEY (directive_id, version));
                CREATE TABLE IF NOT EXISTS permit_directives (permit TEXT PRIMARY KEY REFERENCES permits(permit) ON DELETE CASCADE, directive_id TEXT NOT NULL, directive_version INTEGER NOT NULL, directive_hash TEXT NOT NULL, directive_issued_at_ns INTEGER NOT NULL, directive_expires_at_ns INTEGER NOT NULL, parent_directive_hash TEXT);
                CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL, payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, timestamp_ns INTEGER NOT NULL, hash TEXT NOT NULL, signature TEXT);
            """)
            columns = {row[1] for row in self._connection.execute("PRAGMA table_info(permit_directives)").fetchall()}
            if "parent_directive_hash" not in columns:
                self._connection.execute("ALTER TABLE permit_directives ADD COLUMN parent_directive_hash TEXT")
            # The audit signature column (Phase 2, Item 1): deployments
            # created before it existed gain it on first mutating open,
            # following the permit_directives migration precedent above.
            # Existing records keep NULL signatures — they are the legacy
            # prefix, verified by hash alone until the deployment
            # enables signing.
            audit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(audit)").fetchall()}
            if "signature" not in audit_columns:
                self._connection.execute("ALTER TABLE audit ADD COLUMN signature TEXT")
        # Whether the audit table carries a signature column, read once
        # at open: with migration it is always present; without it, a
        # legacy database reports False and the read/append paths below
        # adapt instead of assuming the column exists.
        audit_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(audit)").fetchall()}
        self._audit_has_signature = "signature" in audit_columns

    @property
    def audit(self) -> list[dict[str, Any]]:
        # A legacy database opened without migration has no signature
        # column: read the records without it (signature None) rather
        # than failing the projection with "no such column".
        if self._audit_has_signature:
            rows = self._connection.execute("SELECT event, payload_json, previous_hash, timestamp_ns, hash, signature FROM audit ORDER BY sequence").fetchall()
        else:
            rows = self._connection.execute("SELECT event, payload_json, previous_hash, timestamp_ns, hash FROM audit ORDER BY sequence").fetchall()
            rows = [(event, payload_json, previous_hash, timestamp_ns, record_hash, None) for event, payload_json, previous_hash, timestamp_ns, record_hash in rows]
        records = []
        for event, payload_json, previous_hash, timestamp_ns, record_hash, signature in rows:
            record: dict[str, Any] = {"event": event, "payload": json.loads(payload_json), "previous_hash": previous_hash, "timestamp_ns": timestamp_ns, "hash": record_hash}
            if signature is not None:
                record["signature"] = signature
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

    def ceremony_replay_reason(self, evidence_id: str) -> str | None: return self._ceremony_replay_reason(evidence_id)
    def _ceremony_replay_reason(self, evidence_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM ceremony_evidence WHERE evidence_id = ?) THEN 'ceremony_evidence_replayed' ELSE NULL END",
            (evidence_id,),
        ).fetchone()
        return row[0] if row is not None else None

    def issue_permit(self, permit: str, intent_hash: str, decision_reason: str, timestamp_ns: int, approval: ApprovalUse | None = None) -> str | None:
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            if approval is not None:
                replay = self._approval_replay_reason(approval.approval_id, approval.nonce)
                if replay: return replay
                if approval.ceremony_evidence_id is not None:
                    ceremony_replay = self._ceremony_replay_reason(approval.ceremony_evidence_id)
                    if ceremony_replay: return ceremony_replay
                    self._connection.execute("INSERT INTO ceremony_evidence (evidence_id) VALUES (?)", (approval.ceremony_evidence_id,))
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
        # A signer configured over a database without a signature column
        # (a read-only open over a legacy database) must never silently
        # append unsigned: fail loudly before the write is attempted.
        # See _append for the same guard on the direct path.
        if self.audit_signer is not None and not self._audit_has_signature:
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")
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
        # Same loud failure as append(): a signer over a database
        # without a signature column never appends unsigned.
        if self.audit_signer is not None and not self._audit_has_signature:
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            rows = self._connection.execute(
                "SELECT payload_json FROM audit WHERE event = ? ORDER BY sequence",
                (event,),
            ).fetchall()
            matches: list[dict[str, Any]] = []
            for (encoded,) in rows:
                candidate = json.loads(str(encoded))
                if isinstance(candidate, dict) and candidate.get(identity_field) == identity_value:
                    matches.append(candidate)
            if len(matches) > 1:
                raise ValueError("unique audit identity ambiguous")
            if matches:
                return matches[0]
            self._append(event, payload, timestamp_ns)
            return None

    def _append(self, event: str, payload: dict[str, Any], timestamp_ns: int) -> None:
        row = self._connection.execute("SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1").fetchone(); previous = row[0] if row else "0" * 64
        record = _audit_record(previous, event, payload, timestamp_ns, signer=self.audit_signer)
        if not self._audit_has_signature and self.audit_signer is not None:
            # Opened without migration over a legacy database: a signer
            # configured here must never silently append unsigned — the
            # record would be refused at the next boot, bricking the
            # deployment (Codex P1 on PR #357). Fail loudly instead; the
            # caller re-opens with migration to add the column first.
            # (The same guard sits in append()/append_unique() so the
            # precise error fires before the connection's own write
            # refusal; this one covers direct _append callers.)
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")
        self._connection.execute("INSERT INTO audit (event, payload_json, previous_hash, timestamp_ns, hash, signature) VALUES (?, ?, ?, ?, ?, ?)", (record["event"], _canonical(record["payload"]).decode(), record["previous_hash"], record["timestamp_ns"], record["hash"], record.get("signature")))

    def close(self) -> None: self._connection.close()

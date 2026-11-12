"""External anchored head for the canonical audit chain.

The kernel audit chain is an unkeyed SHA-256 chain that does not commit to
its own length.  ``GovernanceKernel.verify_audit`` therefore proves internal
consistency of the records it is shown, but a writer with direct access to
the audit store can truncate the chain's tail, or delete a record and
recompute every following ``previous_hash``/``hash``, and the shortened or
rebuilt chain still verifies (see the documented gaps in
``tests/test_mythos_laundering_scenario.py``).

This module is the external witness for that gap.  An anchor records the
audit head hash and record count at a moment in time, chained to the
previous anchor and optionally counter-signed by a key held outside the
kernel, in an append-only store that is not writable through the kernel or
state API surface.  ``verify_anchored_audit`` fails closed unless the anchor
history is intact and every anchor still matches the exact prefix of the
presented audit trail it witnessed.

Trust domain, stated plainly: anchoring detects tampering with the audit
store relative to the anchor history the verifier holds.  It does not
protect against a writer who can also rewrite the anchor store and, for
signed anchors, holds the anchor key; that writer is outside this layer's
scope.  Truncating the tail of the anchor history itself cannot be
distinguished from anchoring having stopped earlier; it only reduces the
witnessed coverage, and verification reports exactly how many records the
latest surviving anchor covers.

Anchoring is observation, not governance.  It appends nothing to the
canonical audit chain, grants no authority, and changes no kernel state.
The anchor store is a witness log for one audit trail, not a second ledger
of governed transitions and not an authority plane.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Protocol, Sequence


GENESIS_HASH = "0" * 64
ANCHOR_SCHEMA = "pulpo.audit-anchor.v1"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_sha256(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class AuditAnchor:
    """One witnessed audit head: exact record count plus head hash."""

    sequence: int
    record_count: int
    head_hash: str
    previous_anchor_hash: str
    timestamp_ns: int
    signature: str = ""
    schema: str = ANCHOR_SCHEMA

    def __post_init__(self) -> None:
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise ValueError("anchor sequence must be a non-negative integer")
        if isinstance(self.record_count, bool) or not isinstance(self.record_count, int) or self.record_count < 0:
            raise ValueError("anchor record_count must be a non-negative integer")
        _require_sha256(self.head_hash, "anchor head_hash")
        _require_sha256(self.previous_anchor_hash, "anchor previous_anchor_hash")
        if (self.record_count == 0) != (self.head_hash == GENESIS_HASH):
            raise ValueError("anchor head must be the genesis hash exactly when record_count is zero")
        if isinstance(self.timestamp_ns, bool) or not isinstance(self.timestamp_ns, int) or self.timestamp_ns <= 0:
            raise ValueError("anchor timestamp_ns must be positive")
        if self.schema != ANCHOR_SCHEMA:
            raise ValueError("unsupported audit anchor schema")

    def signing_payload(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_payload())

    @property
    def anchor_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class AnchorVerification:
    """Fail-closed result of checking an audit trail against its anchors."""

    ok: bool
    reason: str
    anchored_records: int = 0
    total_records: int = 0
    anchors_checked: int = 0


class AnchorSigner(Protocol):
    """Signs anchor payloads with a key held outside the governed kernel."""

    def sign(self, payload: bytes) -> str: ...


class AnchorVerifier(Protocol):
    """Verifies anchor signatures against a caller-pinned key."""

    def verify(self, payload: bytes, signature: str) -> bool: ...


class HmacAnchorSigner:
    """HMAC-SHA256 anchor signer/verifier keyed by the anchor operator.

    The key belongs to whoever operates the witness (for example the
    deployment owner running a separate anchoring job).  It is not a human
    approval credential and must never be the kernel's permit secret: the
    trust separation between the audit writer and the anchor witness is the
    control.  Deployments that need asymmetric custody can implement the
    same two protocols over their existing signature machinery.
    """

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("anchor key must be non-empty")
        self._key = key

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class AnchorStore(Protocol):
    """Append-only witness storage, outside the kernel/state API surface."""

    def append(self, anchor: AuditAnchor) -> None: ...
    def anchors(self) -> list[AuditAnchor]: ...


def _check_extension(existing: Sequence[AuditAnchor], anchor: AuditAnchor) -> None:
    expected_sequence = len(existing)
    expected_previous = existing[-1].anchor_hash if existing else GENESIS_HASH
    if anchor.sequence != expected_sequence:
        raise ValueError("anchor does not extend the anchor history sequence")
    if anchor.previous_anchor_hash != expected_previous:
        raise ValueError("anchor does not extend the anchor history head")


class InMemoryAnchorStore:
    """Append-only in-process anchor store; reads return detached copies."""

    def __init__(self) -> None:
        self._anchors: list[AuditAnchor] = []

    def append(self, anchor: AuditAnchor) -> None:
        _check_extension(self._anchors, anchor)
        self._anchors.append(anchor)

    def anchors(self) -> list[AuditAnchor]:
        return list(self._anchors)


class FileAnchorStore:
    """Append-only JSON-lines anchor store in a file the kernel never opens.

    Appends are extension-checked and fsynced; there is deliberately no
    update, delete, or rewrite operation.  Reads re-parse the file and
    return detached copies.  Malformed content raises instead of being
    silently skipped, so a damaged witness fails closed downstream.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    def append(self, anchor: AuditAnchor) -> None:
        _check_extension(self.anchors(), anchor)
        line = _canonical(asdict(anchor)).decode()
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def anchors(self) -> list[AuditAnchor]:
        if not self._path.exists():
            return []
        result: list[AuditAnchor] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                result.append(AuditAnchor(**json.loads(line)))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("anchor store content is malformed") from exc
        return result


def _trusted_now(clock: Callable[[], int]) -> int:
    try:
        value = clock()
    except Exception as exc:
        raise ValueError("anchor_clock_invalid") from exc
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("anchor_clock_invalid")
    return value


def anchor_records(
    records: Sequence[dict[str, Any]],
    store: AnchorStore,
    *,
    clock: Callable[[], int] | None = None,
    signer: AnchorSigner | None = None,
) -> AuditAnchor:
    """Witness the current head of ``records`` into ``store``.

    Reads only a snapshot of the presented records; appends nothing to the
    audit trail and mutates no kernel state.
    """

    snapshot = list(records)
    for record in snapshot:
        if not isinstance(record, dict) or not isinstance(record.get("hash"), str):
            raise ValueError("audit records are malformed")
    existing = store.anchors()
    unsigned = AuditAnchor(
        sequence=len(existing),
        record_count=len(snapshot),
        head_hash=snapshot[-1]["hash"] if snapshot else GENESIS_HASH,
        previous_anchor_hash=existing[-1].anchor_hash if existing else GENESIS_HASH,
        timestamp_ns=_trusted_now(clock or time.time_ns),
    )
    if signer is not None:
        from dataclasses import replace

        unsigned = replace(unsigned, signature=signer.sign(unsigned.signing_bytes()))
    store.append(unsigned)
    return unsigned


def anchor_state(
    state: object,
    store: AnchorStore,
    *,
    clock: Callable[[], int] | None = None,
    signer: AnchorSigner | None = None,
) -> AuditAnchor:
    """Witness the audit head of a kernel state backend (``state.audit``)."""

    return anchor_records(list(state.audit), store, clock=clock, signer=signer)


def _chain_valid(records: Sequence[dict[str, Any]]) -> bool:
    previous = GENESIS_HASH
    for record in records:
        body = {key: value for key, value in record.items() if key != "hash"}
        if body.get("previous_hash") != previous:
            return False
        if not hmac.compare_digest(str(record.get("hash")), sha256(_canonical(body)).hexdigest()):
            return False
        previous = str(record["hash"])
    return True


def verify_anchored_audit(
    records: Sequence[dict[str, Any]],
    anchors: Sequence[AuditAnchor],
    *,
    verifier: AnchorVerifier | None = None,
) -> AnchorVerification:
    """Fail closed unless ``anchors`` are intact and pin exact trail prefixes.

    Checks, in order: the anchor history is non-empty and internally chained
    with gapless sequences; anchor signatures verify when present (and a
    verifier is required whenever any anchor is signed); anchor counts never
    regress; the presented audit chain is internally valid; and every
    anchor's (record_count, head_hash) still matches the presented trail, so
    tail truncation and delete-and-rehash both fail even though the trail's
    own chain verification accepts them.
    """

    trail = list(records)
    history = list(anchors)
    total = len(trail)

    def fail(reason: str, checked: int = 0, anchored: int = 0) -> AnchorVerification:
        return AnchorVerification(False, reason, anchored, total, checked)

    if not history:
        return fail("anchor_history_empty")
    try:
        for index, anchor in enumerate(history):
            if not isinstance(anchor, AuditAnchor):
                return fail("anchor_malformed", index)
            if anchor.sequence != index:
                return fail("anchor_sequence_gap", index)
            expected_previous = history[index - 1].anchor_hash if index else GENESIS_HASH
            if anchor.previous_anchor_hash != expected_previous:
                return fail("anchor_chain_mismatch", index)
            if index:
                prior = history[index - 1]
                if anchor.record_count < prior.record_count:
                    return fail("anchor_count_regression", index)
                if anchor.record_count == prior.record_count and anchor.head_hash != prior.head_hash:
                    return fail("anchor_head_conflict", index)
            if anchor.signature:
                if verifier is None:
                    return fail("anchor_verifier_unavailable", index)
                try:
                    valid = verifier.verify(anchor.signing_bytes(), anchor.signature)
                except Exception:
                    return fail("anchor_signature_invalid", index)
                if valid is not True:
                    return fail("anchor_signature_invalid", index)
            elif verifier is not None:
                return fail("anchor_signature_missing", index)
    except Exception:
        return fail("anchor_malformed")
    try:
        if not _chain_valid(trail):
            return fail("audit_chain_invalid", len(history))
    except Exception:
        return fail("audit_records_malformed", len(history))
    for index, anchor in enumerate(history):
        if anchor.record_count > total:
            return fail("anchor_beyond_trail", index + 1, history[index - 1].record_count if index else 0)
        if anchor.record_count == 0:
            continue
        if trail[anchor.record_count - 1].get("hash") != anchor.head_hash:
            return fail("anchor_prefix_mismatch", index + 1, history[index - 1].record_count if index else 0)
    return AnchorVerification(True, "anchored_prefix_verified", history[-1].record_count, total, len(history))

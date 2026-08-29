"""Governed existing-file replacement for Pulpo Local Lab V0.

The editor binds one existing UTF-8 file's current SHA-256 digest to one exact
replacement payload. A Pulpo permit must match that edit object before any
write. The executor's return value is only a claim; a fresh read observes the
result and reconciliation compares the authorized replacement to observed
bytes.

This is a bounded local development surface, not an arbitrary shell, authority
source, router, or second ledger.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any, Callable

from .kernel import GovernanceKernel, Intent


_HASH = re.compile(r"^[0-9a-f]{64}$")
_MAX_EDIT_BYTES = 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


class LocalEditViolation(RuntimeError):
    """The bounded local-edit contract failed closed."""


@dataclass(frozen=True)
class LocalTextEdit:
    relative_path: str
    expected_content_hash: str
    replacement_content: str
    schema: str = "pulpo.local-text-edit.v0"

    def __post_init__(self) -> None:
        path = Path(self.relative_path)
        if self.schema != "pulpo.local-text-edit.v0":
            raise LocalEditViolation("unsupported_edit_schema")
        if not self.relative_path or self.relative_path in {".", ".."}:
            raise LocalEditViolation("edit_path_required")
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise LocalEditViolation("edit_path_invalid")
        if not _HASH.fullmatch(self.expected_content_hash):
            raise LocalEditViolation("edit_expected_hash_invalid")
        if not isinstance(self.replacement_content, str):
            raise LocalEditViolation("edit_replacement_text_required")
        if len(self.replacement_content.encode("utf-8")) > _MAX_EDIT_BYTES:
            raise LocalEditViolation("edit_replacement_too_large")

    @property
    def replacement_bytes(self) -> bytes:
        return self.replacement_content.encode("utf-8")

    @property
    def replacement_content_hash(self) -> str:
        return sha256(self.replacement_bytes).hexdigest()

    @property
    def edit_hash(self) -> str:
        return _hash(
            {
                "schema": self.schema,
                "relative_path": self.relative_path,
                "expected_content_hash": self.expected_content_hash,
                "replacement_content_hash": self.replacement_content_hash,
                "replacement_bytes": len(self.replacement_bytes),
                "existing_file_only": True,
                "symlinks": False,
            }
        )


def local_edit_intent(
    edit: LocalTextEdit,
    *,
    principal: str = "human:local-lab",
    session_id: str = "local-lab-edit",
) -> Intent:
    return Intent(
        principal=principal,
        action="edit_local_file",
        resource=f"local-edit:{edit.edit_hash}",
        cost=0,
        session_id=session_id,
    )


@dataclass(frozen=True)
class LocalEditExecution:
    edit_hash: str
    intent_hash: str
    relative_path: str
    expected_content_hash: str
    claimed_content_hash: str
    bytes_written: int
    completed_at_ns: int


@dataclass(frozen=True)
class LocalEditObservation:
    edit_hash: str
    relative_path: str
    exists: bool
    observed_content_hash: str | None
    observed_bytes: int | None
    observed_at_ns: int
    authority_effect: str = "none"


@dataclass(frozen=True)
class LocalEditReconciliation:
    outcome: str
    reason: str
    edit_hash: str
    intent_hash: str
    expected_content_hash: str
    observed_content_hash: str | None
    expected_bytes: int
    observed_bytes: int | None
    authority_effect: str = "none"

    @property
    def verified(self) -> bool:
        return self.outcome == "verified"


def _target(root: str | Path, edit: LocalTextEdit) -> tuple[Path, Path]:
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise LocalEditViolation("edit_root_invalid")

    current = root_path
    for part in Path(edit.relative_path).parts:
        current = current / part
        if current.is_symlink():
            raise LocalEditViolation("edit_symlink_forbidden")

    target = (root_path / edit.relative_path).resolve(strict=False)
    try:
        target.relative_to(root_path)
    except ValueError as exc:
        raise LocalEditViolation("edit_path_escape") from exc
    if target.parent == target:
        raise LocalEditViolation("edit_path_invalid")
    return root_path, target


def _read_existing_utf8(target: Path) -> bytes:
    if not target.exists():
        raise LocalEditViolation("edit_target_missing")
    if target.is_symlink() or not target.is_file():
        raise LocalEditViolation("edit_target_not_regular_file")
    try:
        payload = target.read_bytes()
    except OSError as exc:
        raise LocalEditViolation("edit_target_read_failed") from exc
    if len(payload) > _MAX_EDIT_BYTES:
        raise LocalEditViolation("edit_target_too_large")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalEditViolation("edit_target_not_utf8_text") from exc
    return payload


class LocalTextEditExecutor:
    """Consume one exact Pulpo permit before replacing one existing text file."""

    def __init__(self, *, clock: Callable[[], int] = time.time_ns) -> None:
        self._clock = clock

    def execute(
        self,
        kernel: GovernanceKernel,
        edit: LocalTextEdit,
        permit: str,
        *,
        root: str | Path,
    ) -> LocalEditExecution:
        root_path, target = _target(root, edit)

        # Optimistic concurrency check before permit consumption. A stale edit
        # never spends its permit and never overwrites newer work.
        before = _read_existing_utf8(target)
        before_hash = sha256(before).hexdigest()
        if before_hash != edit.expected_content_hash:
            raise LocalEditViolation("edit_stale_expected_hash")

        intent = local_edit_intent(edit)
        if not kernel.consume(permit, intent):
            raise LocalEditViolation("permit_rejected")

        # Re-check after permit consumption so a detected concurrent change fails
        # closed rather than being overwritten. No automatic retry is attempted.
        current = _read_existing_utf8(target)
        if sha256(current).hexdigest() != edit.expected_content_hash:
            raise LocalEditViolation("edit_changed_after_permit_consumed")

        payload = edit.replacement_bytes
        temp_name = f".{target.name}.pulpo-edit-{secrets.token_hex(8)}.tmp"
        temp = root_path / target.relative_to(root_path).parent / temp_name
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temp, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = None
                written = handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if written != len(payload):
                raise LocalEditViolation("edit_partial_write_after_permit_consumed")
            os.replace(temp, target)
        except LocalEditViolation:
            raise
        except OSError as exc:
            raise LocalEditViolation("edit_write_failed_after_permit_consumed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                if temp.exists():
                    temp.unlink()
            except OSError:
                pass

        completed_at_ns = self._clock()
        if isinstance(completed_at_ns, bool) or not isinstance(completed_at_ns, int) or completed_at_ns <= 0:
            raise LocalEditViolation("edit_clock_invalid_after_permit_consumed")

        return LocalEditExecution(
            edit_hash=edit.edit_hash,
            intent_hash=kernel.intent_hash(intent),
            relative_path=edit.relative_path,
            expected_content_hash=edit.expected_content_hash,
            claimed_content_hash=edit.replacement_content_hash,
            bytes_written=len(payload),
            completed_at_ns=completed_at_ns,
        )


def observe_local_edit(
    edit: LocalTextEdit,
    *,
    root: str | Path,
    clock: Callable[[], int] = time.time_ns,
) -> LocalEditObservation:
    _, target = _target(root, edit)
    observed_at_ns = clock()
    if isinstance(observed_at_ns, bool) or not isinstance(observed_at_ns, int) or observed_at_ns <= 0:
        raise LocalEditViolation("edit_observation_clock_invalid")
    if not target.exists() or target.is_symlink() or not target.is_file():
        return LocalEditObservation(edit.edit_hash, edit.relative_path, False, None, None, observed_at_ns)
    try:
        payload = target.read_bytes()
    except OSError as exc:
        raise LocalEditViolation("edit_observation_failed") from exc
    return LocalEditObservation(
        edit.edit_hash,
        edit.relative_path,
        True,
        sha256(payload).hexdigest(),
        len(payload),
        observed_at_ns,
    )


def reconcile_local_edit(
    kernel: GovernanceKernel,
    edit: LocalTextEdit,
    execution: LocalEditExecution,
    observation: LocalEditObservation,
) -> LocalEditReconciliation:
    intent = local_edit_intent(edit)
    expected_intent_hash = kernel.intent_hash(intent)
    expected_bytes = len(edit.replacement_bytes)
    reason = "edit_verified"

    if execution.edit_hash != edit.edit_hash:
        reason = "execution_edit_mismatch"
    elif execution.intent_hash != expected_intent_hash:
        reason = "execution_intent_mismatch"
    elif execution.relative_path != edit.relative_path:
        reason = "execution_path_mismatch"
    elif execution.expected_content_hash != edit.expected_content_hash:
        reason = "execution_expected_hash_mismatch"
    elif execution.claimed_content_hash != edit.replacement_content_hash:
        reason = "execution_replacement_claim_mismatch"
    elif execution.bytes_written != expected_bytes:
        reason = "execution_byte_count_mismatch"
    elif observation.edit_hash != edit.edit_hash:
        reason = "observation_edit_mismatch"
    elif observation.relative_path != edit.relative_path:
        reason = "observation_path_mismatch"
    elif not observation.exists:
        reason = "edit_not_observed"
    elif observation.observed_content_hash != edit.replacement_content_hash:
        reason = "observed_content_mismatch"
    elif observation.observed_bytes != expected_bytes:
        reason = "observed_byte_count_mismatch"

    return LocalEditReconciliation(
        outcome="verified" if reason == "edit_verified" else "mismatch",
        reason=reason,
        edit_hash=edit.edit_hash,
        intent_hash=expected_intent_hash,
        expected_content_hash=edit.replacement_content_hash,
        observed_content_hash=observation.observed_content_hash,
        expected_bytes=expected_bytes,
        observed_bytes=observation.observed_bytes,
    )


def build_local_edit_proof(
    kernel: GovernanceKernel,
    edit: LocalTextEdit,
    execution: LocalEditExecution,
    observation: LocalEditObservation,
    reconciliation: LocalEditReconciliation,
) -> dict[str, Any]:
    payload = {
        "schema": "pulpo.local-edit-proof.v0",
        "edit": {
            "schema": edit.schema,
            "relative_path": edit.relative_path,
            "edit_hash": edit.edit_hash,
            "expected_content_hash": edit.expected_content_hash,
            "replacement_content_hash": edit.replacement_content_hash,
            "replacement_bytes": len(edit.replacement_bytes),
        },
        "execution": asdict(execution),
        "observation": asdict(observation),
        "reconciliation": asdict(reconciliation),
        "audit_valid": kernel.verify_audit(),
        "audit_tip": kernel.audit[-1]["hash"] if kernel.audit else None,
    }
    return {**payload, "bundle_hash": _hash(payload)}

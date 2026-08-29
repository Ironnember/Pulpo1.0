"""Bounded local consequence, observation, and reconciliation proof.

This module extends Pulpo's existing kernel/permit path with one deliberately
small execution surface: create one new hidden proof file at the supplied root.
It does not execute a shell, overwrite files, create directories, authenticate a
human, or create another authority/evidence ledger.

The executor's claim is not treated as proof of consequence. A separate read
path observes the file after execution and reconciliation compares the exact
authorized effect to that observation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Callable

from .kernel import GovernanceKernel, Intent


_EFFECT_ID = re.compile(r"^[0-9a-f]{16}$")
_MAX_CONTENT_BYTES = 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


class LocalEffectViolation(RuntimeError):
    """The bounded local-effect contract failed closed."""


@dataclass(frozen=True)
class LocalFileEffect:
    """Exact reversible proof consequence.

    The path is derived from ``effect_id`` so callers cannot supply arbitrary
    filesystem paths. The effect may create one root-level hidden text file and
    may never overwrite an existing path.
    """

    effect_id: str
    content: str
    schema: str = "pulpo.local-file-effect.v0"

    def __post_init__(self) -> None:
        if self.schema != "pulpo.local-file-effect.v0":
            raise LocalEffectViolation("unsupported_effect_schema")
        if not _EFFECT_ID.fullmatch(self.effect_id):
            raise LocalEffectViolation("effect_id_invalid")
        if not isinstance(self.content, str) or not self.content:
            raise LocalEffectViolation("effect_content_required")
        if len(self.content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            raise LocalEffectViolation("effect_content_too_large")

    @property
    def relative_path(self) -> str:
        return f".pulpo-effect-v0-{self.effect_id}.txt"

    @property
    def content_hash(self) -> str:
        return sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def effect_hash(self) -> str:
        return _hash(
            {
                "schema": self.schema,
                "effect_id": self.effect_id,
                "relative_path": self.relative_path,
                "content_hash": self.content_hash,
                "content_bytes": len(self.content.encode("utf-8")),
                "overwrite": False,
            }
        )


def local_file_intent(
    effect: LocalFileEffect,
    *,
    principal: str = "human:local-effect-demo",
    session_id: str = "local-effect-demo",
) -> Intent:
    """Bind the exact effect object to Pulpo's one canonical intent path."""

    return Intent(
        principal=principal,
        action="create_local_file",
        resource=f"local-effect:{effect.effect_hash}",
        cost=0,
        session_id=session_id,
    )


@dataclass(frozen=True)
class LocalFileExecution:
    """Executor-reported result. This is a claim until independently observed."""

    effect_hash: str
    intent_hash: str
    relative_path: str
    claimed_content_hash: str
    bytes_written: int
    completed_at_ns: int


@dataclass(frozen=True)
class LocalFileObservation:
    """Fresh read-path observation of the consequence."""

    effect_hash: str
    relative_path: str
    exists: bool
    observed_content_hash: str | None
    observed_bytes: int | None
    observed_at_ns: int
    authority_effect: str = "none"


@dataclass(frozen=True)
class LocalFileReconciliation:
    """Comparison of authorized effect, execution claim, and observed state."""

    outcome: str
    reason: str
    effect_hash: str
    intent_hash: str
    expected_content_hash: str
    observed_content_hash: str | None
    expected_bytes: int
    observed_bytes: int | None
    authority_effect: str = "none"

    @property
    def verified(self) -> bool:
        return self.outcome == "verified"


class LocalFileExecutor:
    """Consume exactly one Pulpo permit before creating exactly one proof file."""

    def __init__(self, *, clock: Callable[[], int] = time.time_ns) -> None:
        self._clock = clock

    @staticmethod
    def _target(root: Path, effect: LocalFileEffect) -> Path:
        root = root.resolve()
        if not root.is_dir():
            raise LocalEffectViolation("effect_root_invalid")
        target = root / effect.relative_path
        if target.parent != root:
            raise LocalEffectViolation("effect_path_escape")
        return target

    def execute(
        self,
        kernel: GovernanceKernel,
        effect: LocalFileEffect,
        permit: str,
        *,
        root: str | Path,
    ) -> LocalFileExecution:
        target = self._target(Path(root), effect)
        if target.exists() or target.is_symlink():
            raise LocalEffectViolation("effect_target_exists")

        intent = local_file_intent(effect)
        if not kernel.consume(permit, intent):
            raise LocalEffectViolation("permit_rejected")

        payload = effect.content.encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor: int | None = None
        try:
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = None
                written = handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            # The permit has already been consumed. Do not retry automatically.
            raise LocalEffectViolation("effect_race_after_permit_consumed") from exc
        except OSError as exc:
            raise LocalEffectViolation("effect_write_failed_after_permit_consumed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

        if written != len(payload):
            raise LocalEffectViolation("effect_partial_write_after_permit_consumed")

        completed_at_ns = self._clock()
        if isinstance(completed_at_ns, bool) or not isinstance(completed_at_ns, int) or completed_at_ns <= 0:
            raise LocalEffectViolation("effect_clock_invalid_after_permit_consumed")

        return LocalFileExecution(
            effect_hash=effect.effect_hash,
            intent_hash=kernel.intent_hash(intent),
            relative_path=effect.relative_path,
            claimed_content_hash=effect.content_hash,
            bytes_written=len(payload),
            completed_at_ns=completed_at_ns,
        )


def observe_local_file(
    effect: LocalFileEffect,
    *,
    root: str | Path,
    clock: Callable[[], int] = time.time_ns,
) -> LocalFileObservation:
    """Observe the consequence through a fresh read path, not executor state."""

    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise LocalEffectViolation("effect_root_invalid")
    target = root_path / effect.relative_path
    if target.parent != root_path:
        raise LocalEffectViolation("effect_path_escape")

    observed_at_ns = clock()
    if isinstance(observed_at_ns, bool) or not isinstance(observed_at_ns, int) or observed_at_ns <= 0:
        raise LocalEffectViolation("observation_clock_invalid")

    if not target.exists() or target.is_symlink() or not target.is_file():
        return LocalFileObservation(
            effect.effect_hash,
            effect.relative_path,
            False,
            None,
            None,
            observed_at_ns,
        )

    try:
        payload = target.read_bytes()
    except OSError as exc:
        raise LocalEffectViolation("effect_observation_failed") from exc
    return LocalFileObservation(
        effect.effect_hash,
        effect.relative_path,
        True,
        sha256(payload).hexdigest(),
        len(payload),
        observed_at_ns,
    )


def reconcile_local_file(
    kernel: GovernanceKernel,
    effect: LocalFileEffect,
    execution: LocalFileExecution,
    observation: LocalFileObservation,
) -> LocalFileReconciliation:
    """Reconcile exact intent/effect bindings against fresh observed state."""

    intent = local_file_intent(effect)
    expected_intent_hash = kernel.intent_hash(intent)
    expected_bytes = len(effect.content.encode("utf-8"))

    reason = "effect_verified"
    if execution.effect_hash != effect.effect_hash:
        reason = "execution_effect_mismatch"
    elif execution.intent_hash != expected_intent_hash:
        reason = "execution_intent_mismatch"
    elif execution.relative_path != effect.relative_path:
        reason = "execution_path_mismatch"
    elif execution.claimed_content_hash != effect.content_hash:
        reason = "execution_content_claim_mismatch"
    elif execution.bytes_written != expected_bytes:
        reason = "execution_byte_count_mismatch"
    elif observation.effect_hash != effect.effect_hash:
        reason = "observation_effect_mismatch"
    elif observation.relative_path != effect.relative_path:
        reason = "observation_path_mismatch"
    elif not observation.exists:
        reason = "effect_not_observed"
    elif observation.observed_content_hash != effect.content_hash:
        reason = "observed_content_mismatch"
    elif observation.observed_bytes != expected_bytes:
        reason = "observed_byte_count_mismatch"

    outcome = "verified" if reason == "effect_verified" else "mismatch"
    return LocalFileReconciliation(
        outcome=outcome,
        reason=reason,
        effect_hash=effect.effect_hash,
        intent_hash=expected_intent_hash,
        expected_content_hash=effect.content_hash,
        observed_content_hash=observation.observed_content_hash,
        expected_bytes=expected_bytes,
        observed_bytes=observation.observed_bytes,
    )


def build_local_effect_proof(
    kernel: GovernanceKernel,
    effect: LocalFileEffect,
    execution: LocalFileExecution,
    observation: LocalFileObservation,
    reconciliation: LocalFileReconciliation,
) -> dict[str, Any]:
    """Build a portable projection; this is not a second ledger or authority source."""

    payload = {
        "schema": "pulpo.local-effect-proof.v0",
        "effect": {
            "schema": effect.schema,
            "effect_id": effect.effect_id,
            "relative_path": effect.relative_path,
            "effect_hash": effect.effect_hash,
            "content_hash": effect.content_hash,
            "content_bytes": len(effect.content.encode("utf-8")),
            "overwrite": False,
        },
        "execution": asdict(execution),
        "observation": asdict(observation),
        "reconciliation": asdict(reconciliation),
        "audit_valid": kernel.verify_audit(),
        "audit_tip": kernel.audit[-1]["hash"] if kernel.audit else None,
    }
    return {**payload, "bundle_hash": _hash(payload)}

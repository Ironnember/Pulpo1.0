"""Completion evidence for Pulpo's existing durable LockedTarget seam.

This module does not create a task manager, authority source, policy engine, or
second evidence ledger. A locked target is already Pulpo's immutable durable
statement of one proposed consequence. This projection only answers whether
that exact target remains unresolved or has locally observed file-artifact
evidence recorded in the kernel's existing audit chain.

V0 proves objective persistence and exact evidence binding for tangible file
artifacts. It does not prove semantic quality of an artifact, independent
observer trust, or generic non-file completion. Those remain separate evidence
and reconciliation problems.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import stat
from typing import Literal

from .kernel import GovernanceKernel, StateIntegrityError


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_sha256(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{field}_invalid")


@dataclass(frozen=True)
class ArtifactCompletionEvidence:
    target_id: str
    version: int
    target_hash: str
    intent_hash: str
    artifact_path: str
    artifact_sha256: str
    size_bytes: int
    observed_at_ns: int
    schema: str = "pulpo.target-artifact-completion.v0"

    def __post_init__(self) -> None:
        if not self.target_id or self.version <= 0:
            raise ValueError("target_identity_invalid")
        _require_sha256(self.target_hash, "target_hash")
        _require_sha256(self.intent_hash, "intent_hash")
        _require_sha256(self.artifact_sha256, "artifact_sha256")
        if not self.artifact_path or not Path(self.artifact_path).is_absolute():
            raise ValueError("artifact_path_invalid")
        if self.size_bytes <= 0:
            raise ValueError("artifact_empty")
        if self.observed_at_ns <= 0:
            raise ValueError("artifact_observation_time_invalid")
        if self.schema != "pulpo.target-artifact-completion.v0":
            raise ValueError("unsupported_completion_schema")

    @property
    def evidence_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class TargetObligationStatus:
    state: Literal["unresolved", "completed", "deny"]
    reason: str
    target_id: str
    version: int
    target_hash: str
    completion: ArtifactCompletionEvidence | None = None


class GovernedTargetReconciliation:
    """Project completion state from the kernel-owned target and audit chain."""

    COMPLETION_EVENT = "target_completed"

    def __init__(self, kernel: GovernanceKernel) -> None:
        self.kernel = kernel

    def _trusted_now(self) -> int:
        now_ns = self.kernel._trusted_now()
        if now_ns is None:
            raise RuntimeError("target_completion_clock_invalid")
        return now_ns

    def _exact_target(self, target_id: str, expected_target_hash: str, version: int):
        if not target_id or version <= 0 or not isinstance(expected_target_hash, str):
            return None, "target_reference_invalid"
        try:
            _require_sha256(expected_target_hash, "target_hash")
        except ValueError:
            return None, "target_reference_invalid"
        target = self.kernel.get_locked_target(target_id, version=version)
        if target is None:
            return None, "target_not_locked"
        if not hmac.compare_digest(target.target_hash, expected_target_hash):
            return None, "target_hash_mismatch"
        return target, "target_exact_match"

    @staticmethod
    def _completion_from_record(record: dict[str, object]) -> ArtifactCompletionEvidence:
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise StateIntegrityError("target completion record payload is invalid")
        if payload.get("authority_effect") != "none":
            raise StateIntegrityError("target completion cannot carry authority")
        raw = payload.get("completion")
        if not isinstance(raw, dict):
            raise StateIntegrityError("target completion evidence is missing")
        try:
            completion = ArtifactCompletionEvidence(**raw)
        except (TypeError, ValueError) as exc:
            raise StateIntegrityError("target completion evidence is invalid") from exc
        stored_hash = payload.get("completion_hash")
        if not isinstance(stored_hash, str) or not hmac.compare_digest(completion.evidence_hash, stored_hash):
            raise StateIntegrityError("target completion evidence hash is invalid")
        return completion

    def status(
        self,
        target_id: str,
        expected_target_hash: str,
        *,
        version: int = 1,
    ) -> TargetObligationStatus:
        target, reason = self._exact_target(target_id, expected_target_hash, version)
        if target is None:
            return TargetObligationStatus("deny", reason, target_id, version, expected_target_hash)

        expected_intent_hash = self.kernel.intent_hash(target.intent)
        for record in reversed(self.kernel.audit):
            if record.get("event") != self.COMPLETION_EVENT:
                continue
            completion = self._completion_from_record(record)
            if completion.target_id != target_id or completion.version != version:
                continue
            if not hmac.compare_digest(completion.target_hash, target.target_hash):
                raise StateIntegrityError("target completion target hash is invalid")
            if not hmac.compare_digest(completion.intent_hash, expected_intent_hash):
                raise StateIntegrityError("target completion intent hash is invalid")
            return TargetObligationStatus(
                "completed",
                "completion_evidence_recorded",
                target_id,
                version,
                target.target_hash,
                completion,
            )

        return TargetObligationStatus(
            "unresolved",
            "completion_evidence_missing",
            target_id,
            version,
            target.target_hash,
        )

    @staticmethod
    def _observe_file(path: str | Path) -> tuple[str, str, int]:
        """Hash one stable regular file through a descriptor-bound observation.

        The resolved path, descriptor identity, byte count, size, and metadata
        must remain stable for the whole observation. A writer racing the read
        therefore cannot produce completion evidence for a mixed or replaced
        artifact snapshot.
        """

        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("artifact_not_found") from exc

        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(resolved, flags)
        except FileNotFoundError as exc:
            raise ValueError("artifact_changed_during_observation") from exc
        except OSError as exc:
            raise ValueError("artifact_unreadable") from exc

        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("artifact_not_file")
            if before.st_size <= 0:
                raise ValueError("artifact_empty")

            digest = sha256()
            bytes_read = 0
            try:
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    digest.update(chunk)
                after = os.fstat(descriptor)
                path_after = os.stat(resolved, follow_symlinks=False)
            except OSError as exc:
                raise ValueError("artifact_changed_during_observation") from exc

            stable_descriptor = (
                before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_size == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns
            )
            stable_path = (
                after.st_dev == path_after.st_dev
                and after.st_ino == path_after.st_ino
                and after.st_size == path_after.st_size
            )
            if bytes_read != before.st_size or not stable_descriptor or not stable_path:
                raise ValueError("artifact_changed_during_observation")

            return str(resolved), digest.hexdigest(), bytes_read
        finally:
            os.close(descriptor)

    def complete_file(
        self,
        target_id: str,
        expected_target_hash: str,
        artifact_path: str | Path,
        *,
        version: int = 1,
    ) -> ArtifactCompletionEvidence:
        target, reason = self._exact_target(target_id, expected_target_hash, version)
        if target is None:
            raise ValueError(reason)

        resolved_path, artifact_sha256, size_bytes = self._observe_file(artifact_path)
        now_ns = self._trusted_now()
        if now_ns < target.created_at_ns:
            raise RuntimeError("artifact_observed_before_target")

        completion = ArtifactCompletionEvidence(
            target_id=target.target_id,
            version=target.version,
            target_hash=target.target_hash,
            intent_hash=self.kernel.intent_hash(target.intent),
            artifact_path=resolved_path,
            artifact_sha256=artifact_sha256,
            size_bytes=size_bytes,
            observed_at_ns=now_ns,
        )

        current = self.status(target_id, expected_target_hash, version=version)
        if current.state == "completed":
            assert current.completion is not None
            existing = current.completion
            same_artifact = (
                hmac.compare_digest(existing.artifact_sha256, completion.artifact_sha256)
                and existing.artifact_path == completion.artifact_path
                and existing.size_bytes == completion.size_bytes
            )
            if same_artifact:
                return existing
            raise ValueError("target_completion_immutable")

        self.kernel._state.append(
            self.COMPLETION_EVENT,
            {
                "target_id": target.target_id,
                "version": target.version,
                "target_hash": target.target_hash,
                "intent_hash": self.kernel.intent_hash(target.intent),
                "completion": asdict(completion),
                "completion_hash": completion.evidence_hash,
                "authority_effect": "none",
            },
            now_ns,
        )
        return completion

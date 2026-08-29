from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Iterable, Literal, Sequence


SurfaceRole = Literal["protected", "writable", "evidence"]
ReconciliationStatus = Literal["verified", "mismatch", "uncertain"]
DeltaClassification = Literal[
    "authorized_runtime_effect",
    "canonical_pulpo_evidence",
    "protected_surface_delta",
    "undeclared_effect",
]


class EffectReconciliationError(ValueError):
    """Raised when an effect envelope or observation is structurally invalid."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hash_json(value: object) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def _normalize_absolute(path: str) -> str:
    if not path:
        raise EffectReconciliationError("path_required")
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        raise EffectReconciliationError("absolute_path_required")
    return os.path.realpath(os.path.normpath(expanded))


def _normalize_relative(path: str) -> str:
    if not path:
        raise EffectReconciliationError("relative_path_required")
    if os.path.isabs(path):
        raise EffectReconciliationError("relative_path_must_not_be_absolute")
    normalized = os.path.normpath(path).replace(os.sep, "/")
    if normalized in (".", ""):
        raise EffectReconciliationError("surface_root_cannot_be_excluded")
    if normalized == ".." or normalized.startswith("../"):
        raise EffectReconciliationError("relative_path_escape")
    return normalized


def _under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _relative_to_root(path: str, root: str) -> str | None:
    if not _under(path, root):
        return None
    relative = os.path.relpath(path, root).replace(os.sep, "/")
    return "." if relative == "." else relative


def _excluded_by(surface: "SurfaceSpec", path: str) -> bool:
    relative = _relative_to_root(path, surface.root)
    if relative is None or relative == ".":
        return False
    return _is_excluded(relative, surface.exclude)


@dataclass(frozen=True)
class SurfaceSpec:
    root: str
    role: SurfaceRole
    exclude: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.role not in ("protected", "writable", "evidence"):
            raise EffectReconciliationError("invalid_surface_role")
        object.__setattr__(self, "root", _normalize_absolute(self.root))
        object.__setattr__(self, "exclude", tuple(sorted({_normalize_relative(p) for p in self.exclude})))


@dataclass(frozen=True)
class EffectEnvelope:
    permit_id: str
    executable_path: str
    executable_sha256: str
    argv: tuple[str, ...]
    workdir: str
    source_sha: str
    profile: str
    expires_at_ns: int
    surfaces: tuple[SurfaceSpec, ...]
    schema: str = "pulpo.effect-envelope.v1"

    def __post_init__(self) -> None:
        if not self.permit_id:
            raise EffectReconciliationError("permit_id_required")
        object.__setattr__(self, "executable_path", _normalize_absolute(self.executable_path))
        if len(self.executable_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.executable_sha256):
            raise EffectReconciliationError("invalid_executable_sha256")
        if not self.argv or any(not isinstance(arg, str) for arg in self.argv):
            raise EffectReconciliationError("argv_required")
        object.__setattr__(self, "workdir", _normalize_absolute(self.workdir))
        if not self.source_sha:
            raise EffectReconciliationError("source_sha_required")
        if not self.profile:
            raise EffectReconciliationError("profile_required")
        if self.expires_at_ns <= 0:
            raise EffectReconciliationError("invalid_expiry")
        if not self.surfaces:
            raise EffectReconciliationError("surface_required")

        roots = [surface.root for surface in self.surfaces]
        if len(set(roots)) != len(roots):
            raise EffectReconciliationError("duplicate_surface_root")
        for index, left in enumerate(self.surfaces):
            for right in self.surfaces[index + 1 :]:
                if _under(right.root, left.root):
                    if not _excluded_by(left, right.root):
                        raise EffectReconciliationError("ambiguous_overlapping_surface_roots")
                elif _under(left.root, right.root):
                    if not _excluded_by(right, left.root):
                        raise EffectReconciliationError("ambiguous_overlapping_surface_roots")

    @property
    def envelope_hash(self) -> str:
        payload = {
            "schema": self.schema,
            "permit_id": self.permit_id,
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
            "argv": list(self.argv),
            "workdir": self.workdir,
            "source_sha": self.source_sha,
            "profile": self.profile,
            "expires_at_ns": self.expires_at_ns,
            "surfaces": [
                {"root": surface.root, "role": surface.role, "exclude": list(surface.exclude)}
                for surface in sorted(self.surfaces, key=lambda item: item.root)
            ],
        }
        return _hash_json(payload)


@dataclass(frozen=True)
class ExecutionIdentity:
    executable_path: str
    executable_sha256: str
    argv: tuple[str, ...]
    workdir: str
    source_sha: str
    profile: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "executable_path", _normalize_absolute(self.executable_path))
        object.__setattr__(self, "workdir", _normalize_absolute(self.workdir))


@dataclass(frozen=True)
class SnapshotEntry:
    relative_path: str
    kind: Literal["file", "directory", "symlink", "other"]
    mode: int
    size: int
    uid: int
    gid: int
    mtime_ns: int
    ctime_ns: int
    content_sha256: str | None = None
    link_target: str | None = None

    @property
    def fingerprint(self) -> str:
        return _hash_json(asdict(self))


@dataclass(frozen=True)
class TreeSnapshot:
    root: str
    role: SurfaceRole
    exclude: tuple[str, ...]
    exists: bool
    entries: tuple[SnapshotEntry, ...]
    digest: str


@dataclass(frozen=True)
class SurfaceObservation:
    before: TreeSnapshot
    after: TreeSnapshot


@dataclass(frozen=True)
class EffectDelta:
    path: str
    change: Literal["created", "deleted", "modified", "observed"]
    classification: DeltaClassification
    before_fingerprint: str | None = None
    after_fingerprint: str | None = None


@dataclass(frozen=True)
class EffectReconciliation:
    status: ReconciliationStatus
    reason: str
    effect_envelope_hash: str
    deltas: tuple[EffectDelta, ...]
    protected_surface_delta: int
    unauthorized_effects: int
    uncertain_effects: int
    authorized_runtime_effects: int
    canonical_pulpo_evidence: int

    @property
    def reconciliation_hash(self) -> str:
        return _hash_json(
            {
                "status": self.status,
                "reason": self.reason,
                "effect_envelope_hash": self.effect_envelope_hash,
                "deltas": [asdict(delta) for delta in self.deltas],
                "protected_surface_delta": self.protected_surface_delta,
                "unauthorized_effects": self.unauthorized_effects,
                "uncertain_effects": self.uncertain_effects,
                "authorized_runtime_effects": self.authorized_runtime_effects,
                "canonical_pulpo_evidence": self.canonical_pulpo_evidence,
            }
        )


def _is_excluded(relative_path: str, exclude: Sequence[str]) -> bool:
    if relative_path == ".":
        return False
    for item in exclude:
        if relative_path == item or relative_path.startswith(item + "/"):
            return True
    return False


def _entry_from_lstat(path: Path, relative_path: str) -> SnapshotEntry:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    common = dict(
        relative_path=relative_path,
        mode=mode,
        size=info.st_size,
        uid=info.st_uid,
        gid=info.st_gid,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )
    if stat.S_ISREG(info.st_mode):
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return SnapshotEntry(kind="file", content_sha256=digest.hexdigest(), **common)
    if stat.S_ISDIR(info.st_mode):
        return SnapshotEntry(kind="directory", **common)
    if stat.S_ISLNK(info.st_mode):
        return SnapshotEntry(kind="symlink", link_target=os.readlink(path), **common)
    return SnapshotEntry(kind="other", **common)


def capture_surface(surface: SurfaceSpec) -> TreeSnapshot:
    root = Path(surface.root)
    if not root.exists() and not root.is_symlink():
        payload = {
            "root": surface.root,
            "role": surface.role,
            "exclude": list(surface.exclude),
            "exists": False,
            "entries": [],
        }
        return TreeSnapshot(
            root=surface.root,
            role=surface.role,
            exclude=surface.exclude,
            exists=False,
            entries=(),
            digest=_hash_json(payload),
        )

    entries: list[SnapshotEntry] = []

    def walk(path: Path, relative_path: str) -> None:
        if _is_excluded(relative_path, surface.exclude):
            return
        entry = _entry_from_lstat(path, relative_path)
        entries.append(entry)
        if entry.kind != "directory":
            return
        children = sorted(path.iterdir(), key=lambda child: child.name)
        for child in children:
            child_relative = child.name if relative_path == "." else f"{relative_path}/{child.name}"
            walk(child, child_relative)

    try:
        walk(root, ".")
    except OSError as exc:
        raise EffectReconciliationError(f"snapshot_failed:{surface.root}:{exc.__class__.__name__}") from exc

    frozen_entries = tuple(sorted(entries, key=lambda item: item.relative_path))
    payload = {
        "root": surface.root,
        "role": surface.role,
        "exclude": list(surface.exclude),
        "exists": True,
        "entries": [asdict(entry) for entry in frozen_entries],
    }
    return TreeSnapshot(
        root=surface.root,
        role=surface.role,
        exclude=surface.exclude,
        exists=True,
        entries=frozen_entries,
        digest=_hash_json(payload),
    )


def capture_envelope_surfaces(envelope: EffectEnvelope) -> tuple[TreeSnapshot, ...]:
    return tuple(capture_surface(surface) for surface in envelope.surfaces)


def _diff(before: TreeSnapshot, after: TreeSnapshot) -> tuple[tuple[str, str, str | None, str | None], ...]:
    if before.root != after.root or before.role != after.role or before.exclude != after.exclude:
        raise EffectReconciliationError("snapshot_surface_mismatch")

    left = {entry.relative_path: entry for entry in before.entries}
    right = {entry.relative_path: entry for entry in after.entries}
    deltas: list[tuple[str, str, str | None, str | None]] = []
    for relative_path in sorted(set(left) | set(right)):
        old = left.get(relative_path)
        new = right.get(relative_path)
        if old is None:
            deltas.append((relative_path, "created", None, new.fingerprint if new else None))
        elif new is None:
            deltas.append((relative_path, "deleted", old.fingerprint, None))
        elif old != new:
            deltas.append((relative_path, "modified", old.fingerprint, new.fingerprint))
    if before.exists != after.exists and "." not in {delta[0] for delta in deltas}:
        deltas.append((".", "created" if after.exists else "deleted", None, None))
    return tuple(deltas)


def _identity_matches(envelope: EffectEnvelope, identity: ExecutionIdentity) -> bool:
    return (
        envelope.executable_path == identity.executable_path
        and envelope.executable_sha256 == identity.executable_sha256
        and envelope.argv == identity.argv
        and envelope.workdir == identity.workdir
        and envelope.source_sha == identity.source_sha
        and envelope.profile == identity.profile
    )


def _classify_role(role: SurfaceRole) -> DeltaClassification:
    if role == "writable":
        return "authorized_runtime_effect"
    if role == "evidence":
        return "canonical_pulpo_evidence"
    return "protected_surface_delta"


def _absolute_delta_path(root: str, relative_path: str) -> str:
    if relative_path == ".":
        return root
    return os.path.normpath(os.path.join(root, *relative_path.split("/")))


def _role_for_path(envelope: EffectEnvelope, path: str) -> SurfaceRole | None:
    normalized = _normalize_absolute(path)
    candidates = [surface for surface in envelope.surfaces if _under(normalized, surface.root)]
    if not candidates:
        return None
    candidates.sort(key=lambda surface: len(surface.root), reverse=True)
    return candidates[0].role


def reconcile_effects(
    envelope: EffectEnvelope,
    identity: ExecutionIdentity,
    before: Iterable[TreeSnapshot],
    after: Iterable[TreeSnapshot],
    *,
    execution_started_ns: int,
    observed_changed_paths: Iterable[str] = (),
    observation_complete: bool,
) -> EffectReconciliation:
    reasons: list[str] = []
    mismatch = False
    uncertain = False
    uncertainty_count = 0

    if not _identity_matches(envelope, identity):
        mismatch = True
        reasons.append("execution_identity_mismatch")
    if execution_started_ns > envelope.expires_at_ns:
        mismatch = True
        reasons.append("permit_expired_before_execution")

    before_snapshots = tuple(before)
    after_snapshots = tuple(after)
    before_by_root = {snapshot.root: snapshot for snapshot in before_snapshots}
    after_by_root = {snapshot.root: snapshot for snapshot in after_snapshots}
    expected = {surface.root: surface for surface in envelope.surfaces}

    if len(before_by_root) != len(before_snapshots) or len(after_by_root) != len(after_snapshots):
        uncertain = True
        uncertainty_count += 1
        reasons.append("duplicate_surface_observation")

    missing = sorted(set(expected) - set(before_by_root) | set(expected) - set(after_by_root))
    extra = sorted((set(before_by_root) | set(after_by_root)) - set(expected))
    if missing:
        uncertain = True
        uncertainty_count += len(missing)
        reasons.append("missing_surface_observation")
    if extra:
        mismatch = True
        reasons.append("undeclared_surface_observation")

    deltas: list[EffectDelta] = []
    known_paths: set[str] = set()

    for root, surface in sorted(expected.items()):
        left = before_by_root.get(root)
        right = after_by_root.get(root)
        if left is None or right is None:
            continue
        if left.role != surface.role or right.role != surface.role or left.exclude != surface.exclude or right.exclude != surface.exclude:
            mismatch = True
            reasons.append("surface_spec_mismatch")
            continue
        try:
            changes = _diff(left, right)
        except EffectReconciliationError:
            mismatch = True
            reasons.append("snapshot_surface_mismatch")
            continue
        classification = _classify_role(surface.role)
        for relative_path, change, old_fp, new_fp in changes:
            absolute = _absolute_delta_path(root, relative_path)
            known_paths.add(absolute)
            deltas.append(
                EffectDelta(
                    path=absolute,
                    change=change,  # type: ignore[arg-type]
                    classification=classification,
                    before_fingerprint=old_fp,
                    after_fingerprint=new_fp,
                )
            )
            if classification == "protected_surface_delta":
                mismatch = True

    for raw_path in observed_changed_paths:
        path = _normalize_absolute(raw_path)
        if path in known_paths:
            continue
        role = _role_for_path(envelope, path)
        classification: DeltaClassification
        if role is None:
            classification = "undeclared_effect"
            mismatch = True
        else:
            classification = _classify_role(role)
            if classification == "protected_surface_delta":
                mismatch = True
        deltas.append(EffectDelta(path=path, change="observed", classification=classification))

    if not observation_complete:
        uncertain = True
        uncertainty_count += 1
        reasons.append("observation_incomplete")

    protected_count = sum(delta.classification == "protected_surface_delta" for delta in deltas)
    undeclared_count = sum(delta.classification == "undeclared_effect" for delta in deltas)
    writable_count = sum(delta.classification == "authorized_runtime_effect" for delta in deltas)
    evidence_count = sum(delta.classification == "canonical_pulpo_evidence" for delta in deltas)

    if protected_count:
        mismatch = True
        reasons.append("protected_surface_changed")
    if undeclared_count:
        mismatch = True
        reasons.append("undeclared_effect_observed")

    if mismatch:
        status: ReconciliationStatus = "mismatch"
    elif uncertain:
        status = "uncertain"
    else:
        status = "verified"

    if not reasons:
        reason = "observed_effects_within_permit_envelope"
    else:
        reason = "+".join(dict.fromkeys(reasons))

    return EffectReconciliation(
        status=status,
        reason=reason,
        effect_envelope_hash=envelope.envelope_hash,
        deltas=tuple(sorted(deltas, key=lambda delta: (delta.path, delta.change, delta.classification))),
        protected_surface_delta=protected_count,
        unauthorized_effects=protected_count + undeclared_count,
        uncertain_effects=uncertainty_count,
        authorized_runtime_effects=writable_count,
        canonical_pulpo_evidence=evidence_count,
    )

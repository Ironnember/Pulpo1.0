"""Bounded read-only local workspace capability for Pulpo Local Lab V0.

This module exposes deterministic listing, UTF-8 text reads, and SHA-256 hashing
inside one operator-supplied workspace root. It does not mutate the filesystem,
follow symlinks, execute commands, create authority, or become a second router.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable


_MAX_READ_BYTES = 1024 * 1024
_MAX_LIST_ENTRIES = 1000


class WorkspaceViolation(RuntimeError):
    """The bounded workspace contract failed closed."""


@dataclass(frozen=True)
class WorkspaceEntry:
    relative_path: str
    kind: str
    size_bytes: int | None


@dataclass(frozen=True)
class WorkspaceRead:
    relative_path: str
    content: str
    content_hash: str
    size_bytes: int
    authority_effect: str = "none"


@dataclass(frozen=True)
class WorkspaceDigest:
    relative_path: str
    content_hash: str
    size_bytes: int
    authority_effect: str = "none"


class LocalWorkspace:
    """Read-only view over one fixed local directory tree."""

    def __init__(self, root: str | Path) -> None:
        resolved = Path(root).resolve()
        if not resolved.is_dir():
            raise WorkspaceViolation("workspace_root_invalid")
        self._root = resolved

    @property
    def root(self) -> Path:
        return self._root

    def _resolve(self, relative_path: str | Path) -> Path:
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise WorkspaceViolation("workspace_absolute_path_forbidden")
        if any(part in {"", ".", ".."} for part in candidate.parts):
            if str(candidate) not in {"", "."}:
                raise WorkspaceViolation("workspace_path_traversal")

        target = self._root if str(candidate) in {"", "."} else self._root / candidate
        try:
            target.relative_to(self._root)
        except ValueError as exc:
            raise WorkspaceViolation("workspace_path_escape") from exc

        # Reject any symlink component before resolving so links cannot escape the root.
        current = self._root
        for part in candidate.parts:
            if part in {"", "."}:
                continue
            current = current / part
            if current.is_symlink():
                raise WorkspaceViolation("workspace_symlink_forbidden")

        resolved = target.resolve(strict=False)
        try:
            resolved.relative_to(self._root)
        except ValueError as exc:
            raise WorkspaceViolation("workspace_path_escape") from exc
        return resolved

    def list(self, relative_path: str | Path = ".") -> tuple[WorkspaceEntry, ...]:
        directory = self._resolve(relative_path)
        if not directory.exists():
            raise WorkspaceViolation("workspace_path_missing")
        if not directory.is_dir():
            raise WorkspaceViolation("workspace_not_directory")

        entries: list[WorkspaceEntry] = []
        try:
            children: Iterable[Path] = sorted(directory.iterdir(), key=lambda item: item.name)
            for child in children:
                if len(entries) >= _MAX_LIST_ENTRIES:
                    raise WorkspaceViolation("workspace_listing_too_large")
                if child.is_symlink():
                    kind = "symlink"
                    size = None
                elif child.is_dir():
                    kind = "directory"
                    size = None
                elif child.is_file():
                    kind = "file"
                    size = child.stat().st_size
                else:
                    kind = "other"
                    size = None
                entries.append(
                    WorkspaceEntry(
                        relative_path=child.relative_to(self._root).as_posix(),
                        kind=kind,
                        size_bytes=size,
                    )
                )
        except OSError as exc:
            raise WorkspaceViolation("workspace_listing_failed") from exc
        return tuple(entries)

    def read_text(self, relative_path: str | Path) -> WorkspaceRead:
        target = self._resolve(relative_path)
        if not target.exists():
            raise WorkspaceViolation("workspace_path_missing")
        if not target.is_file():
            raise WorkspaceViolation("workspace_not_file")
        size = target.stat().st_size
        if size > _MAX_READ_BYTES:
            raise WorkspaceViolation("workspace_file_too_large")
        try:
            payload = target.read_bytes()
        except OSError as exc:
            raise WorkspaceViolation("workspace_read_failed") from exc
        try:
            content = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WorkspaceViolation("workspace_not_utf8_text") from exc
        return WorkspaceRead(
            relative_path=target.relative_to(self._root).as_posix(),
            content=content,
            content_hash=sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )

    def digest(self, relative_path: str | Path) -> WorkspaceDigest:
        target = self._resolve(relative_path)
        if not target.exists():
            raise WorkspaceViolation("workspace_path_missing")
        if not target.is_file():
            raise WorkspaceViolation("workspace_not_file")
        try:
            payload = target.read_bytes()
        except OSError as exc:
            raise WorkspaceViolation("workspace_read_failed") from exc
        return WorkspaceDigest(
            relative_path=target.relative_to(self._root).as_posix(),
            content_hash=sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )

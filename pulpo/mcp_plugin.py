"""Portable, capability-stripped Pulpo MCP plugin entrypoint.

The plugin consumes only a frozen ``MCPReadSnapshot`` exported by trusted
Pulpo. It never receives a kernel, orchestrator, authority client, executor,
policy object, trusted clock, canonical state backend, credential, permit, or
ledger reference.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from typing import Any, Sequence

from .mcp_boundary import MCPBoundaryError, MCPReadSnapshot, create_mcp_server


DEFAULT_SNAPSHOT_PATH = Path.home() / ".pulpo" / "mcp-read-snapshot.json"
_MAX_SNAPSHOT_BYTES = 16_384
_SNAPSHOT_FIELDS = frozenset(
    {
        "policy_hash",
        "audit_valid",
        "audit_records",
        "audit_tip",
        "source_schema",
        "schema",
    }
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate_json_key")
        document[key] = value
    return document


def _path_is_junction(path: Path) -> bool:
    """Return whether *path* is a Windows junction when the runtime can tell."""

    detector = getattr(path, "is_junction", None)
    return bool(detector and detector())


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare stable file identity fields exposed by the current platform."""

    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def load_mcp_snapshot(
    path: str | os.PathLike[str] = DEFAULT_SNAPSHOT_PATH,
) -> MCPReadSnapshot:
    """Load one exact owner-private frozen snapshot without write capability."""

    if not isinstance(path, (str, os.PathLike)) or isinstance(path, bytes):
        raise MCPBoundaryError("mcp_plugin_snapshot_path_invalid")
    target = Path(path).expanduser()
    if not target.is_absolute() or not target.name or "\x00" in target.name:
        raise MCPBoundaryError("mcp_plugin_snapshot_path_invalid")

    parent = target.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise MCPBoundaryError("mcp_plugin_snapshot_parent_invalid") from exc
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or _path_is_junction(parent)
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        raise MCPBoundaryError("mcp_plugin_snapshot_parent_invalid")

    directory_descriptor = -1
    file_descriptor = -1
    try:
        if os.name == "nt":
            # Windows cannot reliably open directories through os.open() with
            # POSIX-style O_DIRECTORY semantics. Resolve the complete parent
            # path instead and reject any symlink/junction traversal before
            # opening the exact snapshot by absolute path.
            try:
                resolved_parent = parent.resolve(strict=True)
            except OSError as exc:
                raise MCPBoundaryError("mcp_plugin_snapshot_parent_invalid") from exc

            lexical_parent = os.path.normcase(os.path.abspath(os.fspath(parent)))
            canonical_parent = os.path.normcase(os.fspath(resolved_parent))
            if lexical_parent != canonical_parent:
                raise MCPBoundaryError("mcp_plugin_snapshot_parent_invalid")

            try:
                target_metadata = target.lstat()
            except OSError as exc:
                raise MCPBoundaryError("mcp_plugin_snapshot_open_failed") from exc

            if stat.S_ISLNK(target_metadata.st_mode) or _path_is_junction(target):
                raise MCPBoundaryError("mcp_plugin_snapshot_open_failed")
            if (
                not stat.S_ISREG(target_metadata.st_mode)
                or target_metadata.st_size > _MAX_SNAPSHOT_BYTES
            ):
                raise MCPBoundaryError("mcp_plugin_snapshot_invalid")

            file_flags = os.O_RDONLY
            file_flags |= getattr(os, "O_CLOEXEC", 0)
            file_flags |= getattr(os, "O_BINARY", 0)
            try:
                file_descriptor = os.open(target, file_flags)
                metadata = os.fstat(file_descriptor)
            except OSError as exc:
                raise MCPBoundaryError("mcp_plugin_snapshot_open_failed") from exc

            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > _MAX_SNAPSHOT_BYTES
                or not _same_file_identity(metadata, target_metadata)
            ):
                raise MCPBoundaryError("mcp_plugin_snapshot_invalid")
        else:
            directory_flags = os.O_RDONLY
            directory_flags |= getattr(os, "O_CLOEXEC", 0)
            directory_flags |= getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                directory_descriptor = os.open(parent, directory_flags)
                opened_parent = os.fstat(directory_descriptor)
            except OSError as exc:
                raise MCPBoundaryError("mcp_plugin_snapshot_parent_invalid") from exc
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or not _same_file_identity(opened_parent, parent_metadata)
            ):
                raise MCPBoundaryError("mcp_plugin_snapshot_parent_invalid")

            file_flags = os.O_RDONLY
            file_flags |= getattr(os, "O_CLOEXEC", 0)
            file_flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                file_descriptor = os.open(
                    target.name,
                    file_flags,
                    dir_fd=directory_descriptor,
                )
                metadata = os.fstat(file_descriptor)
            except OSError as exc:
                raise MCPBoundaryError("mcp_plugin_snapshot_open_failed") from exc
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_SNAPSHOT_BYTES:
                raise MCPBoundaryError("mcp_plugin_snapshot_invalid")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise MCPBoundaryError("mcp_plugin_snapshot_permissions_invalid")

        try:
            with os.fdopen(file_descriptor, "r", encoding="utf-8") as handle:
                file_descriptor = -1
                raw = handle.read(_MAX_SNAPSHOT_BYTES + 1)
        except (OSError, UnicodeError) as exc:
            raise MCPBoundaryError("mcp_plugin_snapshot_invalid") from exc
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)

    if len(raw) > _MAX_SNAPSHOT_BYTES:
        raise MCPBoundaryError("mcp_plugin_snapshot_invalid")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise MCPBoundaryError("mcp_plugin_snapshot_invalid") from exc
    if type(document) is not dict or set(document) != _SNAPSHOT_FIELDS:
        raise MCPBoundaryError("mcp_plugin_snapshot_invalid")

    try:
        return MCPReadSnapshot(**document)
    except (TypeError, ValueError) as exc:
        raise MCPBoundaryError("mcp_plugin_snapshot_invalid") from exc


def create_plugin_server(
    snapshot_path: str | os.PathLike[str] = DEFAULT_SNAPSHOT_PATH,
):
    """Create the existing capability-stripped MCP server from a frozen file."""

    return create_mcp_server(load_mcp_snapshot(snapshot_path))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local portable plugin over MCP stdio."""

    parser = argparse.ArgumentParser(
        prog="pulpo-mcp-plugin",
        description="Run Pulpo's frozen read/proposal MCP projection.",
    )
    parser.add_argument(
        "--snapshot",
        default=str(DEFAULT_SNAPSHOT_PATH),
        help="Absolute path to a trusted exported pulpo.mcp-read-snapshot.v0 file.",
    )
    args = parser.parse_args(argv)

    server = create_plugin_server(args.snapshot)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":  # pragma: no cover - console entrypoint
    raise SystemExit(main())

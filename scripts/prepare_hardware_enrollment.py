#!/usr/bin/env python3
"""Prepare a one-shot local hardware-WebAuthn enrollment bundle.

This script performs no WebAuthn ceremony and grants no authority. It creates:
- a mode-0600 raw bootstrap token file for the operator browser only;
- a mode-0600 environment file containing only the token SHA-256 digest;
- a mode-0600 browser URL file whose fragment carries the raw token;
- a mode-0700 launch script for the loopback-only bootstrap runtime.

It deliberately does not edit DNS, /etc/hosts, trust stores, authority state,
provider credentials, or Pulpo policy.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
from urllib.parse import quote, urlparse


DEFAULT_ORIGIN = "https://authority.pulpo.ai:8443"
DEFAULT_RP_ID = "authority.pulpo.ai"
DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 600


class PreparationBlocked(RuntimeError):
    pass


def _canonical_path(value: str, field: str, *, must_exist: bool = False) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise PreparationBlocked(f"{field} must be an absolute path")
    if path.is_symlink():
        raise PreparationBlocked(f"{field} must not be a symlink")
    if must_exist and not path.is_file():
        raise PreparationBlocked(f"{field} is unavailable")
    return path


def _validate_origin(origin: str, rp_id: str) -> tuple[str, int]:
    parsed = urlparse(origin)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise PreparationBlocked("origin must be one exact HTTPS origin")
    if parsed.hostname != rp_id and not parsed.hostname.endswith(f".{rp_id}"):
        raise PreparationBlocked("origin host must equal or be below rp_id")
    port = parsed.port or 443
    if not 1 <= port <= 65_535:
        raise PreparationBlocked("origin port is invalid")
    return parsed.hostname, port


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    except FileExistsError as exc:
        raise PreparationBlocked(f"refusing to overwrite existing file: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _shell_export(name: str, value: str) -> str:
    return f"export {name}={shlex.quote(value)}"


def prepare(
    *,
    output_dir: Path,
    tls_cert_path: Path,
    tls_key_path: Path,
    origin: str = DEFAULT_ORIGIN,
    rp_id: str = DEFAULT_RP_ID,
    role: str = "primary",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    token_factory=None,
) -> dict[str, object]:
    output_dir = _canonical_path(str(output_dir), "output_dir")
    tls_cert_path = _canonical_path(str(tls_cert_path), "tls_cert_path", must_exist=True)
    tls_key_path = _canonical_path(str(tls_key_path), "tls_key_path", must_exist=True)
    rp_id = rp_id.strip()
    if not rp_id or "/" in rp_id or ":" in rp_id:
        raise PreparationBlocked("rp_id must be one canonical hostname")
    _, port = _validate_origin(origin, rp_id)
    if role not in {"primary", "recovery"}:
        raise PreparationBlocked("role must be primary or recovery")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or ttl_seconds <= 0
        or ttl_seconds > MAX_TTL_SECONDS
    ):
        raise PreparationBlocked("ttl_seconds is outside the allowed range")

    if output_dir.exists():
        if not output_dir.is_dir():
            raise PreparationBlocked("output_dir exists and is not a directory")
        if any(output_dir.iterdir()):
            raise PreparationBlocked("output_dir must be empty; refusing to mix bootstrap material")
    else:
        output_dir.mkdir(parents=True, mode=0o700)
    output_dir.chmod(0o700)

    token = (token_factory or secrets.token_urlsafe)(32)
    if (
        not isinstance(token, str)
        or not token
        or token != token.strip()
        or any(character.isspace() for character in token)
    ):
        raise PreparationBlocked("secure bootstrap token generation failed")
    token_digest = sha256(token.encode()).hexdigest()

    token_path = output_dir / "bootstrap-token.txt"
    env_path = output_dir / "enrollment.env"
    url_path = output_dir / "bootstrap-url.txt"
    launch_path = output_dir / "launch-enrollment.sh"
    candidate_path = output_dir / f"{role}-credential-candidate.json"

    environment = "\n".join(
        (
            _shell_export("PULPO_ENROLLMENT_ORIGIN", origin),
            _shell_export("PULPO_ENROLLMENT_RP_ID", rp_id),
            _shell_export("PULPO_ENROLLMENT_CANDIDATE_PATH", str(candidate_path)),
            _shell_export("PULPO_ENROLLMENT_TTL_SECONDS", str(ttl_seconds)),
            _shell_export("PULPO_ENROLLMENT_ROLE", role),
            _shell_export("PULPO_ENROLLMENT_BOOTSTRAP_TOKEN_SHA256", token_digest),
            _shell_export("PULPO_ENROLLMENT_TLS_CERT_PATH", str(tls_cert_path)),
            _shell_export("PULPO_ENROLLMENT_TLS_KEY_PATH", str(tls_key_path)),
            _shell_export("PULPO_ENROLLMENT_BIND_HOST", "127.0.0.1"),
        )
    ) + "\n"

    browser_url = f"{origin}/bootstrap#token={quote(token, safe='')}\n"
    launch = """#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$here/enrollment.env"
exec "${PYTHON:-python3}" -m pulpo_authority_service.hardware_enrollment_runtime
"""

    _write_exclusive(token_path, (token + "\n").encode(), 0o600)
    _write_exclusive(env_path, environment.encode(), 0o600)
    _write_exclusive(url_path, browser_url.encode(), 0o600)
    _write_exclusive(launch_path, launch.encode(), 0o700)

    # Enforce final modes even when the caller's umask is unusually permissive.
    token_path.chmod(0o600)
    env_path.chmod(0o600)
    url_path.chmod(0o600)
    launch_path.chmod(0o700)

    return {
        "schema": "pulpo.hardware-enrollment-preparation.v0",
        "origin": origin,
        "rp_id": rp_id,
        "port": port,
        "role": role,
        "ttl_seconds": ttl_seconds,
        "output_dir": str(output_dir),
        "token_path": str(token_path),
        "token_sha256": token_digest,
        "environment_path": str(env_path),
        "browser_url_path": str(url_path),
        "launch_path": str(launch_path),
        "candidate_path": str(candidate_path),
        "raw_token_printed": False,
        "dns_or_hosts_changed": False,
        "trust_store_changed": False,
        "candidate_admitted": False,
        "authority_effect": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--tls-cert-path", required=True)
    parser.add_argument("--tls-key-path", required=True)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    parser.add_argument("--rp-id", default=DEFAULT_RP_ID)
    parser.add_argument("--role", choices=("primary", "recovery"), default="primary")
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    args = parser.parse_args()

    try:
        result = prepare(
            output_dir=Path(args.output_dir),
            tls_cert_path=Path(args.tls_cert_path),
            tls_key_path=Path(args.tls_key_path),
            origin=args.origin,
            rp_id=args.rp_id,
            role=args.role,
            ttl_seconds=args.ttl_seconds,
        )
    except PreparationBlocked as exc:
        print(f"hardware enrollment preparation blocked: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

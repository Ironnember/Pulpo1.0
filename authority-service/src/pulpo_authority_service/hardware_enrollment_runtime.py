"""Loopback-only TLS runtime for hardware credential candidate bootstrap.

The process deliberately refuses authority signing, custody, or provider secret
material. It can create only an enrollment candidate file; it cannot activate
that candidate in the authority service.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse

from .hardware_enrollment import build_enrollment_app


FORBIDDEN_SECRET_NAMES = {
    "PULPO_ENROLLMENT_BOOTSTRAP_TOKEN",
    "PULPO_AUTHORITY_PRIVATE_KEY_PATH",
    "PULPO_AUTHORITY_PRIVATE_KEY_HEX",
    "PULPO_KERNEL_SECRET_HEX",
    "PULPO_CUSTODY_SECRET_HEX",
    "NAMECOM_SANDBOX_EXECUTOR_TOKEN",
    "NAMECOM_SANDBOX_OBSERVER_TOKEN",
}


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty canonical text")
    return value


def _absolute_file(environment: Mapping[str, str], name: str) -> Path:
    path = Path(_required(environment, name))
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if not path.is_file():
        raise RuntimeError(f"{name} is unavailable")
    return path


def validate_runtime_environment(environment: Mapping[str, str]) -> tuple[str, int, Path, Path]:
    forbidden = sorted(name for name in FORBIDDEN_SECRET_NAMES if environment.get(name))
    if forbidden:
        raise RuntimeError(
            "hardware enrollment process refuses authority/execution secret material: "
            + ", ".join(forbidden)
        )

    origin = _required(environment, "PULPO_ENROLLMENT_ORIGIN")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("PULPO_ENROLLMENT_ORIGIN must be HTTPS")
    port = parsed.port or 443
    if not 1 <= port <= 65_535:
        raise ValueError("enrollment origin port is invalid")

    bind_host = environment.get("PULPO_ENROLLMENT_BIND_HOST", "127.0.0.1")
    if bind_host not in {"127.0.0.1", "::1"}:
        raise ValueError("hardware enrollment V0 must bind only to loopback")

    cert = _absolute_file(environment, "PULPO_ENROLLMENT_TLS_CERT_PATH")
    key = _absolute_file(environment, "PULPO_ENROLLMENT_TLS_KEY_PATH")
    return bind_host, port, cert, key


def main() -> None:
    import uvicorn

    environment = dict(os.environ)
    bind_host, port, cert, key = validate_runtime_environment(environment)
    app = build_enrollment_app(environment)
    uvicorn.run(
        app,
        host=bind_host,
        port=port,
        workers=1,
        access_log=False,
        server_header=False,
        ssl_certfile=str(cert),
        ssl_keyfile=str(key),
    )


if __name__ == "__main__":
    main()

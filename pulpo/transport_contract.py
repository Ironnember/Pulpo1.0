"""Shared outbound transport policy checks for governed provider adapters."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


class TransportPolicyError(ValueError):
    """An outbound request violates the Pulpo transport contract."""


@dataclass(frozen=True)
class TransportPolicy:
    connect_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 5.0
    max_response_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if (
            self.connect_timeout_seconds <= 0
            or self.read_timeout_seconds <= 0
            or self.max_response_bytes <= 0
        ):
            raise ValueError("transport bounds must be positive")


def require_https_origin(origin: str, *, allowed: frozenset[str]) -> str:
    if not isinstance(origin, str) or origin not in allowed:
        raise TransportPolicyError("provider origin is not pinned")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or parsed.hostname is None or parsed.path not in ("", "/"):
        raise TransportPolicyError("provider origin must use pinned HTTPS")
    return origin


def redact_secret(value: object) -> str:
    return "<redacted>" if value else "<empty>"


def require_response_size(size: int, *, policy: TransportPolicy) -> None:
    if size < 0 or size > policy.max_response_bytes:
        raise TransportPolicyError("provider response exceeds bounded size")

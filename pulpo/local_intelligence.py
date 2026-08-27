"""Loopback-only local model client for Pulpo intelligence proposals.

Local models are intelligence capabilities, never governance authorities. This
module can ask an OpenAI-compatible endpoint on the same host for a text
proposal and return inspectable evidence about that proposal. It cannot evaluate
Pulpo policy, issue permits, consume permits, or execute side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
from typing import Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class LocalIntelligenceError(RuntimeError):
    """Raised when the local inference boundary cannot be trusted or parsed."""


@dataclass(frozen=True)
class LocalModelConfig:
    endpoint: str
    model: str
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        if not self.model:
            raise ValueError("local model id must be non-empty")
        if self.timeout_seconds <= 0:
            raise ValueError("local model timeout must be positive")
        parsed = urlparse(self.endpoint)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("local model endpoint must use http or https")
        if parsed.path != "/v1/chat/completions" or parsed.params or parsed.query or parsed.fragment:
            raise ValueError("local model endpoint must be the exact /v1/chat/completions path")
        host = parsed.hostname
        if not host or not _is_loopback_host(host):
            raise ValueError("local model endpoint must resolve to loopback by configuration")


@dataclass(frozen=True)
class LocalModelProposal:
    model: str
    text: str
    endpoint: str
    request_hash: str
    response_hash: str


Transport = Callable[[str, bytes, float], bytes]


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _default_transport(endpoint: str, body: bytes, timeout_seconds: float) -> bytes:
    request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


class LocalIntelligenceClient:
    """Request text proposals from one exact local model endpoint.

    The client intentionally exposes no tool schema, authority object, Pulpo
    kernel, permit method, credential injection, or arbitrary URL override.
    """

    def __init__(self, config: LocalModelConfig, transport: Transport | None = None) -> None:
        self.config = config
        self._transport = transport or _default_transport

    def propose(self, messages: tuple[dict[str, str], ...]) -> LocalModelProposal:
        if not messages:
            raise ValueError("local proposal requires at least one message")
        normalized: list[dict[str, str]] = []
        for message in messages:
            role = message.get("role")
            content = message.get("content")
            if role not in {"system", "user", "assistant"} or not isinstance(content, str) or not content:
                raise ValueError("local proposal messages must contain non-empty role/content text")
            normalized.append({"role": role, "content": content})

        payload = {
            "model": self.config.model,
            "messages": normalized,
            "temperature": 0,
            "stream": False,
        }
        request_body = _canonical(payload)
        request_hash = sha256(request_body).hexdigest()
        try:
            response_body = self._transport(
                self.config.endpoint,
                request_body,
                self.config.timeout_seconds,
            )
        except Exception as exc:
            raise LocalIntelligenceError("local model request failed") from exc

        response_hash = sha256(response_body).hexdigest()
        try:
            response = json.loads(response_body)
        except (TypeError, ValueError) as exc:
            raise LocalIntelligenceError("local model response is not valid JSON") from exc
        if not isinstance(response, dict):
            raise LocalIntelligenceError("local model response must be an object")
        if response.get("model") != self.config.model:
            raise LocalIntelligenceError("local model identity mismatch")
        try:
            choices = response["choices"]
            text = choices[0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LocalIntelligenceError("local model response shape is invalid") from exc
        if not isinstance(text, str) or not text:
            raise LocalIntelligenceError("local model proposal text is empty")

        return LocalModelProposal(
            model=self.config.model,
            text=text,
            endpoint=self.config.endpoint,
            request_hash=request_hash,
            response_hash=response_hash,
        )

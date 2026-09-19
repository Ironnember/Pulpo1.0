"""ASGI request admission limits with bounded buffering.

These limits are intentionally stateless. They bound obvious probing and
resource-exhaustion inputs without turning the governance service into a
rate-limit state machine.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable


MAX_HTTP_REQUEST_BODY_BYTES = 262_144
MAX_HTTP_REQUEST_TARGET_BYTES = 8_192
MAX_HTTP_HEADER_BYTES = 32_768


async def _reject(
    send: Callable[[dict[str, Any]], Awaitable[None]],
    status: int,
    message: bytes,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(message)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": message})


class RequestBodyLimitMiddleware:
    """Reject oversized request targets, headers, and bodies before routing."""

    def __init__(
        self,
        app,
        max_bytes: int = MAX_HTTP_REQUEST_BODY_BYTES,
        max_target_bytes: int = MAX_HTTP_REQUEST_TARGET_BYTES,
        max_header_bytes: int = MAX_HTTP_HEADER_BYTES,
    ) -> None:
        if max_bytes <= 0 or max_target_bytes <= 0 or max_header_bytes <= 0:
            raise ValueError("request admission limits must be positive")
        self.app = app
        self.max_bytes = max_bytes
        self.max_target_bytes = max_target_bytes
        self.max_header_bytes = max_header_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        raw_path = scope.get("raw_path")
        if not isinstance(raw_path, bytes):
            raw_path = str(scope.get("path", "")).encode("utf-8", "surrogatepass")
        query_string = scope.get("query_string", b"")
        if not isinstance(query_string, bytes):
            await _reject(send, 400, b"invalid request target")
            return
        target_size = len(raw_path) + (1 + len(query_string) if query_string else 0)
        if target_size > self.max_target_bytes:
            await _reject(send, 414, b"request target too large")
            return

        raw_headers = scope.get("headers", ())
        header_bytes = 0
        headers: dict[bytes, bytes] = {}
        for key, value in raw_headers:
            if not isinstance(key, bytes) or not isinstance(value, bytes):
                await _reject(send, 400, b"invalid request headers")
                return
            header_bytes += len(key) + len(value)
            if header_bytes > self.max_header_bytes:
                await _reject(send, 431, b"request headers too large")
                return
            headers[key.lower()] = value

        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except (TypeError, ValueError):
                await _reject(send, 400, b"invalid content-length")
                return
            if declared < 0:
                await _reject(send, 400, b"invalid content-length")
                return
            if declared > self.max_bytes:
                await _reject(send, 413, b"request body too large")
                return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"")
            if not isinstance(chunk, bytes):
                await _reject(send, 400, b"invalid request body")
                return
            total += len(chunk)
            if total > self.max_bytes:
                await _reject(send, 413, b"request body too large")
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)

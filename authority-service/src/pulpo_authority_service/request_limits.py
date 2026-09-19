"""ASGI request-body admission limit with bounded buffering."""

from __future__ import annotations

from typing import Any, Awaitable, Callable


MAX_HTTP_REQUEST_BODY_BYTES = 262_144


async def _reject(send: Callable[[dict[str, Any]], Awaitable[None]], status: int, message: bytes) -> None:
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
    """Read at most max_bytes before handing an HTTP request to FastAPI."""

    def __init__(self, app, max_bytes: int = MAX_HTTP_REQUEST_BODY_BYTES) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", ())}
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

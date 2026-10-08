"""
A request-body size limit for the whole Web API (security audit leftovers, 1.0.1).

Every body the API accepts is small: credentials, a scan request, a list of check ids. Nothing
bounded them, so an unauthenticated client could send a body of any size and make the process
parse and hold it. This middleware refuses a body over ``MAX_BODY_BYTES`` with a ``413`` before
the application reads the rest of it: at once when ``Content-Length`` already says it is too
large, and as soon as the bytes received pass the limit when the client streams a body without
declaring its length.

It is a pure ASGI middleware (no ``BaseHTTPMiddleware``) because the latter reads the body
itself and would defeat the point.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# 1 MiB. The largest legitimate body is a scan request with a long ``disabled_checks`` list, a
# few kilobytes; this leaves two orders of magnitude of room and still stops a flood.
MAX_BODY_BYTES = 1024 * 1024

_TOO_LARGE = json.dumps({"detail": "request body too large"}).encode()


class BodyLimitMiddleware:
    """Answers ``413`` to an HTTP request whose body is larger than ``max_bytes``."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        """
        Args:
            app (ASGIApp): The application to wrap.
            max_bytes (int): The largest body accepted, in bytes. Defaults to
                ``MAX_BODY_BYTES``.
        """
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Args:
            scope (Scope): The ASGI connection scope; only ``http`` is limited.
            receive (Receive): The ASGI receive channel.
            send (Send): The ASGI send channel.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. A body that declares itself too large is refused without reading any of it.
        declared = _declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _reject(send)
            return

        # 2. A body that does not declare its length is counted as it arrives.
        received = 0
        rejected = False
        started = False

        async def limited_receive() -> Message:
            """Pass the body through, and cut it off with a 413 when it passes the limit."""
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request" and not started and not rejected:
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    rejected = True
                    await _reject(send)
                    # The application sees a client that went away and stops reading.
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            """Drop whatever the application sends once the 413 is on its way."""
            nonlocal started
            if rejected:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, limited_receive, guarded_send)


def _declared_length(scope: Scope) -> int | None:
    """
    Args:
        scope (Scope): The ASGI connection scope.

    Returns:
        int | None: The ``Content-Length`` the client declared, or ``None`` when there is none or
            it is not a non-negative integer (the server answers a malformed one itself).
    """
    for name, value in scope["headers"]:
        if name == b"content-length":
            try:
                length = int(value)
            except ValueError:
                return None
            return length if length >= 0 else None
    return None


async def _reject(send: Send) -> None:
    """
    Send the ``413`` answer.

    Args:
        send (Send): The ASGI send channel.
    """
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_TOO_LARGE)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _TOO_LARGE})

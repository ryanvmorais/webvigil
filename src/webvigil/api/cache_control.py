"""
Every response of the Web API tells caches not to store it.

The API answers with a signed-in user's scans, findings and reports, and nothing it sends is
meant to be reused: a browser's disk cache or a proxy between the browser and the server could
otherwise keep a report after the session ends. A response that already says how it may be cached
keeps its own ``Cache-Control``.

It is a pure ASGI middleware, like :mod:`webvigil.api.body_limit`, so it covers the answers of
the other middlewares too.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# ASGI hands header names over as lower-case bytes, so the name is compared and written that way.
_CACHE_CONTROL = b"cache-control"
# No copy anywhere, not even one revalidated first: what the API sends is one user's data.
NO_STORE = b"no-store"


class NoStoreMiddleware:
    """Adds ``Cache-Control: no-store`` to every HTTP response that has no ``Cache-Control``."""

    def __init__(self, app: ASGIApp) -> None:
        """
        Args:
            app (ASGIApp): The application it wraps.
        """
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Args:
            scope (Scope): The ASGI connection scope.
            receive (Receive): The ASGI receive channel.
            send (Send): The ASGI send channel.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_no_store(message: Message) -> None:
            """
            Args:
                message (Message): An ASGI message; a response's start gains the header.
            """
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if not any(name.lower() == _CACHE_CONTROL for name, _ in headers):
                    headers.append((_CACHE_CONTROL, NO_STORE))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_no_store)

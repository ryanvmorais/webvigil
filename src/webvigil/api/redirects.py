"""
A redirect of the Web API keeps the scheme the client used.

Starlette answers a path with a stray trailing slash with a ``307`` to an absolute URL, built from
what the server saw. Behind a TLS-terminating proxy that is ``http``, and a ``307`` makes the
client send its body again, so a login's password would leave in clear text. A relative
``Location`` resolves against the URL the client really used and trusts no forwarding header.

It is a pure ASGI middleware, like :mod:`webvigil.api.body_limit`.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_REDIRECT_STATUS = range(300, 400)


def relative_location(location: bytes, host: bytes) -> bytes:
    """
    Args:
        location (bytes): The value of a ``Location`` header.
        host (bytes): The ``Host`` the request arrived with.

    Returns:
        bytes: Its path and query when it points at ``host``. Any other value is returned as it
            is, and so is a path a browser would read as another host once it stands alone.
    """
    try:
        parts = urlsplit(location.decode("latin-1"))
    except ValueError:
        return location
    if parts.netloc.encode("latin-1").lower() != host.lower():
        return location
    if not parts.path.startswith("/") or parts.path.startswith("//") or "\\" in parts.path:
        return location
    return urlunsplit(("", "", parts.path, parts.query, "")).encode("latin-1")


class RelativeRedirectMiddleware:
    """Rewrites the ``Location`` of a redirect to this server as a relative reference."""

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
        host = dict(scope["headers"]).get(b"host", b"")

        async def send_relative(message: Message) -> None:
            """
            Args:
                message (Message): An ASGI message; a redirect's start has its header rewritten.
            """
            if message["type"] == "http.response.start" and message["status"] in _REDIRECT_STATUS:
                headers = [
                    (name, relative_location(value, host) if name == b"location" else value)
                    for name, value in message.get("headers", [])
                ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_relative)

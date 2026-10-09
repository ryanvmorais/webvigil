"""
An ``Origin`` check on the state-changing requests of the Web API (issue #162).

The session cookie is ``SameSite=Lax``, which keeps a request from another *site* from carrying
it, but a page on another port of the same host is the same site, and a ``POST`` with no body
(``/api/auth/logout``, ``/api/scans/{id}/cancel``) needs no CORS preflight. A browser sends an
``Origin`` header on every ``POST``, ``PUT``, ``PATCH`` and ``DELETE``, so this middleware refuses
one whose ``Origin`` is present and is neither this server's own nor one the operator listed in
``web.cors_origins`` (the same list that opens CORS). A request without ``Origin`` is not a
browser form or fetch (curl, the CLI, a server-to-server call) and is not touched.

"Own" is the ``Host`` the request arrived with or, behind the dashboard's proxy, the
``X-Forwarded-Host`` it adds: Next rewrites ``/api/*`` to the API with the API's own ``Host``, so
the browser's ``Origin`` (the dashboard) only matches the forwarded one. A page of another site
can set neither header, so trusting them here does not weaken the check. The scheme is not
compared (the API behind a TLS-terminating proxy sees ``http`` while the browser says ``https``);
the host and the port are.

It is a pure ASGI middleware, like :mod:`webvigil.api.body_limit`, and answers before the body is
read.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Receive, Scope, Send

_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_REFUSED = json.dumps({"detail": "cross-origin request refused"}).encode()


def _origin(value: str) -> str | None:
    """
    Args:
        value (str): An origin as written in ``web.cors_origins`` or in an ``Origin`` header.

    Returns:
        str | None: ``scheme://host[:port]`` in lower case, or ``None`` when ``value`` is not an
            origin (``null``, a path, an opaque or malformed value).
    """
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc or parts.path not in ("", "/") or parts.query:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


class OriginCheckMiddleware:
    """Answers ``403`` to a state-changing request from a foreign ``Origin``."""

    def __init__(self, app: ASGIApp, allowed_origins: Iterable[str] = ()) -> None:
        """
        Args:
            app (ASGIApp): The application to wrap.
            allowed_origins (Iterable[str]): The origins accepted besides the server's own, as in
                ``web.cors_origins``. Defaults to none.
        """
        self.app = app
        self._allowed = frozenset(o for o in map(_origin, allowed_origins) if o is not None)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Args:
            scope (Scope): The ASGI connection scope; only ``http`` is checked.
            receive (Receive): The ASGI receive channel.
            send (Send): The ASGI send channel.
        """
        if scope["type"] != "http" or scope["method"] not in _STATE_CHANGING:
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        raw = headers.get(b"origin")
        if raw is None or self._accepts(raw.decode("latin-1"), headers):
            await self.app(scope, receive, send)
            return
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_REFUSED)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _REFUSED})

    def _accepts(self, raw: str, headers: dict[bytes, bytes]) -> bool:
        """
        Args:
            raw (str): The ``Origin`` header value.
            headers (dict[bytes, bytes]): The request headers, lower-cased names.

        Returns:
            bool: ``True`` when ``raw`` is one of the allowed origins or names the host (and port)
                this request was addressed to, directly or through the dashboard's proxy.
        """
        origin = _origin(raw)
        if origin is None:  # "null" (a sandboxed frame, a file), or not an origin at all
            return False
        if origin in self._allowed:
            return True
        netloc = origin.split("://", 1)[1]
        own = {headers.get(b"host", b"").decode("latin-1").lower()}
        forwarded = headers.get(b"x-forwarded-host", b"").decode("latin-1")
        own.add(forwarded.split(",")[0].strip().lower())  # the first hop is the browser's
        own.discard("")
        return netloc in own

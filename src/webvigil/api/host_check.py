"""
A ``Host`` check on every request of the Web API (GHSA-q373-8m5q-qwww).

The API and the dashboard usually listen on the loopback address of the user's own machine. A
browser decides what is "the same site" by the host *name* in the address bar, not by the address
that name resolves to, so a name under someone else's control that is made to resolve to the
loopback address would let one of their pages talk to the API as its own origin (DNS rebinding):
the ``Origin`` check (:mod:`webvigil.api.origin_check`) compares the ``Origin`` with the ``Host``,
and both would carry that name.

This middleware answers ``400`` to a request whose ``Host``, or whose ``X-Forwarded-Host`` (the
browser's ``Host``, as the dashboard's proxy forwards it), names a host the server was not told
about. Accepted are:

- an IP address (``127.0.0.1``, ``[::1]``, a LAN address): a page can only have an IP address as
  its origin if it was served from that address, which is this server;
- ``localhost``, which browsers resolve to the loopback address themselves;
- the bind host from ``web.host``, when it is a name;
- the names listed in ``web.allowed_hosts`` (a reverse proxy's public name, the API's service name
  inside Docker Compose).

The port is not compared: a page on another port is another origin, and the ``Origin`` check
already handles it. A request with no ``Host`` at all (HTTP/1.0 from a script) is not a browser's
and passes. Pure ASGI, like :mod:`webvigil.api.body_limit`: it answers before the body is read.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

_REFUSED = json.dumps({"detail": "host not allowed"}).encode()
_CHECKED_HEADERS = frozenset({b"host", b"x-forwarded-host"})
ALWAYS_ALLOWED = frozenset({"localhost"})


def host_name(value: str) -> str:
    """
    Args:
        value (str): A ``Host`` or ``X-Forwarded-Host`` value: ``name``, ``name:port``, ``a.b.c.d``,
            ``a.b.c.d:port``, ``[v6]`` or ``[v6]:port``.

    Returns:
        str: The host part in lower case, without the port, the IPv6 brackets or a trailing dot;
            ``""`` when there is none.
    """
    value = value.strip().lower()
    if value.startswith("["):  # [v6] or [v6]:port
        end = value.find("]")
        return value[1:end] if end != -1 else ""
    if value.count(":") == 1:  # name:port (a bare v6 address has more than one colon)
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def _is_ip_address(name: str) -> bool:
    """
    Args:
        name (str): A host part, as :func:`host_name` returns it.

    Returns:
        bool: ``True`` when ``name`` is an IPv4 address in dotted form or an IPv6 address.
    """
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


class HostCheckMiddleware:
    """Answers ``400`` to a request addressed to a host name this server does not know."""

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str] = ()) -> None:
        """
        Args:
            app (ASGIApp): The application to wrap.
            allowed_hosts (Iterable[str]): Host names accepted besides IP addresses and
                ``localhost``, as in ``web.allowed_hosts`` (plus the bind host). Defaults to none.
        """
        self.app = app
        self._allowed = ALWAYS_ALLOWED | {host_name(h) for h in allowed_hosts if host_name(h)}

    def _accepts(self, raw: bytes) -> bool:
        """
        Args:
            raw (bytes): A ``Host`` or ``X-Forwarded-Host`` header value.

        Returns:
            bool: ``True`` when it names an IP address or one of the allowed names. For
                ``X-Forwarded-Host`` only the first hop (the browser's) is looked at.
        """
        name = host_name(raw.decode("latin-1").split(",")[0])
        return name in self._allowed or _is_ip_address(name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Args:
            scope (Scope): The ASGI connection scope; ``http`` and ``websocket`` are checked.
            receive (Receive): The ASGI receive channel.
            send (Send): The ASGI send channel.
        """
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        # Every occurrence counts: a repeated header must not let a good value vouch for a bad one.
        checked = [value for name, value in scope["headers"] if name in _CHECKED_HEADERS]
        if all(self._accepts(value) for value in checked):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":  # the API serves none; close it rather than answer
            await send({"type": "websocket.close", "code": 1008})
            return
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_REFUSED)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _REFUSED})

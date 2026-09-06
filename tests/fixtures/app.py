"""A minimal Starlette target app with an ``insecure`` and a ``hardened`` profile (RF-27).

TLS/HTTPS findings are not exercised here — the app is plain HTTP by nature — so the
integration test disables the ``tls.https`` check. Those cases live in the socket-based
unit tests.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

_LINKS = '<a href="/about">about</a> <a href="/contact">contact</a>'
_PAGE = f"<!doctype html><html><body><h1>Demo</h1>{_LINKS}</body></html>"

_HARDENED_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "cross-origin-resource-policy": "same-origin",
}


def _insecure(request: Request) -> Response:
    response = HTMLResponse(_PAGE)
    response.headers["server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["x-powered-by"] = "PHP/8.1.2"
    response.headers["set-cookie"] = "session=abc123; Path=/"
    origin = request.headers.get("origin")
    if origin is not None:
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
    return response


def _hardened(request: Request) -> Response:
    response = HTMLResponse(_PAGE)
    for name, value in _HARDENED_HEADERS.items():
        response.headers[name] = value
    response.headers["set-cookie"] = "__Host-session=abc123; Secure; HttpOnly; Path=/; SameSite=Lax"
    return response


def make_app(profile: str) -> Starlette:
    handler = _insecure if profile == "insecure" else _hardened
    routes = [Route(path, handler) for path in ("/", "/about", "/contact")]
    return Starlette(routes=routes)

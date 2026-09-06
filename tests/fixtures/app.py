"""A minimal Starlette target app with an ``insecure`` and a ``hardened`` profile (RF-27).

TLS/HTTPS findings are not exercised here — the app is plain HTTP by nature — so the
integration test disables the ``tls.https`` check. Those cases live in the socket-based
unit tests.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.routing import Route

_LINKS = '<a href="/about">about</a> <a href="/contact">contact</a>'
_PAGE = f"<!doctype html><html><body><h1>Demo</h1>{_LINKS}</body></html>"
# The insecure profile also ships a known-vulnerable jQuery from its own origin (spec 004,
# RF-19). 1.7.1 is well below every fixed version in the Retire.js database.
_VULNERABLE_JS_PATH = "/static/jquery-1.7.1.min.js"
_INSECURE_PAGE = (
    f"<!doctype html><html><body><h1>Demo</h1>{_LINKS}"
    f'<script src="{_VULNERABLE_JS_PATH}"></script></body></html>'
)
_VULNERABLE_JS = "/*! jQuery v1.7.1 jquery.com | jquery.org/license */\n!function(){}();\n"

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
    response = HTMLResponse(_INSECURE_PAGE)
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


def _vulnerable_js(request: Request) -> Response:
    return PlainTextResponse(_VULNERABLE_JS, media_type="application/javascript")


def make_app(profile: str) -> Starlette:
    handler = _insecure if profile == "insecure" else _hardened
    routes = [Route(path, handler) for path in ("/", "/about", "/contact")]
    if profile == "insecure":
        routes.append(Route(_VULNERABLE_JS_PATH, _vulnerable_js))
    return Starlette(routes=routes)

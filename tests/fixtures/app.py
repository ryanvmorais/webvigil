"""A minimal Starlette target app with an ``insecure`` and a ``hardened`` profile (RF-27).

TLS/HTTPS findings are not exercised here — the app is plain HTTP by nature — so the
integration test disables the ``tls.https`` check. Those cases live in the socket-based
unit tests.
"""

from __future__ import annotations

from collections.abc import Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.routing import Route

_LINKS = '<a href="/about">about</a> <a href="/contact">contact</a>'
_PAGE = f"<!doctype html><html><body><h1>Demo</h1>{_LINKS}</body></html>"
# The insecure profile also ships a known-vulnerable jQuery from its own origin (spec 004,
# RF-19). 1.7.1 is well below every fixed version in the Retire.js database.
_VULNERABLE_JS_PATH = "/static/jquery-1.7.1.min.js"
# spec 005 (RF-13): the insecure profile also links a directory listing and a stack-trace
# page (found passively), and serves .git/.env/package.json (found only by --probe).
_DISCLOSURE_LINKS = '<a href="/uploads/">uploads</a> <a href="/boom">boom</a>'
_INSECURE_PAGE = (
    f"<!doctype html><html><body><h1>Demo</h1>{_LINKS} {_DISCLOSURE_LINKS}"
    f'<script src="{_VULNERABLE_JS_PATH}"></script></body></html>'
)
_VULNERABLE_JS = "/*! jQuery v1.7.1 jquery.com | jquery.org/license */\n!function(){}();\n"

_GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
    '[remote "origin"]\n\turl = git@github.com:acme/webapp.git\n'
)
_GIT_HEAD = "ref: refs/heads/main\n"
_DOTENV = (
    "SECRET_KEY=django-insecure-9x1q7c\n"
    "DATABASE_URL=postgres://app:s3cr3t@db.internal/app\n"
    "DEBUG=True\n"
)
_PACKAGE_JSON = (
    '{"name": "acme-webapp", "version": "3.2.1", '
    '"dependencies": {"express": "4.18.2", "lodash": "4.17.21"}}'
)
_LISTING_PAGE = (
    "<!doctype html><html><head><title>Index of /uploads</title></head><body>"
    "<h1>Index of /uploads</h1><pre>"
    '<a href="../">../</a>\n<a href="invoice.pdf">invoice.pdf</a>\n'
    '<a href="db-backup.sql">db-backup.sql</a>\n</pre></body></html>'
)
_TRACE_PAGE = (
    "<!doctype html><html><head><title>RuntimeError // Werkzeug Debugger</title></head>"
    '<body><div class="traceback"><h1>RuntimeError</h1>'
    "<div>The Werkzeug debugger caught an exception.</div><pre>"
    "Traceback (most recent call last):\n"
    "  File &quot;/srv/acme/views.py&quot;, line 88, in boom\n"
    "    raise RuntimeError(&quot;boom&quot;)\nRuntimeError: boom</pre></div></body></html>"
)

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


def _text(body: str) -> Callable[[Request], Response]:
    return lambda request: PlainTextResponse(body)


def _html(body: str) -> Callable[[Request], Response]:
    return lambda request: HTMLResponse(body)


def _package_json(request: Request) -> Response:
    return Response(_PACKAGE_JSON, media_type="application/json")


_INSECURE_EXTRA_ROUTES = (
    (_VULNERABLE_JS_PATH, _vulnerable_js),
    ("/uploads/", _html(_LISTING_PAGE)),
    ("/boom", _html(_TRACE_PAGE)),
    ("/.git/config", _text(_GIT_CONFIG)),
    ("/.git/HEAD", _text(_GIT_HEAD)),
    ("/.env", _text(_DOTENV)),
    ("/package.json", _package_json),
)


def make_app(profile: str) -> Starlette:
    handler = _insecure if profile == "insecure" else _hardened
    routes = [Route(path, handler) for path in ("/", "/about", "/contact")]
    if profile == "insecure":
        routes += [Route(path, view) for path, view in _INSECURE_EXTRA_ROUTES]
    return Starlette(routes=routes)

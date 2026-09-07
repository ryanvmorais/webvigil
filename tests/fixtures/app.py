"""A minimal Starlette target app with an ``insecure`` and a ``hardened`` profile.

Covers spec 001 (headers/cookies/CORS/revealing), spec 004 (a vulnerable jQuery), spec 005
(exposed .git/.env/backups, a listing, a stack trace), spec 006 (reflected XSS, SQLi, path
traversal, open redirect), spec 007 (a cookie-gated ``/account`` area, a tokenless POST
form, a ``/logout`` link the crawler must not follow) and spec 008 (a guestbook and a
behind-login profile page that render stored input unescaped on a later request). The app
is plain HTTP by nature, so the integration test disables ``tls.https``; TLS cases live in
the socket-based unit tests.
"""

from __future__ import annotations

import html
import re
import sqlite3
import time
from collections.abc import Callable

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

_LINKS = (
    '<a href="/about">about</a> <a href="/contact">contact</a> '
    '<a href="/account">account</a> <a href="/guestbook">guestbook</a>'
)
# spec 006 (RF-20): links to the injectable endpoints, and the three forms. Both profiles
# link them so an Active scan of the hardened profile actually fuzzes and finds nothing.
_INJECTION_LINKS = (
    '<a href="/search?q=demo">search</a> <a href="/item?id=1">item</a> '
    '<a href="/download?file=readme.txt">download</a> <a href="/go?next=/home">go</a> '
    # spec 009: two "fetch this URL" endpoints — SSRF-able in the insecure profile.
    '<a href="/fetch?url=/preview">fetch</a> '
    '<a href="/webhook?callback=/ping">webhook</a>'
)
_FORMS = (
    '<form method="get" action="/search"><input name="q"></form>'
    '<form method="post" action="/comment">'
    '<input type="hidden" name="csrf" value="tok123"><textarea name="body"></textarea></form>'
    '<form method="post" action="/login">'
    '<input name="username"><input type="password" name="password"></form>'
    # spec 008 (RF-13): a guestbook whose entries are rendered on a per-entry page reachable
    # only after a post — so the stored-XSS re-crawl must find it. It carries a CSRF token so
    # the CSRF check stays quiet; the stored-XSS pass fuzzes the `body` field.
    '<form method="post" action="/guestbook">'
    '<input type="hidden" name="csrf_token" value="gbtok"><textarea name="body"></textarea></form>'
)
_PAGE = f"<!doctype html><html><body><h1>Demo</h1>{_LINKS} {_INJECTION_LINKS}{_FORMS}</body></html>"

# The insecure profile also ships a known-vulnerable jQuery from its own origin (spec 004,
# RF-19). 1.7.1 is well below every fixed version in the Retire.js database.
_VULNERABLE_JS_PATH = "/static/jquery-1.7.1.min.js"
# spec 005 (RF-13): the insecure profile also links a directory listing and a stack-trace
# page (found passively), and serves .git/.env/package.json (found only by --probe).
_DISCLOSURE_LINKS = '<a href="/uploads/">uploads</a> <a href="/boom">boom</a>'
_INSECURE_PAGE = (
    f"<!doctype html><html><body><h1>Demo</h1>{_LINKS} {_INJECTION_LINKS} {_DISCLOSURE_LINKS}"
    f"{_FORMS}"
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

# spec 006: a known system file the traversal payloads reach on the insecure profile.
_ETC_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_SLEEP_RE = re.compile(r"(?:sleep|pg_sleep)\((\d+)\)", re.I)

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.executescript(
    "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"
    "INSERT INTO items VALUES (1, 'Widget'), (2, 'Gadget'), (3, 'Sprocket');"
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


def _home(request: Request) -> Response:
    return HTMLResponse("<!doctype html><html><body><p>home</p></body></html>")


# --- spec 006: the injectable endpoints (insecure) --------------------------------


def _search_insecure(request: Request) -> Response:
    q = request.query_params.get("q", "")
    return HTMLResponse(f"<!doctype html><h1>Results for {q}</h1><form action='/search'></form>")


def _item_insecure(request: Request) -> Response:
    raw = request.query_params.get("id", "1")
    match = _SLEEP_RE.search(raw)
    if match:
        time.sleep(min(int(match.group(1)), 6))
        raw = "1"
    try:
        rows = _DB.execute("SELECT name FROM items WHERE id = '" + raw + "'").fetchall()
    except sqlite3.OperationalError as exc:
        return PlainTextResponse(f"sqlite3.OperationalError: {exc}", status_code=500)
    if rows:
        return HTMLResponse(f"<!doctype html><div>Item: {rows[0][0]}</div>")
    return HTMLResponse("<!doctype html><div>No such item</div>", status_code=404)


def _download_insecure(request: Request) -> Response:
    name = request.query_params.get("file", "")
    lowered = name.replace("\\", "/").lower()
    if "etc/passwd" in lowered:
        return PlainTextResponse(_ETC_PASSWD)
    return PlainTextResponse(f"contents of {name}")


def _go_insecure(request: Request) -> Response:
    return RedirectResponse(request.query_params.get("next", "/"), status_code=302)


async def _comment_insecure(request: Request) -> Response:
    form = await request.form()
    return HTMLResponse(f"<!doctype html><p>Posted: {form.get('body', '')}</p>")


# spec 009 (RF-12): two server-side URL fetchers. `/fetch` is fully SSRF-able and stands in
# for a real cloud/host environment so the integration scan is deterministic and offline.
# `/webhook` blocks the metadata IP (as many real apps do) but still reaches loopback.
_AWS_METADATA = (
    '{"Code":"Success","LastUpdated":"2026-09-07T00:00:00Z",'
    '"AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/EXAMPLE",'
    '"Token":"FQoGZXIvYXdzEEXAMPLE","Expiration":"2026-09-07T06:00:00Z"}'
)
_REDIS_BANNER = "redis_version:7.2.4\r\nredis_mode:standalone\r\nconnected_clients:1\r\n"
_LOOPBACK_HOSTS = (
    "127.0.0.1",
    "127.1",
    "localhost",
    "[::1]",
    "0.0.0.0",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
)
_METADATA_HOSTS = (
    "169.254.169.254",
    "2852039166",
    "0xa9fea9fe",
    "metadata.google",
    "100.100.100.200",
    "kubernetes.default",
)


def _fetch_insecure(request: Request) -> Response:
    raw = request.query_params.get("url", "")
    low = raw.lower()
    if not low.startswith(("http://", "https://", "file:")):
        return HTMLResponse(f"<!doctype html><div>preview of {raw}</div>")
    if any(h in low for h in _METADATA_HOSTS):
        return PlainTextResponse(_AWS_METADATA, media_type="application/json")
    if low.startswith("file:"):
        return PlainTextResponse(_ETC_PASSWD if "passwd" in low else f"contents of {raw}")
    if any(h in low for h in _LOOPBACK_HOSTS):
        return PlainTextResponse(_REDIS_BANNER)
    return PlainTextResponse(f"failed to fetch {raw}: Connection refused", status_code=502)


def _webhook_insecure(request: Request) -> Response:
    raw = request.query_params.get("callback", "")
    low = raw.lower()
    if not low.startswith(("http://", "https://", "file:")):
        return HTMLResponse(f"<!doctype html><div>callback set to {raw}</div>")
    if any(h in low for h in _METADATA_HOSTS) or low.startswith("file:"):
        return PlainTextResponse("blocked: address not permitted", status_code=400)
    if any(h in low for h in _LOOPBACK_HOSTS):
        return PlainTextResponse(_REDIS_BANNER)
    return PlainTextResponse(f"failed to fetch {raw}: Connection refused", status_code=502)


def _fetch_hardened(request: Request) -> Response:
    raw = request.query_params.get("url" if "url" in request.query_params else "callback", "")
    if not raw.startswith(("https://cdn.example.com/", "https://api.example.com/")):
        return PlainTextResponse("blocked: destination not on the allow-list", status_code=400)
    return PlainTextResponse("ok")


def _login(request: Request) -> Response:
    return HTMLResponse("<!doctype html><p>Sign in</p>")


# --- spec 007: the cookie-gated account area (RF-13) ------------------------------

_ACCOUNT_INSECURE = (
    "<!doctype html><html><body><h1>Account</h1>"
    '<a href="/account/settings">settings</a> <a href="/logout">log out</a>'
    '<form method="post" action="/profile"><input name="nickname"></form>'
    "</body></html>"
)
_ACCOUNT_HARDENED = (
    "<!doctype html><html><body><h1>Account</h1>"
    '<a href="/account/settings">settings</a> <a href="/logout">log out</a>'
    '<form method="post" action="/profile">'
    '<input type="hidden" name="csrf_token" value="tok123"><input name="nickname"></form>'
    "</body></html>"
)


def _account(cookie_name: str, body: str) -> Callable[[Request], Response]:
    def view(request: Request) -> Response:
        if not request.cookies.get(cookie_name):  # any non-empty session value is "logged in"
            return RedirectResponse("/login", status_code=302)
        return HTMLResponse(body)

    return view


def _account_settings(cookie_name: str, *, escape: bool) -> Callable[[Request], Response]:
    def view(request: Request) -> Response:
        if not request.cookies.get(cookie_name):
            return RedirectResponse("/login", status_code=302)
        # spec 008: the nickname set via POST /profile is rendered here on a later request —
        # a stored-XSS sink that only an authenticated re-crawl can reach.
        nickname: str = request.app.state.profile
        shown = html.escape(nickname) if escape else nickname
        return HTMLResponse(f"<!doctype html><html><body><p>settings: {shown}</p></body></html>")

    return view


async def _profile(request: Request) -> Response:
    form = await request.form()
    request.app.state.profile = str(form.get("nickname", ""))
    return HTMLResponse("<!doctype html><p>updated</p>")


def _logout(request: Request) -> Response:
    return RedirectResponse("/", status_code=302)


# --- spec 008: the guestbook — stored XSS on a per-entry page (RF-13) -------------


def _guestbook_list(request: Request) -> Response:
    entries: list[str] = request.app.state.guestbook
    links = "".join(f'<a href="/guestbook/e/{i}">entry {i}</a>' for i in range(len(entries)))
    return HTMLResponse(
        f"<!doctype html><html><body><h1>Guestbook</h1>{links}"
        '<form method="post" action="/guestbook">'
        '<input type="hidden" name="csrf_token" value="gbtok"><textarea name="body"></textarea>'
        "</form></body></html>"
    )


async def _guestbook_post(request: Request) -> Response:
    form = await request.form()
    request.app.state.guestbook.append(str(form.get("body", "")))
    return RedirectResponse("/guestbook", status_code=302)


def _guestbook_entry(escape: bool) -> Callable[[Request], Response]:
    def view(request: Request) -> Response:
        entries: list[str] = request.app.state.guestbook
        index = int(request.path_params["i"])
        if not 0 <= index < len(entries):
            return HTMLResponse("<!doctype html><div>no such entry</div>", status_code=404)
        body = html.escape(entries[index]) if escape else entries[index]
        return HTMLResponse(f"<!doctype html><html><body><div>{body}</div></body></html>")

    return view


async def _guestbook(request: Request) -> Response:
    if request.method == "POST":
        return await _guestbook_post(request)
    return _guestbook_list(request)


# --- spec 006: the safe equivalents (hardened) -----------------------------------


def _search_hardened(request: Request) -> Response:
    q = html.escape(request.query_params.get("q", ""))
    return HTMLResponse(f"<!doctype html><h1>Results for {q}</h1>")


def _item_hardened(request: Request) -> Response:
    raw = request.query_params.get("id", "1")
    if not raw.isdigit():
        return HTMLResponse("<!doctype html><div>Not found</div>", status_code=404)
    rows = _DB.execute("SELECT name FROM items WHERE id = ?", (int(raw),)).fetchall()
    if rows:
        return HTMLResponse(f"<!doctype html><div>Item: {rows[0][0]}</div>")
    return HTMLResponse("<!doctype html><div>No such item</div>", status_code=404)


def _download_hardened(request: Request) -> Response:
    name = request.query_params.get("file", "")
    if "/" in name or "\\" in name or ".." in name:
        return PlainTextResponse("invalid file name", status_code=400)
    return PlainTextResponse(f"contents of {name}")


def _go_hardened(request: Request) -> Response:
    allowed = {"/home", "/about", "/contact"}
    dest = request.query_params.get("next", "/")
    return RedirectResponse(dest if dest in allowed else "/", status_code=302)


async def _comment_hardened(request: Request) -> Response:
    form = await request.form()
    return HTMLResponse(f"<!doctype html><p>Posted: {html.escape(str(form.get('body', '')))}</p>")


_INSECURE_EXTRA_ROUTES: tuple[tuple[str, Callable[[Request], Response]], ...] = (
    (_VULNERABLE_JS_PATH, _vulnerable_js),
    ("/uploads/", _html(_LISTING_PAGE)),
    ("/boom", _html(_TRACE_PAGE)),
    ("/.git/config", _text(_GIT_CONFIG)),
    ("/.git/HEAD", _text(_GIT_HEAD)),
    ("/.env", _text(_DOTENV)),
    ("/package.json", _package_json),
)

_INJECTION_ROUTES = {
    "insecure": (
        ("/search", _search_insecure, ["GET"]),
        ("/item", _item_insecure, ["GET"]),
        ("/download", _download_insecure, ["GET"]),
        ("/go", _go_insecure, ["GET"]),
        ("/fetch", _fetch_insecure, ["GET"]),
        ("/webhook", _webhook_insecure, ["GET"]),
        ("/comment", _comment_insecure, ["POST"]),
        ("/account", _account("session", _ACCOUNT_INSECURE), ["GET"]),
        ("/account/settings", _account_settings("session", escape=False), ["GET"]),
        ("/profile", _profile, ["POST"]),
        ("/logout", _logout, ["GET"]),
        ("/guestbook", _guestbook, ["GET", "POST"]),
        ("/guestbook/e/{i:int}", _guestbook_entry(escape=False), ["GET"]),
    ),
    "hardened": (
        ("/search", _search_hardened, ["GET"]),
        ("/item", _item_hardened, ["GET"]),
        ("/download", _download_hardened, ["GET"]),
        ("/go", _go_hardened, ["GET"]),
        ("/fetch", _fetch_hardened, ["GET"]),
        ("/webhook", _fetch_hardened, ["GET"]),
        ("/comment", _comment_hardened, ["POST"]),
        ("/account", _account("__Host-session", _ACCOUNT_HARDENED), ["GET"]),
        ("/account/settings", _account_settings("__Host-session", escape=True), ["GET"]),
        ("/profile", _profile, ["POST"]),
        ("/logout", _logout, ["GET"]),
        ("/guestbook", _guestbook, ["GET", "POST"]),
        ("/guestbook/e/{i:int}", _guestbook_entry(escape=True), ["GET"]),
    ),
}


def _recorder(sink: list[str]) -> Callable[[ASGIApp], ASGIApp]:
    class _Recorder:
        def __init__(self, app: ASGIApp) -> None:
            self._app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "http":
                query = scope.get("query_string", b"").decode("latin-1")
                sink.append(f"{scope['method']} {scope['path']}?{query}")
            await self._app(scope, receive, send)

    return _Recorder


def make_app(profile: str) -> Starlette:
    is_insecure = profile == "insecure"
    handler = _insecure if is_insecure else _hardened
    requests: list[str] = []

    routes = [Route(path, handler) for path in ("/", "/about", "/contact")]
    routes.append(Route("/home", _home))
    routes += [Route(path, view, methods=m) for path, view, m in _INJECTION_ROUTES[profile]]
    routes.append(Route("/login", _login, methods=["GET", "POST"]))
    if is_insecure:
        routes += [Route(path, view) for path, view in _INSECURE_EXTRA_ROUTES]

    app = Starlette(routes=routes, middleware=[Middleware(_recorder(requests))])
    app.state.requests = requests
    app.state.guestbook = []  # spec 008: reset per app so the suite stays deterministic
    app.state.profile = ""
    return app

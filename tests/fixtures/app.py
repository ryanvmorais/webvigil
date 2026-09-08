"""
A minimal Starlette target app with an ``insecure`` and a ``hardened`` profile.

Covers spec 001 (headers/cookies/CORS/revealing), spec 004 (a vulnerable
jQuery), spec 005 (exposed .git/.env/backups, a listing, a stack trace), spec
006 (reflected XSS, SQLi, path traversal, open redirect), spec 007 (a
cookie-gated ``/account`` area, a tokenless POST form, a ``/logout`` link the
crawler must not follow), spec 008 (a guestbook and a behind-login profile page
that render stored input unescaped on a later request), spec 009 (two "fetch
this URL" endpoints), spec 011 (a shell-backed ``/ping`` and a template-backed
``/greet``) and spec 012 (a CRLF ``/set-lang``, a host-header ``/reset``, an XML
``/api/xml`` and a ``/resource`` that advertises TRACE / PUT). The app is plain
HTTP by nature, so the integration test disables ``tls.https``; TLS cases live in
the socket-based unit tests.

The route handlers are one-liners with inline comments per spec; only
:func:`make_app` and the middleware factory carry a docstring.
"""

from __future__ import annotations

import html
import re
import sqlite3
import time
from collections.abc import Callable
from urllib.parse import unquote

import jinja2
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
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
    '<a href="/webhook?callback=/ping">webhook</a> '
    # spec 011: a shell-backed "ping" and a template-backed "greet".
    '<a href="/ping?host=localhost">ping</a> '
    '<a href="/greet?name=guest">greet</a> '
    # spec 012: a language cookie (CRLF), a reset page (host header), a methods route.
    '<a href="/set-lang?lang=en">set-lang</a> '
    '<a href="/reset">reset</a> <a href="/resource">resource</a> '
    # spec 014: an LDAP-filter search, an XPath-over-XML lookup, an SSI-processing page.
    '<a href="/dir?user=jdoe">dir</a> '
    '<a href="/xdoc?node=Dune">xdoc</a> '
    '<a href="/page?tpl=hi">page</a>'
)
# spec 013: the insecure index also carries a cross-origin script with no SRI, a session
# token handed to a third-party link, and an internal IP in a comment — inlined here rather
# than on a new page so the crawl count (and the spec-008 stored-XSS re-crawl budget) is
# unchanged. Both profiles serve /openapi.json + /api/find + /api/items, reached only via
# --openapi.
_SPEC_013_INSECURE = (
    "<!-- upstream backend 10.13.37.1 -->"
    '<script src="https://cdn.example.com/analytics.js"></script>'
    '<a href="https://partner.example/sso?access_token=WV013SECRETTOKEN">partner login</a>'
)
_FORMS = (
    '<form method="get" action="/search"><input name="q"></form>'
    # spec 012: a POST endpoint the opt-in XXE step re-sends as XML. It carries a CSRF token
    # so the passive CSRF check stays quiet — XXE is the point here, not CSRF.
    '<form method="post" action="/api/xml">'
    '<input type="hidden" name="csrf_token" value="xmltok"><input name="data" value="{}"></form>'
    '<form method="post" action="/comment">'
    '<input type="hidden" name="csrf" value="tok123"><textarea name="body"></textarea></form>'
    '<form method="post" action="/login">'
    '<input name="username"><input type="password" name="password"></form>'
    # spec 008 (RF-13): a guestbook whose entries are rendered on a per-entry page reachable
    # only after a post — so the stored-XSS re-crawl must find it. It carries a CSRF token so
    # the CSRF check stays quiet; the stored-XSS pass fuzzes the `body` field.
    '<form method="post" action="/guestbook">'
    '<input type="hidden" name="csrf_token" value="gbtok"><textarea name="body"></textarea></form>'
    # spec 014: a file-upload form the UploadScanner pass probes (opt-in --file-upload). It
    # carries a CSRF token so the passive CSRF check stays quiet.
    '<form method="post" action="/upload" enctype="multipart/form-data">'
    '<input type="hidden" name="csrf_token" value="uptok"><input type="file" name="avatar"></form>'
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
    f"{_FORMS}{_SPEC_013_INSECURE}"
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
# spec 011: the insecure /ping endpoint simulates a shell-out — it evaluates the arithmetic
# echo payload and, for a `sleep N` / `ping -n N` payload, blocks that long (bounded).
_CMDI_SLEEP_RE = re.compile(r"sleep (\d+)|ping -n (\d+)|timeout /t (\d+)", re.I)
_CMDI_ARITH_RE = re.compile(
    r"(wv[0-9a-f]+)=\$\(\((\d+)\*(\d+)\)\)|(wv[0-9a-f]+)&set /a (\d+)\*(\d+)", re.I
)

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


def _ping_insecure(request: Request) -> Response:
    raw = request.query_params.get("host", "")  # spec 011: os.system(f"ping -c1 {raw}")
    sleep = _CMDI_SLEEP_RE.search(raw)
    if sleep:
        time.sleep(min(int(next(g for g in sleep.groups() if g)), 6))
        return PlainTextResponse(f"PING {raw}: 1 packets transmitted")
    arith = _CMDI_ARITH_RE.search(raw)
    if arith and arith.group(1):  # POSIX  $((a*b))
        return PlainTextResponse(
            f"PING\n{arith.group(1)}={int(arith.group(2)) * int(arith.group(3))}\n"
        )
    if arith:  # Windows  set /a a*b
        return PlainTextResponse(
            f"PING\n{arith.group(4)}\n{int(arith.group(5)) * int(arith.group(6))}\n"
        )
    return PlainTextResponse(f"PING {raw}: 1 packets transmitted, 0 received")


def _greet_insecure(request: Request) -> Response:
    name = request.query_params.get("name", "")  # spec 011: name concatenated into the source
    try:
        body = jinja2.Template("<!doctype html><p>Hi " + name + "</p>").render()
    except jinja2.exceptions.TemplateError as exc:
        return PlainTextResponse(f"jinja2.exceptions.{type(exc).__name__}: {exc}", status_code=500)
    return HTMLResponse(body)


# --- spec 012: request-envelope endpoints (insecure) -----------------------------


def _set_lang_insecure(request: Request) -> Response:
    lang = unquote(request.query_params.get("lang", "en"))  # written raw into Set-Cookie
    response = PlainTextResponse(f"lang set to {lang.splitlines()[0] if lang else 'en'}")
    # Starlette/h11 reject a raw CRLF in a header value, so the fixture simulates a permissive
    # server: it parses the injected header line(s) out of the value and sets them as real,
    # valid headers (same "fixture simulates the sink" pattern as spec 006 SLEEP / spec 011).
    for line in lang.split("\r\n")[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            response.headers[key.strip()] = val.strip()
    response.headers["set-cookie"] = f"lang={lang.split(chr(13))[0]}"
    return response


def _reset_insecure(request: Request) -> Response:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    return HTMLResponse(
        f"<!doctype html><p>To reset your password, click "
        f'<a href="https://{host}/reset/confirm?token=abc123">this link</a>.</p>'
    )


async def _xml_insecure(request: Request) -> Response:
    body = (await request.body()).decode("utf-8", "replace")  # entity-resolving parser
    low = body.lower()
    if "file:///etc/passwd" in low or "file:///c:/windows" in low:
        return PlainTextResponse(_ETC_PASSWD)
    if "<!doctype" in low or "<!entity" in low:
        return PlainTextResponse(
            "lxml.etree.XMLSyntaxError: Entity 'xxe' not defined, line 1", status_code=500
        )
    return PlainTextResponse("ok")


def _resource_insecure(request: Request) -> Response:
    if request.method == "TRACE":
        echoed = "\r\n".join(f"{k}: {v}" for k, v in request.headers.items())
        return PlainTextResponse(f"TRACE {request.url.path} HTTP/1.1\r\n{echoed}")
    response = PlainTextResponse("the resource")
    response.headers["allow"] = "GET, POST, PUT, DELETE, TRACE, OPTIONS"
    return response


# --- spec 014: file upload + LDAP / XPath / SSI (insecure) -----------------------
# Every sink is faked offline and deterministically (the "fixture simulates the sink"
# pattern from spec 006 SLEEP / spec 011 shell / spec 012 CRLF). No real PHP / LDAP / XPath.

_CTYPE_BY_EXT = {
    ".html": "text/html",
    ".htm": "text/html",
    ".xhtml": "application/xhtml+xml",
    ".svg": "image/svg+xml",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".txt": "text/plain",
}
_LDAP_ALL_USERS = "\n".join(f"uid=user{i},ou=people,dc=demo" for i in range(120))
_LDAP_ONE_USER = "uid=jdoe,ou=people,dc=demo"
_XML_CATALOGUE = (
    "<book><title>Dune</title></book>",
    "<book><title>Neuromancer</title></book>",
    "<book><title>Snow Crash</title></book>",
)


def _guess_ctype(name: str) -> str:
    for ext, ctype in _CTYPE_BY_EXT.items():
        if name.lower().endswith(ext):
            return ctype
    return "application/octet-stream"


def _run_marker_script(body: bytes) -> bytes:
    text = body.decode("utf-8", "replace")  # collapse "marker:<?php echo A*B; ?>" to "marker:AB"
    match = re.search(r"echo (\d+)\*(\d+)|print\((\d+)\*(\d+)\)", text)
    if match is None:
        return body
    nums = [int(x) for x in match.groups() if x]
    return (text.split(":", 1)[0] + ":" + str(nums[0] * nums[1])).encode()


async def _upload_insecure(request: Request) -> Response:
    form = await request.form()
    field = next((v for v in form.values() if hasattr(v, "filename")), None)
    if field is None:
        return PlainTextResponse("no file", status_code=400)
    raw_name = getattr(field, "filename", None) or "file"
    name = raw_name.rsplit("/", 1)[-1].split("%00")[0]
    body = await field.read()  # type: ignore[union-attr]
    request.app.state.uploads[name] = body
    if "../" in raw_name or "..%2f" in raw_name.lower():
        request.app.state.root_uploads[name] = body  # traversal: also written at the web root
    return HTMLResponse(f'<a href="/files/{name}">saved</a>')


async def _files_insecure(request: Request) -> Response:
    name = request.path_params["name"]
    store = request.app.state.uploads
    if request.method == "PUT":
        store[name] = await request.body()
        return PlainTextResponse("created", status_code=201)
    body = store.get(name)
    if body is None:
        return PlainTextResponse("not found", status_code=404)
    if name.lower().endswith((".php", ".phtml", ".php5", ".jsp", ".asp", ".aspx")):
        return Response(_run_marker_script(body), media_type="text/html")  # "executed"
    return Response(body, media_type=_guess_ctype(name))  # served inline, no attachment


def _root_file_insecure(request: Request) -> Response:
    name = request.path_params["fname"]
    body = request.app.state.root_uploads.get(name)
    if body is None:
        return PlainTextResponse("not found", status_code=404)
    return Response(body, media_type=_guess_ctype(name))


def _dir_insecure(request: Request) -> Response:
    user = request.query_params.get("user", "")  # spliced into an LDAP filter
    if user.count("(") != user.count(")") and "=" not in user:
        return PlainTextResponse(
            "javax.naming.directory.InvalidSearchFilterException: Bad search filter",
            status_code=500,
        )
    return PlainTextResponse(_LDAP_ALL_USERS if "*" in user else _LDAP_ONE_USER)


def _xdoc_insecure(request: Request) -> Response:
    node = request.query_params.get("node", "")  # concatenated into an XPath expression
    if node.count("'") % 2 == 1 and " or " not in node.lower():
        return PlainTextResponse(
            "lxml.etree.XPathEvalError: Invalid expression, line 1", status_code=500
        )
    widened = "'1'='1" in node or "1=1" in node.replace(" ", "")
    return PlainTextResponse("\n".join(_XML_CATALOGUE if widened else _XML_CATALOGUE[:1]))


def _page_insecure(request: Request) -> Response:
    tpl = request.query_params.get("tpl", "")  # reflected into a page an SSI processor evaluates
    out = tpl.replace('<!--#echo var="DATE_LOCAL"-->', "Mon, 08 Sep 2026 12:00:00 GMT")
    out = out.replace(
        "<!--#printenv-->", "DOCUMENT_ROOT=/var/www\nHTTP_HOST=demo.test\nSERVER_SOFTWARE=Apache"
    )
    out = out.replace("<esi:vars>$(HTTP_HOST)</esi:vars>", "demo.test")
    out = re.sub(
        r'<!--#echo var="wv[0-9a-f]+"-->',
        "[an error occurred while processing this directive]",
        out,
    )
    return HTMLResponse(f"<!doctype html><div>{out}</div>")


# --- spec 014: the safe equivalents (hardened) ----------------------------------


async def _upload_hardened(request: Request) -> Response:
    form = await request.form()
    field = next((v for v in form.values() if hasattr(v, "filename")), None)
    allowed = (getattr(field, "filename", "") or "").lower().endswith((".png", ".jpg", ".jpeg"))
    if field is None or not allowed:
        return PlainTextResponse("file type not allowed", status_code=400)
    request.app.state.uploads[f"{int(time.time() * 1000)}.png"] = await field.read()  # type: ignore[union-attr]
    return PlainTextResponse("stored")


async def _files_hardened(request: Request) -> Response:
    if request.method == "PUT":
        return PlainTextResponse("Method Not Allowed", status_code=405)
    body = request.app.state.uploads.get(request.path_params["name"])
    if body is None:
        return PlainTextResponse("not found", status_code=404)
    response = Response(body, media_type="application/octet-stream")
    response.headers["content-disposition"] = "attachment"
    return response


def _dir_hardened(request: Request) -> Response:
    return PlainTextResponse(_LDAP_ONE_USER)  # parameterised lookup — payloads change nothing


def _xdoc_hardened(request: Request) -> Response:
    return PlainTextResponse(_XML_CATALOGUE[0])  # parameterised lookup


def _page_hardened(request: Request) -> Response:
    return HTMLResponse(
        f"<!doctype html><div>{html.escape(request.query_params.get('tpl', ''))}</div>"
    )


# --- spec 013: OpenAPI import -----------------------------------------------------
# The passive content / leakage checks are exercised from the insecure index page
# (_SPEC_013_INSECURE, above). These two operations are linked from no HTML page and are
# reached only via ``--openapi``.

_OPENAPI_DOC: dict[str, object] = {
    "openapi": "3.1.0",
    "servers": [{"url": "/"}],
    "paths": {
        "/api/find": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        "/api/items": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                        }
                    }
                }
            }
        },
    },
}


def _openapi_doc(request: Request) -> Response:
    return JSONResponse(_OPENAPI_DOC)


def _api_find_insecure(request: Request) -> Response:
    q = request.query_params.get("q", "")  # reflected unescaped
    return HTMLResponse(f"<!doctype html><h1>Matches for {q}</h1>")


def _api_find_hardened(request: Request) -> Response:
    q = html.escape(request.query_params.get("q", ""))
    return HTMLResponse(f"<!doctype html><h1>Matches for {q}</h1>")


async def _api_items(request: Request) -> Response:
    form = await request.form()
    return HTMLResponse(f"<!doctype html><p>created {html.escape(str(form.get('name', '')))}</p>")


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


def _ping_hardened(request: Request) -> Response:
    host = request.query_params.get("host", "")  # spec 011: validate, then pass as an argv item
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        return PlainTextResponse("invalid host", status_code=400)
    return PlainTextResponse(f"PING {host}: 1 packets transmitted")


def _greet_hardened(request: Request) -> Response:
    name = request.query_params.get("name", "")  # spec 011: name is template *data*, not source
    template = jinja2.Template("<!doctype html><p>Hi {{ name }}</p>", autoescape=True)
    return HTMLResponse(template.render(name=name))


# --- spec 012: the safe equivalents (hardened) -----------------------------------


def _set_lang_hardened(request: Request) -> Response:
    lang = request.query_params.get("lang", "en")
    lang = lang if lang in {"en", "pt", "es"} else "en"
    response = PlainTextResponse(f"lang set to {lang}")
    response.headers["set-cookie"] = f"lang={lang}; Secure; HttpOnly; SameSite=Lax; Path=/"
    return response


def _reset_hardened(request: Request) -> Response:
    return HTMLResponse(
        "<!doctype html><p>To reset your password, click "
        '<a href="https://app.example.com/reset/confirm?token=abc123">this link</a>.</p>'
    )


def _xml_hardened(request: Request) -> Response:
    return PlainTextResponse("DTDs are not permitted in this document", status_code=400)


def _resource_hardened(request: Request) -> Response:
    if request.method == "TRACE":
        return PlainTextResponse("Method Not Allowed", status_code=405)
    response = PlainTextResponse("the resource")
    response.headers["allow"] = "GET, POST, OPTIONS"
    return response


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
        ("/ping", _ping_insecure, ["GET"]),
        ("/greet", _greet_insecure, ["GET"]),
        ("/set-lang", _set_lang_insecure, ["GET"]),
        ("/reset", _reset_insecure, ["GET"]),
        ("/resource", _resource_insecure, ["GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS"]),
        ("/upload", _upload_insecure, ["POST"]),
        ("/files/{name}", _files_insecure, ["GET", "PUT"]),
        ("/dir", _dir_insecure, ["GET"]),
        ("/xdoc", _xdoc_insecure, ["GET"]),
        ("/page", _page_insecure, ["GET"]),
        ("/openapi.json", _openapi_doc, ["GET"]),
        ("/api/find", _api_find_insecure, ["GET"]),
        ("/api/items", _api_items, ["POST"]),
        ("/api/xml", _xml_insecure, ["POST"]),
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
        ("/ping", _ping_hardened, ["GET"]),
        ("/greet", _greet_hardened, ["GET"]),
        ("/set-lang", _set_lang_hardened, ["GET"]),
        ("/reset", _reset_hardened, ["GET"]),
        ("/resource", _resource_hardened, ["GET", "POST", "OPTIONS"]),
        ("/upload", _upload_hardened, ["POST"]),
        ("/files/{name}", _files_hardened, ["GET", "PUT"]),
        ("/dir", _dir_hardened, ["GET"]),
        ("/xdoc", _xdoc_hardened, ["GET"]),
        ("/page", _page_hardened, ["GET"]),
        ("/openapi.json", _openapi_doc, ["GET"]),
        ("/api/find", _api_find_hardened, ["GET"]),
        ("/api/items", _api_items, ["POST"]),
        ("/api/xml", _xml_hardened, ["POST"]),
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
    """
    Args:
        sink (list[str]): List each request line (``"<method> <path>?<query>"``)
            is appended to.

    Returns:
        Callable[[ASGIApp], ASGIApp]: Middleware that records every HTTP request
            into ``sink`` — the tests assert on what the scan actually sent.
    """

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
    """
    Build the target app in one of the two profiles.

    Args:
        profile (str): ``"insecure"`` for the vulnerable app (weak headers,
            reflected/stored sinks, exposed paths), anything else for the
            hardened equivalent.

    Returns:
        Starlette: The app; ``app.state.requests`` records every request and
            ``app.state.guestbook`` is reset per app for determinism.
    """
    is_insecure = profile == "insecure"
    handler = _insecure if is_insecure else _hardened
    requests: list[str] = []

    routes = [Route(path, handler) for path in ("/", "/about", "/contact")]
    routes.append(Route("/home", _home))
    routes += [Route(path, view, methods=m) for path, view, m in _INJECTION_ROUTES[profile]]
    routes.append(Route("/login", _login, methods=["GET", "POST"]))
    if is_insecure:
        routes += [Route(path, view) for path, view in _INSECURE_EXTRA_ROUTES]
        # spec 014: a catch-all so a traversal-named upload is retrievable at the web root.
        routes.append(Route("/{fname}", _root_file_insecure, methods=["GET"]))

    app = Starlette(routes=routes, middleware=[Middleware(_recorder(requests))])
    app.state.requests = requests
    app.state.guestbook = []  # spec 008: reset per app so the suite stays deterministic
    app.state.profile = ""
    app.state.uploads = {}  # spec 014: reset per app
    app.state.root_uploads = {}
    return app

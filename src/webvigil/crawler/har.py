"""
HAR import: turn browser-recorded traffic into seed operations (spec 021).

A HAR file (HTTP Archive, JSON) is what a browser's network panel or an intercepting proxy saves
after a walk through an application. It is the surface a single-page application builds in
JavaScript, which the crawler cannot see. :func:`load_har` reads one into the same
:class:`~webvigil.crawler.openapi.ApiOperation` records the OpenAPI importer returns, so the crawl
(GET seeds), the ``POST`` phase of spec 018 and the injection pass use them with no new path.

The importer reads a local file and sends nothing. It indexes only the fields it needs: the
request's method, URL and body, the resource type and the response ``mimeType`` (to recognise a
static asset), and the *names* of the request headers (to tell the scan that the recording looks
authenticated). It never reads the value of a header, a cookie, a response body or a timing, so a
session in the file cannot reach a finding, a report or a log line (ADR-3). The values it keeps are
sanitised first: a secret-named parameter and a blob become a placeholder, and a JSON body is
reduced to its shape (ADR-4).

Imports nothing from ``webvigil.checks``: the ``checks -> crawler`` dependency direction holds.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from webvigil.core.errors import HarError
from webvigil.core.target import Target
from webvigil.crawler.openapi import (
    _MAX_BODY_DEPTH,
    _MAX_BODY_KEYS,
    _MAX_BODY_UNITS,
    _SKIP_OPERATION_RE,
    ApiOperation,
    _Budget,
)
from webvigil.crawler.safety import looks_unsafe_operation

# ---------------------------------------------------------------------------
# Bounds (RNF-02, ADR-7): a HAR can come from a third party, so reading it must stay cheap
# ---------------------------------------------------------------------------

# The largest file read. A HAR with response bodies embedded is far larger than the requests it
# holds; the error names the fix (export without bodies). json.loads builds several times this in
# memory and the standard library has no streaming parser, so the file size is the bound.
_MAX_FILE_BYTES = 64 * 1024 * 1024

# Entries walked; a longer recording is cut with a warning, not refused.
_MAX_ENTRIES = 20_000

# Longest value, URL and parameter name kept. A longer value is a blob, not a baseline worth
# replaying; a longer URL or name is not a request a browser would make on purpose.
_MAX_VALUE = 256
_MAX_URL = 2048
_MAX_NAME = 128

# Parameters read from one query or form body, and the body text parsed for one entry.
_MAX_PARAMS = 100
_MAX_BODY_TEXT = 1024 * 1024

# What replaces a secret-named or oversized value: the placeholder ``--openapi`` uses for a string.
_PLACEHOLDER = "wv"

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

_METHODS = ("GET", "POST")

# Chrome's ``_resourceType``. A type not listed here is decided by the response mime type.
_DYNAMIC_TYPES = frozenset({"document", "xhr", "fetch", "ping", "eventsource", "other"})
_STATIC_TYPES = frozenset(
    {"image", "media", "font", "stylesheet", "script", "texttrack", "manifest"}
)

_STATIC_MIME_PREFIXES = ("image/", "font/", "audio/", "video/")
_STATIC_MIMES = frozenset(
    {
        "text/css",
        "text/javascript",
        "text/ecmascript",
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "application/wasm",
        "application/font-woff",
        "application/x-font-ttf",
        "application/vnd.ms-fontobject",
    }
)

# Last resort, when the entry has neither a resource type nor a mime type.
_STATIC_EXTENSIONS = (
    ".js",
    ".mjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".avif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp3",
    ".mp4",
    ".webm",
    ".wasm",
)

# Whole words of a parameter name that mark its value as a secret (RF-07 plus csrf, xsrf, pwd,
# apikey, authorization, credential and bearer: replacing a value costs a baseline, leaking one
# costs more). Matched after splitting camelCase and ``_`` / ``-`` / any non-alphanumeric.
_SECRET_WORDS = frozenset(
    {
        "token",
        "key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "authorization",
        "session",
        "sid",
        "jwt",
        "signature",
        "otp",
        "csrf",
        "xsrf",
        "credential",
        "bearer",
    }
)
_CAMEL_BREAK_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_WORD_RE = re.compile(r"[^a-z0-9]+")

# Header names that mean the recording was made while logged in (names only, ADR-3).
_SESSION_HEADERS = frozenset({"cookie", "authorization"})

_BOUNDARY_RE = re.compile(r'boundary="?([^";]+)"?', re.I)
_PART_NAME_RE = re.compile(r'(?:^|;)\s*name="([^"]*)"', re.I)
_PART_FILE_RE = re.compile(r"filename\s*=", re.I)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HarTally:
    """
    What the import did with each entry it read (RF-11).

    Attributes:
        entries (int): Entries read, after the entry cap.
        out_of_scope (int): Another host or scheme, or a URL that is not ``http`` / ``https``.
        static (int): An image, font, stylesheet, script, media file or source map.
        other_method (int): A method that is neither ``GET`` nor ``POST``.
        unsafe (int): A login, logout or state-changing path (``looks_unsafe_operation``).
        malformed (int): No usable request, URL or parameter name.
        duplicate (int): The same operation as one already kept.
        seeded_get (int): ``GET`` operations returned.
        seeded_post (int): ``POST`` operations returned.
    """

    entries: int = 0
    out_of_scope: int = 0
    static: int = 0
    other_method: int = 0
    unsafe: int = 0
    malformed: int = 0
    duplicate: int = 0
    seeded_get: int = 0
    seeded_post: int = 0


@dataclass(frozen=True, slots=True)
class HarImport:
    """
    The outcome of :func:`load_har`.

    Attributes:
        operations (list[ApiOperation]): The operations (``source="har"``), de-duplicated, stably
            ordered and capped.
        warnings (list[str]): Non-fatal notes: a cut entry list, a capped operation list, a file
            with nothing usable.
        tally (HarTally): The per-reason counts behind :meth:`summary`.
        authenticated (bool): An in-scope entry carried a ``Cookie`` or ``Authorization`` header
            (or recorded cookies). A fact about the file; no value of it is kept.
    """

    operations: list[ApiOperation]
    warnings: list[str] = field(default_factory=list)
    tally: HarTally = field(default_factory=HarTally)
    authenticated: bool = False

    def summary(self) -> str:
        """
        Returns:
            str: The one-line scan warning that lets "no finding" be told apart from "never
                imported" (RF-11); categories with a zero count are left out.
        """
        t = self.tally
        line = (
            f"HAR import: {_count(t.entries, 'entry', 'entries')} read, "
            f"{_count(len(self.operations), 'operation', 'operations')} seeded "
            f"({t.seeded_get} GET, {t.seeded_post} POST)"
        )
        ignored = [
            f"{count} {label}"
            for count, label in (
                (t.out_of_scope, "out of scope"),
                (t.static, "static"),
                (t.other_method, "other method"),
                (t.unsafe, "unsafe"),
                (t.malformed, "malformed"),
                (t.duplicate, "duplicate"),
            )
            if count
        ]
        return f"{line}; ignored: {', '.join(ignored)}" if ignored else line


def _count(n: int, one: str, many: str) -> str:
    """
    Args:
        n (int): A count.
        one (str): The singular noun.
        many (str): The plural noun.

    Returns:
        str: ``n`` and the noun in the right number.
    """
    return f"{n} {one if n == 1 else many}"


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_har(path: str, *, target: Target, max_operations: int) -> HarImport:
    """
    Load a HAR file into acted-on operations, reconciled against the target's scope.

    Args:
        path (str): A local file path (a ``.har`` or ``.json`` file).
        target (Target): The normalized target; its scope rule and scheme decide which entries
            are the target's.
        max_operations (int): Hard cap on the operations returned; the excess is a warning.

    Returns:
        HarImport: The operations, the warnings, the tally and the authenticated flag.

    Raises:
        HarError: If ``path`` is a URL, is not a readable file, is over the size cap, is not
            valid JSON, or is not a HAR document.
    """
    entries, warnings = _read_entries(path)
    tally = HarTally()
    authenticated = False
    kept: dict[tuple[Any, ...], ApiOperation] = {}
    scheme = urlsplit(target.origin).scheme

    for raw in entries:
        tally.entries += 1
        request = raw.get("request") if isinstance(raw, dict) else None
        parsed = _parse_request(request)
        if parsed is None:
            tally.malformed += 1
            continue
        method, parts = parsed
        if parts.scheme not in ("http", "https") or not parts.hostname:
            tally.out_of_scope += 1
            continue
        if parts.scheme != scheme or not target.in_scope(parts.geturl()):
            tally.out_of_scope += 1
            continue
        assert isinstance(request, dict)  # _parse_request returned a parse of it
        authenticated = authenticated or _looks_authenticated(request)
        if method not in _METHODS:
            tally.other_method += 1
            continue
        if _is_static(raw, parts.path):
            tally.static += 1
            continue
        operation = _operation(method, parts, request)
        if operation is None:
            tally.malformed += 1
            continue
        if _is_unsafe(operation):
            tally.unsafe += 1
            continue
        key = _key(operation)
        if key in kept:
            tally.duplicate += 1
            continue
        kept[key] = operation

    operations = sorted(
        kept.values(),
        key=lambda op: (op.url_template, op.method, tuple(name for name, _ in op.query)),
    )
    if len(operations) > max_operations:
        warnings.append(
            f"HAR import seeded the first {max_operations} of {len(operations)} operations"
        )
        operations = operations[:max_operations]
    if not operations:
        warnings.append("HAR file contained no usable in-scope GET or POST operations")
    tally.seeded_get = sum(1 for op in operations if op.method == "GET")
    tally.seeded_post = len(operations) - tally.seeded_get
    return HarImport(operations, warnings, tally, authenticated)


def _read_entries(path: str) -> tuple[list[Any], list[str]]:
    """
    Read and validate the file, returning the entries to walk.

    Args:
        path (str): The source given to ``--har``.

    Returns:
        tuple[list[Any], list[str]]: The first ``_MAX_ENTRIES`` entries and the warnings that
            cutting the list produced.

    Raises:
        HarError: For a URL, a missing or oversized file, undecodable or invalid JSON, or a
            document without ``log.entries``.
    """
    if "://" in path:
        raise HarError(f"--har takes a local file, not a URL: {path}")
    source = Path(path)
    if not source.is_file():
        raise HarError(f"HAR file not found: {path}")
    try:
        size = source.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise HarError(
                f"{path} is {size // (1024 * 1024)} MiB, over the {_MAX_FILE_BYTES // 2**20} MiB "
                "limit: export the HAR without response bodies"
            )
        doc = json.loads(source.read_bytes().decode("utf-8-sig"))
    except OSError as exc:
        raise HarError(f"could not read {path}: {exc}") from exc
    except (ValueError, RecursionError) as exc:  # includes UnicodeDecodeError / JSONDecodeError
        raise HarError(f"{path} is not a HAR file: not valid JSON ({type(exc).__name__})") from exc
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise HarError(f"{path} is not a HAR file: no log.entries")
    warnings: list[str] = []
    if len(entries) > _MAX_ENTRIES:
        warnings.append(f"HAR import read the first {_MAX_ENTRIES} of {len(entries)} entries")
        entries = entries[:_MAX_ENTRIES]
    return entries, warnings


# ---------------------------------------------------------------------------
# One entry
# ---------------------------------------------------------------------------


def _parse_request(request: Any) -> tuple[str, Any] | None:
    """
    Args:
        request (Any): The entry's ``request`` value.

    Returns:
        tuple[str, SplitResult] | None: The upper-cased method and the split URL, or ``None``
            when the request is not a mapping with a string method and URL, or the URL is
            unparsable or longer than ``_MAX_URL`` (a ``data:`` or ``ws:`` URL is judged by its
            scheme first, so it is out of scope, not malformed).
    """
    if not isinstance(request, dict):
        return None
    method, url = request.get("method"), request.get("url")
    if not isinstance(method, str) or not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  # raises ValueError for a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() in ("http", "https") and len(url) > _MAX_URL:
        return None
    return method.upper(), parts


def _is_unsafe(operation: ApiOperation) -> bool:
    """
    Args:
        operation (ApiOperation): A built operation.

    Returns:
        bool: ``True`` when its path looks like authentication or a state-changing action
            (RF-09): the vocabulary of the OpenAPI importer (``checkout``, ``pay``, ``order`` ...)
            or of the ``POST`` phase's safety filter (``delete``, ``logout``, ``password`` ...).
    """
    path = urlsplit(operation.url_template).path
    return bool(_SKIP_OPERATION_RE.search(path)) or looks_unsafe_operation(operation)


def _looks_authenticated(request: dict[str, Any]) -> bool:
    """
    Args:
        request (dict[str, Any]): An in-scope entry's ``request``.

    Returns:
        bool: ``True`` when it has a ``Cookie`` or ``Authorization`` header or recorded cookies.
            Only header *names* and the length of the cookie list are looked at (ADR-3).
    """
    headers = request.get("headers")
    if isinstance(headers, list):
        for header in headers:
            name = header.get("name") if isinstance(header, dict) else None
            if isinstance(name, str) and name.lower() in _SESSION_HEADERS:
                return True
    cookies = request.get("cookies")
    return isinstance(cookies, list) and len(cookies) > 0


def _is_static(entry: dict[str, Any], path: str) -> bool:
    """
    Whether an entry fetched a static asset (RF-04): the browser's resource type, else the
    response mime type, else the URL extension. Only those fields are indexed (ADR-3).

    Args:
        entry (dict[str, Any]): The HAR entry.
        path (str): The request URL's path.

    Returns:
        bool: ``True`` for an image, font, media, stylesheet, script, manifest or source map.
    """
    lowered = path.lower()
    if lowered.endswith(".map"):
        return True
    resource_type = entry.get("_resourceType")
    if isinstance(resource_type, str):
        kind = resource_type.lower()
        if kind in _DYNAMIC_TYPES:
            return False
        if kind in _STATIC_TYPES:
            return True
    response = entry.get("response")
    content = response.get("content") if isinstance(response, dict) else None
    mime = content.get("mimeType") if isinstance(content, dict) else None
    if isinstance(mime, str) and mime.strip():
        main = mime.split(";")[0].strip().lower()
        return main.startswith(_STATIC_MIME_PREFIXES) or main in _STATIC_MIMES
    return lowered.endswith(_STATIC_EXTENSIONS)


def _operation(method: str, parts: Any, request: dict[str, Any]) -> ApiOperation | None:
    """
    Build the operation for one in-scope, acted-on entry.

    Args:
        method (str): ``"GET"`` or ``"POST"``.
        parts (SplitResult): The split request URL.
        request (dict[str, Any]): The entry's ``request``.

    Returns:
        ApiOperation | None: The operation (``source="har"``), or ``None`` when a parameter name
            is empty or longer than ``_MAX_NAME`` or the query has too many parameters.
    """
    host = parts.hostname or ""
    host = f"[{host}]" if ":" in host else host
    port = parts.port
    default = 443 if parts.scheme == "https" else 80
    netloc = f"{host}:{port}" if port is not None and port != default else host
    url = urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))
    try:
        query = _pairs(parse_qsl(parts.query, keep_blank_values=True, max_num_fields=_MAX_PARAMS))
    except ValueError:
        return None
    if query is None:
        return None
    body_fields: tuple[tuple[str, str], ...] = ()
    body_json: str | None = None
    if method == "POST":
        body = _body(request.get("postData"))
        if body is None:
            return None
        body_fields, body_json = body
    return ApiOperation(
        method=method,
        url=url,
        url_template=url,
        query=query,
        path_params=(),
        body_fields=body_fields,
        body_json=body_json,
        operation_id="",
        source="har",
    )


def _pairs(raw: list[tuple[str, str]]) -> tuple[tuple[str, str], ...] | None:
    """
    Args:
        raw (list[tuple[str, str]]): Recorded ``(name, value)`` pairs.

    Returns:
        tuple[tuple[str, str], ...] | None: The pairs with every value sanitised, or ``None`` when
            a name is empty or longer than ``_MAX_NAME``.
    """
    out: list[tuple[str, str]] = []
    for name, value in raw[:_MAX_PARAMS]:
        if not name or len(name) > _MAX_NAME:
            return None
        out.append((name, _scrub(name, value)))
    return tuple(out)


def _body(
    post: Any,
) -> tuple[tuple[tuple[str, str], ...], str | None] | None:
    """
    Read a recorded ``POST`` body (RF-06).

    Args:
        post (Any): The entry's ``request.postData``.

    Returns:
        tuple[tuple[tuple[str, str], ...], str | None] | None: ``(form fields, JSON shape)`` with
            at most one of them non-empty, both empty for a body kind that is not imported, or
            ``None`` when a field name is unusable.
    """
    if not isinstance(post, dict):
        return (), None
    mime = post.get("mimeType")
    kind = mime.split(";")[0].strip().lower() if isinstance(mime, str) else ""
    text = post.get("text")
    text = text if isinstance(text, str) and len(text) <= _MAX_BODY_TEXT else ""
    if kind == "application/json" or kind.endswith("+json"):
        return (), _json_shape(text)
    raw: list[tuple[str, str]]
    if kind == "application/x-www-form-urlencoded":
        raw = _recorded_params(post.get("params"))
        if not raw and text:
            try:
                raw = parse_qsl(text, keep_blank_values=True, max_num_fields=_MAX_PARAMS)
            except ValueError:
                return None
    elif kind == "multipart/form-data":
        raw = _recorded_params(post.get("params")) or _multipart_text_parts(
            text, mime if isinstance(mime, str) else ""
        )
    else:
        return (), None
    fields = _pairs(raw)
    return None if fields is None else (fields, None)


def _recorded_params(params: Any) -> list[tuple[str, str]]:
    """
    Args:
        params (Any): A HAR ``postData.params`` value.

    Returns:
        list[tuple[str, str]]: ``(name, value)`` for every text parameter; a part that has a
            ``fileName`` is a file, not a parameter, and is dropped.
    """
    out: list[tuple[str, str]] = []
    if not isinstance(params, list):
        return out
    for item in params[:_MAX_PARAMS]:
        if not isinstance(item, dict) or item.get("fileName") is not None:
            continue
        name, value = item.get("name"), item.get("value")
        if isinstance(name, str):
            out.append((name, value if isinstance(value, str) else ""))
    return out


def _multipart_text_parts(text: str, mime: str) -> list[tuple[str, str]]:
    """
    Read the text parts out of a raw ``multipart/form-data`` body.

    Args:
        text (str): The recorded body text.
        mime (str): The recorded ``mimeType``, which carries the boundary.

    Returns:
        list[tuple[str, str]]: ``(name, value)`` for every part that has a name and no
            ``filename``; empty when there is no boundary.
    """
    match = _BOUNDARY_RE.search(mime)
    if not match or not text:
        return []
    out: list[tuple[str, str]] = []
    for chunk in text.split(f"--{match.group(1)}")[1 : _MAX_PARAMS + 1]:
        head, sep, value = chunk.lstrip("\r\n").partition("\r\n\r\n")
        if not sep:
            head, sep, value = chunk.lstrip("\r\n").partition("\n\n")
        disposition = next(
            (line for line in head.splitlines() if line.lower().startswith("content-disposition")),
            "",
        )
        name = _PART_NAME_RE.search(disposition)
        if name is None or _PART_FILE_RE.search(disposition):
            continue
        out.append((name.group(1), value.rstrip("\r\n-")))
    return out


# ---------------------------------------------------------------------------
# Sanitising (RF-07, ADR-4)
# ---------------------------------------------------------------------------


def _is_secret_name(name: str) -> bool:
    """
    Args:
        name (str): A query or form parameter name.

    Returns:
        bool: ``True`` when a whole word of the name (after splitting camelCase and any
            non-alphanumeric break, with an optional plural ``s``) is a secret word: ``token``,
            ``access_token``, ``accessToken``, ``X-Api-Key``; not ``tokenizer`` or ``monkey``.
    """
    words = _NON_WORD_RE.split(_CAMEL_BREAK_RE.sub(" ", name).lower())
    return any(word in _SECRET_WORDS or word.rstrip("s") in _SECRET_WORDS for word in words)


def _scrub(name: str, value: str) -> str:
    """
    Args:
        name (str): The parameter name.
        value (str): The recorded value.

    Returns:
        str: ``value``, or the placeholder when the name is secret-like or the value is longer
            than ``_MAX_VALUE``.
    """
    if len(value) > _MAX_VALUE or _is_secret_name(name):
        return _PLACEHOLDER
    return value


def _json_shape(text: str) -> str | None:
    """
    Reduce a recorded JSON body to its shape: its structure with typed placeholders (RF-06).

    Args:
        text (str): The body text.

    Returns:
        str | None: The shape as JSON text, or ``None`` when the text is not a JSON object or
            array (invalid, ``null``, a bare scalar, nested too deeply to parse).
    """
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict | list):
        return None
    return json.dumps(_shape(value, _Budget(_MAX_BODY_UNITS), 0))


def _shape(node: Any, budget: _Budget, depth: int) -> Any:
    """
    Args:
        node (Any): A parsed JSON value.
        budget (_Budget): The size allowance of this body; a node or key past it is left out.
        depth (int): Current recursion depth.

    Returns:
        Any: ``node``'s structure with every leaf replaced by a typed placeholder: a string by
            ``"wv"``, a number by ``1``, a boolean by ``true``; an array keeps one element's
            shape; an object keeps its first keys within the depth, breadth and size bounds.
    """
    if isinstance(node, bool):
        return True
    if isinstance(node, int | float):
        return 1
    if isinstance(node, str):
        return _PLACEHOLDER
    if not isinstance(node, dict | list):
        return None
    if depth >= _MAX_BODY_DEPTH or not budget.take(1):
        return {}
    if isinstance(node, list):
        return [_shape(node[0], budget, depth + 1)] if node else []
    out: dict[str, Any] = {}
    for name, value in list(node.items())[:_MAX_BODY_KEYS]:
        if len(name) > _MAX_NAME or not budget.take(1 + len(name)):
            continue
        out[name] = _shape(value, budget, depth + 1)
    return out


# ---------------------------------------------------------------------------
# Identity and merging
# ---------------------------------------------------------------------------


def _key(op: ApiOperation) -> tuple[Any, ...]:
    """
    Args:
        op (ApiOperation): An operation.

    Returns:
        tuple[Any, ...]: Its identity for de-duplication: method, URL template, the names of its
            query and form fields, and its JSON shape. Recorded *values* are not part of it
            (RF-05).
    """
    return (
        op.method,
        op.url_template,
        tuple(name for name, _ in op.query),
        tuple(name for name, _ in op.body_fields),
        op.body_json,
    )


def merge_operations(
    primary: list[ApiOperation] | tuple[ApiOperation, ...],
    secondary: list[ApiOperation] | tuple[ApiOperation, ...],
) -> list[ApiOperation]:
    """
    Combine two operation lists, the first winning on a tie (RF-01).

    Args:
        primary (list[ApiOperation] | tuple[ApiOperation, ...]): Kept whole (the OpenAPI list).
        secondary (list[ApiOperation] | tuple[ApiOperation, ...]): Appended where its identity
            (method, URL template, parameter names, body shape) is not already in ``primary``.

    Returns:
        list[ApiOperation]: ``primary`` followed by the new operations of ``secondary``.
    """
    seen = {_key(op) for op in primary}
    merged = list(primary)
    for op in secondary:
        key = _key(op)
        if key not in seen:
            seen.add(key)
            merged.append(op)
    return merged


__all__ = ["HarImport", "HarTally", "load_har", "merge_operations"]

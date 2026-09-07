"""Injection-point enumeration and the fuzz / skip heuristics (spec 006, RF-04, RF-06).

Points come from two places, parsed from data the crawler already has: query-string
parameters on discovered URLs, and fuzzable fields of discovered forms. Forms that look
like authentication or destruction are dropped here (RF-04) — the crawler reported them,
this module decides what to do with them.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from webvigil.checks.injection.models import InjectionPoint
from webvigil.core.context import Page
from webvigil.crawler.forms import Form

# Input types worth putting a payload in. Everything else (hidden, submit, checkbox,
# radio, file, password, select, ...) is submitted with its discovered value but not fuzzed.
_FUZZ_TYPES = frozenset({"", "text", "search", "email", "url", "tel", "number", "textarea"})

# A form whose action / field names match this is never fuzzed (RF-04). Best-effort — a
# login form at /session slips through; documented in docs/active-injection.md.
_EXCLUDE_FORM_RE = re.compile(
    r"log[\s_-]?in|log[\s_-]?out|log[\s_-]?off|sign[\s_-]?in|sign[\s_-]?out|sign[\s_-]?up|"
    r"register|delete|remove|destroy|\bdrop\b|password|passwd|\breset\b|checkout|\bpay\b|"
    r"purchase|\border\b|transfer|unsubscribe|deactivate",
    re.I,
)

# Parameters the open-redirect / traversal detectors try first, within budget.
_PREFERRED_REDIRECT = frozenset(
    {
        "next",
        "url",
        "redirect",
        "redirect_uri",
        "redir",
        "return",
        "returnurl",
        "return_to",
        "dest",
        "destination",
        "continue",
        "to",
        "goto",
        "target",
        "out",
        "link",
    }
)
_PATHLIKE_NAMES = frozenset(
    {
        "file",
        "filename",
        "path",
        "page",
        "doc",
        "document",
        "template",
        "tpl",
        "include",
        "inc",
        "dir",
        "folder",
        "download",
        "attachment",
        "load",
        "read",
    }
)
_PATHLIKE_VALUE = re.compile(r"[/\\]|\.\w{1,5}$")

# Parameters the SSRF detector (spec 009) tries first — names that usually carry a URL the
# server will fetch, or a value that already looks like one.
_URLLIKE_NAMES = frozenset(
    {
        "url",
        "uri",
        "u",
        "link",
        "src",
        "source",
        "href",
        "dest",
        "destination",
        "callback",
        "webhook",
        "hook",
        "feed",
        "rss",
        "proxy",
        "fetch",
        "load",
        "remote",
        "image",
        "img",
        "avatar",
        "photo",
        "import",
        "upload",
        "document",
        "file",
        "target",
        "to",
        "out",
        "next",
        "continue",
        "return",
        "redirect",
        "redirect_uri",
        "site",
        "domain",
        "host",
        "server",
        "path",
        "page",
        "view",
        "data",
        "json",
        "xml",
        "api",
        "endpoint",
        "resource",
        "content",
        "preview",
        "open",
        "download",
    }
)
_URLLIKE_VALUE = re.compile(r"^\s*(?:https?:)?//|\bhttps?://|://|^\s*www\.", re.I)


def _base_of(url: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    parts = urlsplit(url)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return base, tuple(parse_qsl(parts.query, keep_blank_values=True))


def enumerate_points(
    pages: tuple[Page, ...], forms: tuple[Form, ...], *, max_points: int
) -> tuple[list[InjectionPoint], list[str]]:
    """Return the injection points to test (stably ordered, capped) plus any cap warning."""
    seen: set[str] = set()
    points: list[InjectionPoint] = []

    for page in pages:
        if not page.ok:
            continue
        base, pairs = _base_of(page.requested_url)
        for name, value in pairs:
            point = InjectionPoint("GET", base, name, value, pairs, source="query")
            if point.key not in seen:
                seen.add(point.key)
                points.append(point)

    for form in forms:
        blob = form.action + " " + " ".join(f.name for f in form.fields)
        if _EXCLUDE_FORM_RE.search(blob):
            continue
        base, query = _base_of(form.action)
        fields = tuple((f.name, f.value) for f in form.fields)
        for field in form.fields:
            if field.type not in _FUZZ_TYPES:
                continue
            point = InjectionPoint(
                form.method, base, field.name, field.value, fields, query=query, source="form"
            )
            if point.key not in seen:
                seen.add(point.key)
                points.append(point)

    points.sort(key=lambda p: (p.base_url, p.param, p.method))
    warnings: list[str] = []
    if len(points) > max_points:
        warnings.append(
            f"active injection tested the first {max_points} of {len(points)} injection points"
        )
        points = points[:max_points]
    return points, warnings


def is_redirect_name(point: InjectionPoint) -> bool:
    return point.param.lower() in _PREFERRED_REDIRECT


def is_pathlike(point: InjectionPoint) -> bool:
    return point.param.lower() in _PATHLIKE_NAMES or bool(_PATHLIKE_VALUE.search(point.original))


def is_urllike(point: InjectionPoint) -> bool:
    return point.param.lower() in _URLLIKE_NAMES or bool(_URLLIKE_VALUE.search(point.original))


def build_request(
    point: InjectionPoint, value: str
) -> tuple[str, str, list[tuple[str, str]], dict[str, str] | None]:
    """The ``(method, url, params, data)`` to replay ``point`` with ``value`` in its slot.

    Shared by the reflected-injection engine (spec 006) and the stored-XSS pass (spec 008).
    """
    fuzzed = [(name, value if name == point.param else current) for name, current in point.params]
    if point.method == "GET":
        return "GET", point.base_url, fuzzed, None
    # httpx wants a Mapping for a urlencoded form body; a pair list takes its raw-content path.
    return "POST", point.base_url, list(point.query), dict(fuzzed)

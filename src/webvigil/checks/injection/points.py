"""
Injection-point enumeration and the fuzz / skip heuristics (spec 006, RF-04, RF-06).

Points come from two places, parsed from data the crawler already has:
query-string parameters on discovered URLs, and fuzzable fields of discovered
forms. Forms that look like authentication or destruction are dropped here
(RF-04) — the crawler reported them, this module decides what to do with them.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from webvigil.checks.injection.models import InjectionPoint
from webvigil.core.context import Page
from webvigil.crawler.forms import Form
from webvigil.crawler.openapi import ApiOperation

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

# Parameters the command-injection / SSTI detectors (spec 011) front-load. Kept off the
# most generic names (``q`` / ``search`` / ``query``) so the fast 006 detectors are not
# starved on every search box; ``cmdi`` / ``ssti`` still run on those points from the base
# order, budget permitting. Name-only: a command / template sink rarely has a telltale
# value.
_COMMANDLIKE_NAMES = frozenset(
    {
        "cmd",
        "command",
        "exec",
        "execute",
        "run",
        "ping",
        "host",
        "hostname",
        "ip",
        "addr",
        "dns",
        "lookup",
        "shell",
        "system",
        "process",
        "proc",
        "arg",
        "args",
        "argv",
        "option",
        "opt",
        "flags",
        "name",
        "template",
        "tpl",
        "tmpl",
        "twig",
        "jinja",
        "render",
        "view",
        "engine",
        "preview",
        "greeting",
        "code",
        "eval",
        "expr",
        "expression",
    }
)

# The narrower subset whose name specifically suggests an OS shell — only these trigger the
# command-injection detector's full echo payload set and its (slower) time-based stage. A
# ``name`` / ``template`` sink is front-loaded for SSTI but is not shell-shaped.
_SHELL_NAMES = frozenset(
    {
        "cmd",
        "command",
        "exec",
        "execute",
        "run",
        "ping",
        "host",
        "hostname",
        "ip",
        "addr",
        "dns",
        "lookup",
        "shell",
        "system",
        "process",
        "proc",
        "arg",
        "args",
        "argv",
        "option",
        "opt",
        "flags",
    }
)


def _base_of(url: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        tuple[str, tuple[tuple[str, str], ...]]: The URL with its query
            stripped, and the parsed query pairs (blank values kept).
    """
    parts = urlsplit(url)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return base, tuple(parse_qsl(parts.query, keep_blank_values=True))


def enumerate_points(
    pages: tuple[Page, ...],
    forms: tuple[Form, ...],
    operations: tuple[ApiOperation, ...] = (),
    *,
    max_points: int,
) -> tuple[list[InjectionPoint], list[str]]:
    """
    Enumerate the injection points to test.

    Query parameters from every OK page, fuzzable fields of every form that is
    not auth- or destruction-shaped, and the query / path / form-body parameters
    of every ``--openapi`` operation (spec 013) — de-duplicated by
    :attr:`InjectionPoint.key` (an operation parameter the crawl already found
    is one point), sorted, and capped at ``max_points``.

    Args:
        pages (tuple[Page, ...]): The crawled pages.
        forms (tuple[Form, ...]): The parsed form inventory.
        operations (tuple[ApiOperation, ...]): Operations from an OpenAPI import.
            Defaults to empty.
        max_points (int): Hard cap on the number of points returned.

    Returns:
        tuple[list[InjectionPoint], list[str]]: The points (stably ordered,
            capped) and a one-item warning list when the cap truncated them.
    """
    seen: set[str] = set()
    points: list[InjectionPoint] = []

    for page in pages:
        if not page.ok:
            continue
        base, pairs = _base_of(page.requested_url)
        for name, value in pairs:
            _add(InjectionPoint("GET", base, name, value, pairs, source="query"), seen, points)

    for form in forms:
        blob = form.action + " " + " ".join(f.name for f in form.fields)
        if _EXCLUDE_FORM_RE.search(blob):
            continue
        base, query = _base_of(form.action)
        fields = tuple((f.name, f.value) for f in form.fields)
        for field in form.fields:
            if field.type not in _FUZZ_TYPES:
                continue
            _add(
                InjectionPoint(
                    form.method, base, field.name, field.value, fields, query=query, source="form"
                ),
                seen,
                points,
            )

    for operation in operations:
        for point in _operation_points(operation):
            _add(point, seen, points)

    points.sort(key=lambda p: (p.base_url, p.param, p.method))
    warnings: list[str] = []
    if len(points) > max_points:
        warnings.append(
            f"active injection tested the first {max_points} of {len(points)} injection points"
        )
        points = points[:max_points]
    return points, warnings


def _add(point: InjectionPoint, seen: set[str], points: list[InjectionPoint]) -> None:
    """
    Append ``point`` unless one with the same :attr:`InjectionPoint.key` is already present.

    Args:
        point (InjectionPoint): The candidate point.
        seen (set[str]): The keys already added, updated in place.
        points (list[InjectionPoint]): The accumulating list, appended in place.
    """
    if point.key not in seen:
        seen.add(point.key)
        points.append(point)


def _operation_points(operation: ApiOperation) -> list[InjectionPoint]:
    """
    Synthesize the injection points of one OpenAPI operation (spec 013 RF-09).

    A GET operation contributes its query parameters; a POST operation its
    form-urlencoded body fields (its query parameters ride along unfuzzed as
    :attr:`InjectionPoint.query` so the endpoint stays reachable). Both
    contribute their path parameters as ``"openapi-path"`` points that
    :func:`build_request` substitutes into the URL template.

    Args:
        operation (ApiOperation): The operation to expand.

    Returns:
        list[InjectionPoint]: Zero or more points, all ``source`` ``"openapi"``
            or ``"openapi-path"``.
    """
    out: list[InjectionPoint] = []
    if operation.method == "GET":
        for name, value in operation.query:
            out.append(
                InjectionPoint("GET", operation.url, name, value, operation.query, source="openapi")
            )
    else:
        for name, value in operation.body_fields:
            out.append(
                InjectionPoint(
                    "POST",
                    operation.url,
                    name,
                    value,
                    operation.body_fields,
                    query=operation.query,
                    source="openapi",
                )
            )
    for name, value in operation.path_params:
        out.append(
            InjectionPoint(
                operation.method,
                operation.url_template,
                name,
                value,
                operation.path_params,
                source="openapi-path",
            )
        )
    return out


def is_redirect_name(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name is one the open-redirect detector
            should try first.
    """
    return point.param.lower() in _PREFERRED_REDIRECT


def is_pathlike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the name or current value looks like a file path —
            the traversal detector front-loads these.
    """
    return point.param.lower() in _PATHLIKE_NAMES or bool(_PATHLIKE_VALUE.search(point.original))


def is_urllike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the name or current value looks like a URL the
            server would fetch — the SSRF detector front-loads these and sends
            its full payload set only for them.
    """
    return point.param.lower() in _URLLIKE_NAMES or bool(_URLLIKE_VALUE.search(point.original))


def is_commandlike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name looks like it feeds a shell
            command or a template — the command-injection and SSTI detectors
            front-load these and send their full payload set only for them.
    """
    return point.param.lower() in _COMMANDLIKE_NAMES


def is_shell_param(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name specifically suggests an OS shell
            — the command-injection detector sends its full echo set and runs its
            time-based stage only for these (spec 011).
    """
    return point.param.lower() in _SHELL_NAMES


# Parameters whose value commonly lands in a *response header* — a redirect, a language
# cookie, a filename in Content-Disposition (spec 012). The CRLF detector front-loads these.
_HEADERLIKE_NAMES = frozenset(
    {
        "url",
        "redirect",
        "redirect_uri",
        "redir",
        "next",
        "return",
        "returnurl",
        "return_to",
        "goto",
        "dest",
        "destination",
        "continue",
        "to",
        "out",
        "link",
        "callback",
        "lang",
        "language",
        "locale",
        "region",
        "country",
        "currency",
        "market",
        "site",
        "ref",
        "referer",
        "referrer",
        "source",
        "utm_source",
        "filename",
        "file",
        "name",
        "download",
        "attachment",
        "title",
        "id",
        "page",
        "view",
    }
)


def is_headerlike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name is one whose value often reaches a
            response header — the CRLF detector front-loads these and sends its
            full payload set only for them (spec 012).
    """
    return point.param.lower() in _HEADERLIKE_NAMES


# Parameters whose value commonly lands in an LDAP search filter, an XPath expression, or a
# page an SSI/ESI processor evaluates (spec 014). Kept deliberately narrow — a front-loaded
# detector on a generic name (``id`` / ``q`` / ``name``) crowds the per-point budget and
# starves the slow ``sqli-time`` detector. Each of ``ldap`` / ``xpath`` / ``ssi`` still runs
# on any point from ``_BASE_ORDER``, budget permitting; these lists only re-prioritise the
# points where that detector is the likely find.
_LDAPLIKE_NAMES = frozenset(
    {
        "user",
        "username",
        "uid",
        "cn",
        "dn",
        "sn",
        "givenname",
        "ou",
        "member",
        "memberof",
        "principal",
        "samaccountname",
        "distinguishedname",
    }
)
_XPATHLIKE_NAMES = frozenset(
    {
        "xpath",
        "xpq",
        "xml",
        "xquery",
        "xsl",
        "xslt",
        "node",
        "nodeset",
        "xnode",
        "xexpr",
        "xmlfilter",
    }
)
_SSILIKE_NAMES = frozenset(
    {
        "ssi",
        "shtml",
        "include",
        "file",
        "page",
        "tpl",
        "template",
        "tmpl",
        "partial",
        "fragment",
        "snippet",
    }
)


def is_ldaplike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name looks like it feeds an LDAP search
            filter — the LDAP detector front-loads these (spec 014).
    """
    return point.param.lower() in _LDAPLIKE_NAMES


def is_xpathlike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name looks like it feeds an XPath /
            XQuery expression — the XPath detector front-loads these (spec 014).
    """
    return point.param.lower() in _XPATHLIKE_NAMES


def is_ssilike(point: InjectionPoint) -> bool:
    """
    Args:
        point (InjectionPoint): The point to classify.

    Returns:
        bool: ``True`` when the parameter name looks like it is reflected into a
            page an SSI / ESI processor evaluates — the SSI detector front-loads
            these (spec 014).
    """
    return point.param.lower() in _SSILIKE_NAMES


def build_request(
    point: InjectionPoint, value: str
) -> tuple[str, str, list[tuple[str, str]], dict[str, str] | None]:
    """
    Build the request to replay ``point`` with ``value`` in its slot.

    Shared by the reflected-injection engine (spec 006) and the stored-XSS pass
    (spec 008).

    Args:
        point (InjectionPoint): The point to replay.
        value (str): The value to place in the point's parameter.

    Returns:
        tuple[str, str, list[tuple[str, str]], dict[str, str] | None]: The
            ``(method, url, params, data)`` — for a GET, ``data`` is ``None`` and
            ``params`` carries the fuzzed pairs; for a POST, ``params`` carries
            the action's own query and ``data`` the fuzzed body. For an
            ``"openapi-path"`` point the payload is substituted into the ``{name}``
            URL template and neither ``params`` nor ``data`` is set (spec 013).
    """
    if point.source == "openapi-path":
        url = point.base_url
        for name, current in point.params:
            replacement = value if name == point.param else current
            url = url.replace("{" + name + "}", quote(replacement, safe=""))
        return point.method, url, [], None

    fuzzed = [(name, value if name == point.param else current) for name, current in point.params]
    if point.method == "GET":
        return "GET", point.base_url, fuzzed, None
    # httpx wants a Mapping for a urlencoded form body; a pair list takes its raw-content path.
    return "POST", point.base_url, list(point.query), dict(fuzzed)

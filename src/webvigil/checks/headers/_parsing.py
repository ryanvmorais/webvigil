"""Shared header-parsing helpers for the header/cookie/CORS checks."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from webvigil.core.context import Page
from webvigil.core.findings import EvidenceItem

# The cookie attributes of RFC 6265bis, and the ones browsers or older standards still read
# (RFC 2965, CHIPS, Chrome's ``Priority``). Any other segment after the pair is not an attribute.
_COOKIE_ATTRIBUTES = frozenset(
    {
        "expires",
        "max-age",
        "domain",
        "path",
        "secure",
        "httponly",
        "samesite",
        "partitioned",
        "priority",
        "comment",
        "commenturl",
        "version",
        "port",
        "discard",
    }
)

# A cookie folded into an attribute after a comma (``Path=/, sid=abc``). A date's comma
# (``Expires=Wed, 21 Oct 2026 07:28:00 GMT``) is followed by no ``name=``.
_FOLDED_PAIR_RE = re.compile(r"(,[ \t]*[^=;,\s]{1,256})=[^;,]*")


def header_value(page: Page, name: str) -> str | None:
    """
    Case-insensitive single header lookup.

    Args:
        page (Page): The response to read from.
        name (str): Header name; matched case-insensitively.

    Returns:
        str | None: The header value, or ``None`` when absent.
    """
    return page.headers.get(name)


def is_https(url: str) -> bool:
    """
    Args:
        url (str): An absolute URL.

    Returns:
        bool: ``True`` when the scheme is ``https``.
    """
    return urlsplit(url).scheme.lower() == "https"


def response_headers_evidence(page: Page, *, only: tuple[str, ...] = ()) -> EvidenceItem:
    """
    Build an evidence blob of the response headers.

    Args:
        page (Page): The response whose headers to render.
        only (tuple[str, ...]): When given, restrict the blob to these header
            names (case-insensitive).

    Returns:
        EvidenceItem: A ``"response headers"`` item, one line per header field, with
            every ``Set-Cookie`` value masked (see :func:`mask_set_cookie`); its
            content notes when none of the relevant headers are present.
    """
    items = page.headers.multi_items()
    if only:
        wanted = {name.lower() for name in only}
        items = [(k, v) for k, v in items if k.lower() in wanted]
    rendered = "\n".join(
        f"{k}: {mask_set_cookie(v) if k.lower() == 'set-cookie' else v}" for k, v in items
    )
    return EvidenceItem.of("response headers", rendered or "(none of the relevant headers present)")


def mask_set_cookie(raw: str) -> str:
    """
    Hide the value of one ``Set-Cookie`` header value, keeping its name and attributes.

    The target issued the value, so the scan cannot know it is not a session token;
    the name and the attributes are what a finding about the cookie needs to show.

    A browser reads a pair without ``=`` as a value with no name (RFC 6265bis, section 5.6),
    so it is masked whole. An attribute the cookie standards do not define is another pair
    written into the same line (a framework that joined two), and a ``name=value`` after a
    comma inside an attribute is a second cookie folded into the line by a proxy
    (``Path=/, sid=abc``): their values are masked too.

    Args:
        raw (str): One raw ``Set-Cookie`` header value.

    Returns:
        str: ``raw`` with the value of its ``name=value`` pair replaced by ``***``
            (``sid=abc; Path=/`` becomes ``sid=***; Path=/``), and so the value of every
            other pair in the line; a pair with an empty value is kept as it is.
    """
    pair, sep, attributes = raw.partition(";")
    name, equals, value = pair.partition("=")
    if not equals:
        pair = "***" if pair.strip() else pair
    elif value.strip():
        pair = f"{name}=***"
    segments = [_mask_attribute(segment) for segment in attributes.split(";")] if sep else []
    return f"{pair}{sep}{';'.join(segments)}"


def _mask_attribute(segment: str) -> str:
    """
    Args:
        segment (str): One ``;``-separated segment after a cookie's pair, spaces included.

    Returns:
        str: The segment as it is when it is a known attribute, with a folded cookie's value
            masked; ``name=***``, or ``***`` for a bare word, when it is not an attribute.
    """
    key, equals, _ = segment.strip().partition("=")
    if not key and not equals:
        return segment
    if key.strip().lower() not in _COOKIE_ATTRIBUTES:
        indent = segment[: len(segment) - len(segment.lstrip())]
        return f"{indent}{key.strip()}=***" if equals else f"{indent}***"
    return _FOLDED_PAIR_RE.sub(lambda match: f"{match[1]}=***", segment)


def parse_csp(value: str) -> dict[str, list[str]]:
    """
    Parse a Content-Security-Policy value into ``{directive: [tokens]}``.

    Args:
        value (str): The raw header value.

    Returns:
        dict[str, list[str]]: Directive name (lower-cased) to its token list.
    """
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def parse_set_cookie(raw: str) -> tuple[str, dict[str, str | bool]]:
    """
    Parse one ``Set-Cookie`` value into ``(name, attributes)``.

    Args:
        raw (str): One raw ``Set-Cookie`` header value.

    Returns:
        tuple[str, dict[str, str | bool]]: The cookie name and its attributes.
            Flag attributes (``Secure``, ``HttpOnly``) map to ``True``; valued
            attributes (``SameSite``, ``Domain``, ``Path``) map to their string
            value. Attribute keys are lower-cased. A pair without ``=`` has no name
            (the text is its value), and an unparseable value yields ``("", {})``.
    """
    segments = [segment.strip() for segment in raw.split(";") if segment.strip()]
    if not segments:
        return "", {}
    name, equals, _ = segments[0].partition("=")
    name = name.strip() if equals else ""
    attributes: dict[str, str | bool] = {}
    for segment in segments[1:]:
        if "=" in segment:
            key, _, val = segment.partition("=")
            attributes[key.strip().lower()] = val.strip()
        else:
            attributes[segment.strip().lower()] = True
    return name, attributes

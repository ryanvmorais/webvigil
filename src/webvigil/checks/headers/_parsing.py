"""Shared header-parsing helpers for the header/cookie/CORS checks."""

from __future__ import annotations

from typing import cast
from urllib.parse import urlsplit

from webvigil.core.context import Page
from webvigil.core.findings import EvidenceItem


def header_value(page: Page, name: str) -> str | None:
    """
    Case-insensitive single header lookup.

    Args:
        page (Page): The response to read from.
        name (str): Header name; matched case-insensitively.

    Returns:
        str | None: The header value, or ``None`` when absent.
    """
    return cast("str | None", page.headers.get(name))


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

    Args:
        raw (str): One raw ``Set-Cookie`` header value.

    Returns:
        str: ``raw`` with the value of its ``name=value`` pair replaced by ``***``
            (``sid=abc; Path=/`` becomes ``sid=***; Path=/``); a pair with an empty
            value, or without ``=``, is kept as it is.
    """
    pair, sep, attributes = raw.partition(";")
    name, equals, value = pair.partition("=")
    if equals and value.strip():
        pair = f"{name}=***"
    return f"{pair}{sep}{attributes}"


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
            value. Attribute keys are lower-cased. An unparseable value yields
            ``("", {})``.
    """
    segments = [segment.strip() for segment in raw.split(";") if segment.strip()]
    if not segments:
        return "", {}
    name = segments[0].split("=", 1)[0].strip()
    attributes: dict[str, str | bool] = {}
    for segment in segments[1:]:
        if "=" in segment:
            key, _, val = segment.partition("=")
            attributes[key.strip().lower()] = val.strip()
        else:
            attributes[segment.strip().lower()] = True
    return name, attributes

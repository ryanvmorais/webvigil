"""Shared header-parsing helpers for the header/cookie/CORS checks."""

from __future__ import annotations

from typing import cast
from urllib.parse import urlsplit

from webvigil.core.context import Page
from webvigil.core.findings import EvidenceItem


def header_value(page: Page, name: str) -> str | None:
    """Case-insensitive single header lookup."""
    return cast("str | None", page.headers.get(name))


def is_https(url: str) -> bool:
    return urlsplit(url).scheme.lower() == "https"


def response_headers_evidence(page: Page, *, only: tuple[str, ...] = ()) -> EvidenceItem:
    """An evidence blob of the response headers (optionally a subset)."""
    items = list(page.headers.items())
    if only:
        wanted = {name.lower() for name in only}
        items = [(k, v) for k, v in items if k.lower() in wanted]
    rendered = "\n".join(f"{k}: {v}" for k, v in items) or "(none of the relevant headers present)"
    return EvidenceItem.of("response headers", rendered)


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy value into ``{directive: [tokens]}`` (lowercased keys)."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def parse_set_cookie(raw: str) -> tuple[str, dict[str, str | bool]]:
    """Parse one ``Set-Cookie`` value into ``(name, attributes)``.

    Flag attributes (``Secure``, ``HttpOnly``) map to ``True``; valued attributes
    (``SameSite``, ``Domain``, ``Path``) map to their string value (attribute keys lowercased).
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

"""
``is_http_url``, the predicate that decides whether a reference becomes a link — issue #161 —
and ``resolve_url``, which follows a link the scanned site wrote.

Pure string logic: no I/O, nothing mocked. The accepted values are what a check or an advisory
legitimately carries; the rejected ones are the schemes and tricks a third-party record could use
to make a click run code (``javascript:``, ``data:``), plus the browser quirks that make a value
look like something else (a tab or newline inside the scheme is dropped by a browser).
"""

from __future__ import annotations

import pytest

from webvigil.core.urls import is_http_url, resolve_url


@pytest.mark.parametrize(
    "value",
    [
        "https://example.org/ref",
        "http://example.org/ref?a=1&b=2#frag",
        "HTTPS://EXAMPLE.ORG/",
        "https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2",
        "http://127.0.0.1:8000/docs",
    ],
)
def test_an_absolute_http_url_is_a_link(value: str) -> None:
    """An ``http`` or ``https`` URL with a host may be rendered as a link."""
    assert is_http_url(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "java\tscript:alert(1)",  # a browser drops the tab and reads javascript:
        "java\nscript:alert(1)",
        "\x01javascript:alert(1)",
        " https://example.org/",
        "https://example.org/a b",
        "https://",
        "https:///path",
        "//example.org/path",
        "/relative/path",
        "ftp://example.org/file",
        "mailto:someone@example.org",
        "http://[::1",  # urlsplit raises ValueError on this one
        "",
        "http:example.org/path",  # a browser resolves it against the current page
        "https://example.org/" + chr(0x9B) + "x",  # C1: a terminal reads it as CSI
        "https://example.org/" + chr(0x202E) + "fdp.exe",  # reads as another address
        "https://exa" + chr(0x200B) + "mple.org/",
    ],
)
def test_anything_else_is_not_a_link(value: str) -> None:
    """
    Another scheme, a relative or scheme-relative value, a missing host or a stray control,
    whitespace, bidirectional or invisible character is rejected; a malformed URL does not raise.
    """
    assert is_http_url(value) is False


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("/next", "https://example.com/next"),
        ("other", "https://example.com/dir/other"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("", "https://example.com/dir/page"),
    ],
)
def test_resolve_url_joins_like_a_browser(ref: str, expected: str) -> None:
    """A relative, absolute or empty reference resolves against the page URL."""
    assert resolve_url("https://example.com/dir/page", ref) == expected


@pytest.mark.parametrize(
    "ref",
    ["http://[::1", "http://[not-an-ip]/", "https://example.com:99999/", "https://example.com:x/"],
)
def test_resolve_url_gives_up_on_a_malformed_reference(ref: str) -> None:
    """An unclosed bracket, a bad IPv6 literal or a bad port is ``None``, never an exception."""
    assert resolve_url("https://example.com/", ref) is None

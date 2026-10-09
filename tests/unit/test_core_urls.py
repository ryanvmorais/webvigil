"""
``is_http_url``, the predicate that decides whether a reference becomes a link — issue #161.

Pure string logic: no I/O, nothing mocked. The accepted values are what a check or an advisory
legitimately carries; the rejected ones are the schemes and tricks a third-party record could use
to make a click run code (``javascript:``, ``data:``), plus the browser quirks that make a value
look like something else (a tab or newline inside the scheme is dropped by a browser).
"""

from __future__ import annotations

import pytest

from webvigil.core.urls import is_http_url


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
    ],
)
def test_anything_else_is_not_a_link(value: str) -> None:
    """Another scheme, a relative or scheme-relative value, a missing host or a stray control
    or whitespace character is rejected; a malformed URL does not raise."""
    assert is_http_url(value) is False

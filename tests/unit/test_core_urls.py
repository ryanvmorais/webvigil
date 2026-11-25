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

from webvigil.core.urls import (
    HIDDEN_ADDRESS,
    HIDDEN_PATH,
    UNREADABLE_URL,
    display_path,
    display_url,
    has_userinfo,
    is_http_url,
    resolve_url,
)


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
    ("ref", "expected"),
    [
        ("/\\other.example/x", "https://other.example/x"),
        ("\\\\other.example/x", "https://other.example/x"),
        ("\\/other.example/x", "https://other.example/x"),
        ("https:\\\\other.example/x", "https://other.example/x"),
        ("HTTPS:\\\\other.example/x", "https://other.example/x"),
        ("\thttps:\\\\other.example/x", "https://other.example/x"),
        ("a\\b", "https://example.com/dir/a/b"),
    ],
)
def test_resolve_url_reads_a_backslash_as_a_slash_like_a_browser(ref: str, expected: str) -> None:
    r"""In an ``http(s)`` URL a backslash before the query is a slash: ``/\host`` is off-site."""
    assert resolve_url("https://example.com/dir/page", ref) == expected


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("/a?q=b\\c", "https://example.com/a?q=b\\c"),
        ("/a#b\\c", "https://example.com/a#b\\c"),
        ("/a\\b?q=c\\d#e\\f", "https://example.com/a/b?q=c\\d#e\\f"),
        ("mailto:a\\b", "mailto:a\\b"),
        ("javascript:a\\b", "javascript:a\\b"),
        # the scheme is read as a browser reads it: past a leading space, through a tab
        (" mailto:a\\b", "mailto:a\\b"),
        ("mail\tto:a\\b", "mailto:a\\b"),
    ],
)
def test_resolve_url_keeps_a_backslash_where_a_browser_keeps_it(ref: str, expected: str) -> None:
    """The query and the fragment keep theirs, and so does a URL whose scheme is not ``http(s)``."""
    assert resolve_url("https://example.com/dir/page", ref) == expected


@pytest.mark.parametrize(
    "ref",
    ["http://[::1", "http://[not-an-ip]/", "https://example.com:99999/", "https://example.com:x/"],
)
def test_resolve_url_gives_up_on_a_malformed_reference(ref: str) -> None:
    """An unclosed bracket, a bad IPv6 literal or a bad port is ``None``, never an exception."""
    assert resolve_url("https://example.com/", ref) is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/a/b", "https://example.com/a/b"),
        ("https://example.com", "https://example.com"),
        ("http://example.com:8080/a", "http://example.com:8080/a"),
        ("https://user:pw@example.com/a", "https://example.com/a"),
        ("https://user@example.com:8443/a", "https://example.com:8443/a"),
        ("https://example.com/a?token=x", "https://example.com/a"),
        ("https://example.com/a#frag", "https://example.com/a"),
        ("https://u:p@[::1]:8000/a?b=c#d", "https://[::1]:8000/a"),
        ("https://example.com:8443/a/b;sid=x", "https://example.com:8443/a/b"),
        ("https://example.com/a;sid=x/b", "https://example.com/a/b"),
        ("https://example.com/a;x=1/b;y=2;z=3/c;w", "https://example.com/a/b/c"),
        ("https://example.com/;sid=x", "https://example.com/"),
        ("https://example.com/a//b/%3Bc/d.e-f_g~h/", "https://example.com/a//b/%3Bc/d.e-f_g~h/"),
    ],
)
def test_display_url_keeps_only_what_a_message_may_repeat(url: str, expected: str) -> None:
    """Scheme, host, valid port and path; no userinfo, query, fragment or parameter."""
    assert display_url(url) == expected


@pytest.mark.parametrize(
    ("url", "scheme"),
    [
        ("https://user:mark/er@example.com/a", "https"),
        ("http://user:mark/er@example.com/a", "http"),
        ("https://user:123/marker@example.com:8443/a", "https"),
        ("https://user:123?marker@example.com/a", "https"),
        ("https://user:123#marker@example.com/a", "https"),
        ("https://user:marker@example.com:bad/a", "https"),
        ("https://example.com:notaport/a", "https"),
        ("https://example.com:99999/a", "https"),
        ("https://example.com/users/@marker", "https"),
    ],
    ids=[
        "delimiter-in-password",
        "scheme-is-kept",
        "number-before-the-delimiter",
        "question-mark-in-password",
        "hash-in-password",
        "bad-port-after-userinfo",
        "port-not-a-number",
        "port-out-of-range",
        "at-sign-in-the-path",
    ],
)
def test_display_url_hides_an_address_it_cannot_trust(url: str, scheme: str) -> None:
    """Nothing but the scheme and a fixed marker: no host, port, path or part of a password."""
    assert display_url(url) == f"{scheme}://{HIDDEN_ADDRESS}"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com:8443/users/profile", "https://example.com:8443/users/profile"),
        ("https://user:marker@example.com/users", "https://example.com/users"),
        ("https://example.com/a%40b", "https://example.com/a%40b"),
    ],
    ids=["normal-path", "userinfo-in-the-authority", "escaped-at-sign"],
)
def test_display_url_still_shows_an_address_it_can_trust(url: str, expected: str) -> None:
    """The control of the test above: a clean authority and path are shown as they are."""
    assert display_url(url) == expected


@pytest.mark.parametrize(
    "url",
    ["user:pw@example.com", "example.com/a", "https://", "https://user:pw@/", "http://[::1", ""],
)
def test_display_url_repeats_nothing_of_a_value_it_cannot_read(url: str) -> None:
    """Without a scheme and a host the value may be anything, so none of it is shown."""
    assert display_url(url) == UNREADABLE_URL


@pytest.mark.parametrize("path", ["spec.json", "./api/spec.json", r"C:\specs\spec.json"])
def test_display_path_repeats_a_plain_file_path(path: str) -> None:
    """A path that holds no URL delimiter is what the user needs to see."""
    assert display_path(path) == path


@pytest.mark.parametrize(
    "path",
    ["user:pw@host/doc", "host/doc?token=x", "host/doc#x", "host/doc;sid=x/y"],
    ids=["userinfo", "query", "fragment", "parameter"],
)
def test_display_path_hides_what_may_be_a_url_without_its_scheme(path: str) -> None:
    """Each delimiter alone is enough to hide the whole value."""
    assert display_path(path) == HIDDEN_PATH


# A credential in a URL is refused where the URL comes in (spec 024, RF-09).
_USERINFO_URLS = [
    "https://user@example.com/",
    "https://user:pass@example.com/",
    "https://:pass@example.com/",
    "https://@example.com/",
    "https://user:s\u00e9nha-\u5bc6\u7801@example.com/",
    "//user:pass@example.com/",
    # ``urlsplit`` refuses these hosts; the credential in front of them is still seen
    "https://user:pass@[::1/",
    "https://@[::1/",
    "//user:pass@[::1/",
    "https://user@exa\uff03mple.com/",
    " https://user:pass@[::1/",
    "https:/\t/user:pass@[::1/",
]
_NO_USERINFO_URLS = [
    "https://example.com/users/@me",
    "https://example.com/?mail=a@b.example",
    "https://example.com/#a@b",
    "https://example.com/a%40b",
    "https://[::1/users/@me",
    "https://[::1?mail=a@b.example",
    "https://[::1#a@b",
    "https:@example.com/",
    "./specs/@team/openapi.json",
    r"C:\specs\team@b.json",
    "/account/@me",
]


@pytest.mark.parametrize("url", _USERINFO_URLS)
def test_has_userinfo_sees_any_at_sign_in_the_authority(url: str) -> None:
    assert has_userinfo(url)


@pytest.mark.parametrize("url", _NO_USERINFO_URLS)
def test_has_userinfo_leaves_an_at_sign_outside_the_authority(url: str) -> None:
    """Positive controls: an ``@`` after the authority, or encoded, is not a credential."""
    assert not has_userinfo(url)

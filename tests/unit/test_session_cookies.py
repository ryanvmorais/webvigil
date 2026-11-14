"""
Session-looking cookies — spec 020 RF-02.

One definition of "a session cookie" (by name), JWT-shaped values skipped, and the extraction of
the session ids out of a response's ``Set-Cookie`` lines. Pure functions over strings and
``httpx.Headers``: no network.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from webvigil.checks.session.cookies import (
    MAX_ATTRIBUTE_VALUE_OCTETS,
    MAX_NAME_VALUE_OCTETS,
    cookie_attribute,
    cookie_pair,
    is_jwt,
    is_session_cookie,
    session_cookies,
)


def _b64(obj: object) -> str:
    """
    Args:
        obj (object): A JSON-serialisable value.

    Returns:
        str: Its JSON as unpadded base64url.
    """
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


_JWT = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': '1'})}.c2lnbmF0dXJl"

_NAMES = [
    ("session", True),
    ("SESSIONID", True),
    ("JSESSIONID", True),
    ("PHPSESSID", True),
    ("ASP.NET_SessionId", True),
    ("connect.sid", True),
    ("laravel_session", True),
    ("sid", True),
    ("auth_token", True),
    ("access-token", True),
    ("jwt", True),
    ("lang", False),
    ("theme", False),
    ("pre", False),
    ("welcome", False),
    ("ticket", False),
]


@pytest.mark.parametrize(("name", "expected"), _NAMES)
def test_a_session_cookie_is_recognised_by_its_name(name: str, expected: bool) -> None:
    """The framework names and the generic words match; ordinary cookies do not."""
    assert is_session_cookie(name) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (_JWT, True),
        ("abc.def.ghi", False),  # three segments, but the first is not a JSON header
        ("a1b2c3d4e5f60718", False),
        ("only.two", False),
        ("", False),
        (f"{_b64([1, 2])}.{_b64({})}.sig", False),  # the header decodes to a list, not an object
        ("not base64!.x.y", False),
    ],
)
def test_a_jwt_is_recognised_by_its_shape_only(value: str, expected: bool) -> None:
    """Three base64url segments with a JSON-object header: enough to skip it, nothing more."""
    assert is_jwt(value) is expected


def test_session_cookies_reads_every_set_cookie_line_and_skips_what_is_not_an_id() -> None:
    """Session-looking names only, in header order; a JWT, an empty value and junk are dropped."""
    headers = httpx.Headers(
        [
            ("set-cookie", "PHPSESSID=abc123def; Path=/; HttpOnly"),
            ("set-cookie", "lang=en; Path=/"),
            ("set-cookie", f"auth_token={_JWT}; Path=/"),  # a signed token, not a random id
            ("set-cookie", "session=; Max-Age=0"),  # a deletion carries no value
            ("set-cookie", "sid=9f8e7d; Secure"),
            ("set-cookie", "\x00\x01 not a cookie"),
        ]
    )

    assert session_cookies(headers) == [("PHPSESSID", "abc123def"), ("sid", "9f8e7d")]


def test_a_cookie_whose_name_and_value_pass_the_browser_limit_is_ignored() -> None:
    """Past ``MAX_NAME_VALUE_OCTETS`` a browser drops the cookie, and so does the check."""
    at_limit = "b" * (MAX_NAME_VALUE_OCTETS - len("session"))
    headers = httpx.Headers(
        [
            ("set-cookie", "sid=" + "a" * MAX_NAME_VALUE_OCTETS),
            ("set-cookie", f"session={at_limit}"),
        ]
    )
    assert session_cookies(headers) == [("session", at_limit)]


def test_long_attributes_do_not_hide_a_session_cookie() -> None:
    """Attributes a browser ignores, however long, leave the cookie readable."""
    junk = "; x=" + "q" * 50_000
    headers = httpx.Headers([("set-cookie", f"sid=abc123{junk}; Path=/")])
    assert session_cookies(headers) == [("sid", "abc123")]


def test_the_pair_is_counted_in_octets() -> None:
    """A multi-byte value counts every octet it takes."""
    value = "\u00e9" * (MAX_NAME_VALUE_OCTETS // 2)  # two octets each in UTF-8
    assert cookie_pair(f"s={value}") is None
    assert cookie_pair("s=" + "e" * (MAX_NAME_VALUE_OCTETS - 1)) is not None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("sid=a; Path=/; SameSite=Lax", "Lax", id="present"),
        pytest.param("sid=a; Path=/", None, id="absent"),
        pytest.param("sid=a; samesite=None; SameSite=Strict", "Strict", id="last-wins"),
        pytest.param("sid=a; Secure", None, id="other-flag"),
        pytest.param(
            "sid=a; SameSite=Lax; SameSite=" + "x" * (MAX_ATTRIBUTE_VALUE_OCTETS + 1),
            "Lax",
            id="too-long-is-ignored",
        ),
    ],
)
def test_an_attribute_is_read_as_a_browser_reads_it(raw: str, expected: str | None) -> None:
    """The last one wins, case does not matter, and a value past the limit is ignored."""
    assert cookie_attribute(raw, "SameSite") == expected


def test_a_response_without_cookies_has_no_session_ids() -> None:
    """No ``Set-Cookie`` header, no ids."""
    assert session_cookies(httpx.Headers({"content-type": "text/html"})) == []


def test_a_jwt_shaped_value_with_a_deeply_nested_header_is_not_a_jwt() -> None:
    """A header nested past the JSON parser's depth is rejected, not raised."""
    header = base64.urlsafe_b64encode(b"[" * 200_000).decode().rstrip("=")
    assert is_jwt(f"{header}.e30.sig") is False

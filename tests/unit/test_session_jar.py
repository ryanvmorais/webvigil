"""
SessionJar — the cookie jar behind an automated login — spec 019 RF-07.

Responses are built by hand (``httpx2.Response`` with a ``Set-Cookie`` header and its request)
and fed to ``absorb``; ``pairs_for`` is the observable: the cookies a request to a URL would
carry. No network, no transport: the jar is the standard ``http.cookiejar`` rules behind a
small wrapper, and these tests pin the wrapper (the two modes, the host rule, the value list)
and the rules the login depends on (``Secure``, ``Path``, expiry, odd hosts).
"""

from __future__ import annotations

import httpx2
import pytest

from webvigil.http.session import (
    _MAX_JAR_COOKIES,
    _MAX_SCRUB_VALUES,
    _MAX_VARIANTS_PER_NAME,
    SessionJar,
    cookie_bytes,
    jar_text,
    readable_cookie,
)

_URL = "http://demo.test/signin"


def _response(url: str, *set_cookie: str) -> httpx2.Response:
    """
    Args:
        url (str): The URL the response answers; becomes the response's request.
        *set_cookie (str): One ``Set-Cookie`` header value per argument.

    Returns:
        httpx2.Response: A 200 carrying those headers.
    """
    headers = [("set-cookie", value) for value in set_cookie]
    return httpx2.Response(200, headers=headers, request=httpx2.Request("GET", url))


def _committed(jar: SessionJar, url: str, *set_cookie: str) -> None:
    """
    Args:
        jar (SessionJar): The jar under test.
        url (str): The URL the (single) handshake response answers.
        *set_cookie (str): The ``Set-Cookie`` values that response carries.
    """
    jar.begin()
    jar.absorb(_response(url, *set_cookie), handshake=True)
    jar.commit()


# ---------------------------------------------------------------------------
# The two modes
# ---------------------------------------------------------------------------


def test_a_handshake_collects_every_hop_and_commit_makes_it_live() -> None:
    """Cookies from each hop go to the pending jar, are sent on the next hop, and commit."""
    jar = SessionJar("demo.test")
    jar.begin()
    jar.absorb(_response(_URL, "pre=1; Path=/"), handshake=True)
    jar.absorb(_response("http://demo.test/signin/done", "sid=abc; Path=/"), handshake=True)

    assert sorted(jar.pairs_for(_URL, handshake=True)) == [("pre", "1"), ("sid", "abc")]
    assert jar.pairs_for(_URL, handshake=False) == []  # nothing is live before the commit
    jar.commit()
    assert sorted(jar.pairs_for(_URL, handshake=False)) == [("pre", "1"), ("sid", "abc")]
    assert jar.names == {"pre", "sid"}


def test_live_mode_takes_a_rotation_and_drops_every_other_cookie() -> None:
    """After the login only a cookie whose name the session holds is accepted."""
    jar = SessionJar("demo.test")
    _committed(jar, _URL, "sid=one; Path=/")

    jar.absorb(
        _response("http://demo.test/a", "sid=two; Path=/", "tracker=x; Path=/"), handshake=False
    )

    assert jar.pairs_for("http://demo.test/a", handshake=False) == [("sid", "two")]


def test_a_failed_handshake_leaves_the_live_session_untouched() -> None:
    """``rollback`` discards the pending jar; the committed session keeps working."""
    jar = SessionJar("demo.test")
    _committed(jar, _URL, "sid=keep; Path=/")

    jar.begin()
    jar.absorb(_response(_URL, "sid=other; Path=/"), handshake=True)
    jar.rollback()

    assert jar.pairs_for(_URL, handshake=False) == [("sid", "keep")]
    with pytest.raises(RuntimeError):
        jar.commit()  # nothing to commit any more


def test_every_value_that_enters_the_jar_is_remembered_for_scrubbing() -> None:
    """``values`` keeps the pre-login cookie, the session and each rotation."""
    jar = SessionJar("demo.test")
    jar.begin()
    jar.absorb(_response(_URL, "pre=v-pre; Path=/", "sid=v-one; Path=/"), handshake=True)
    jar.commit()
    jar.absorb(_response(_URL, "sid=v-two; Path=/"), handshake=False)

    assert jar.values == {"v-pre", "v-one", "v-two"}


# ---------------------------------------------------------------------------
# Which cookies a request carries
# ---------------------------------------------------------------------------

# (Set-Cookie value, URL the cookie was set from, URL requested, cookies expected)
_RULES = [
    ("sid=a; Path=/", "http://demo.test/x", "http://demo.test/y", [("sid", "a")]),
    # Secure: the browser never sends it over http, and sends it over https
    ("sid=a; Path=/; Secure", "https://demo.test/x", "http://demo.test/y", []),
    ("sid=a; Path=/; Secure", "https://demo.test/x", "https://demo.test/y", [("sid", "a")]),
    # Path scoping
    ("sid=a; Path=/app", "http://demo.test/app/x", "http://demo.test/app/y", [("sid", "a")]),
    ("sid=a; Path=/app", "http://demo.test/app/x", "http://demo.test/other", []),
    # expiry: Max-Age=0 clears a cookie the same handshake set earlier
    ("sid=; Max-Age=0; Path=/", "http://demo.test/x", "http://demo.test/y", []),
    # host-only: a host the cookie was not set for gets nothing
    ("sid=a; Path=/", "http://demo.test/x", "http://other.test/y", []),
    # hosts with no dot or an IP literal still round-trip
    ("sid=a; Path=/", "http://localhost/x", "http://localhost/y", [("sid", "a")]),
    ("sid=a; Path=/", "http://127.0.0.1/x", "http://127.0.0.1/y", [("sid", "a")]),
]


@pytest.mark.parametrize(("set_cookie", "set_from", "requested", "expected"), _RULES)
def test_the_browser_rules_decide_which_cookies_a_request_carries(
    set_cookie: str, set_from: str, requested: str, expected: list[tuple[str, str]]
) -> None:
    """Secure, Path, expiry and the host rule, each through one handshake."""
    host = httpx2.URL(requested).host
    jar = SessionJar(host)
    jar.begin()
    if "Max-Age=0" in set_cookie:  # set it first, then clear it, as a login does with `pre`
        jar.absorb(_response(set_from, "sid=a; Path=/"), handshake=True)
    jar.absorb(_response(set_from, set_cookie), handshake=True)
    assert jar.pairs_for(requested, handshake=True) == expected


def test_cookies_are_sent_to_the_target_host_only() -> None:
    """Whatever the jar holds, a request to another host carries nothing."""
    jar = SessionJar("demo.test")
    _committed(jar, _URL, "sid=a; Path=/")

    assert jar.pairs_for("http://evil.test/", handshake=False) == []
    assert jar.pairs_for("http://sub.demo.test/", handshake=False) == []


# ---------------------------------------------------------------------------
# A Secure cookie over plain http (spec 020)
# ---------------------------------------------------------------------------


def test_a_secure_cookie_set_over_http_is_refused_like_a_browser_does() -> None:
    """It neither enters the handshake jar nor replaces the live session cookie."""
    jar = SessionJar("demo.test")
    jar.begin()
    jar.absorb(_response(_URL, "sid=one; Path=/", "tracker=t; Path=/; Secure"), handshake=True)
    jar.commit()
    assert jar.pairs_for(_URL, handshake=False) == [("sid", "one")]

    jar.absorb(_response(_URL, "sid=two; Path=/; Secure; HttpOnly"), handshake=False)
    assert jar.pairs_for(_URL, handshake=False) == [
        ("sid", "one")
    ]  # the Secure rotation is refused

    jar.absorb(_response(_URL, "sid=three; Path=/", "other=x; Secure"), handshake=False)
    assert jar.pairs_for(_URL, handshake=False) == [("sid", "three")]  # a plain one still rotates


def test_the_same_secure_cookie_over_https_is_accepted() -> None:
    """Over ``https`` the rule does not apply."""
    jar = SessionJar("demo.test")
    jar.begin()
    jar.absorb(_response("https://demo.test/signin", "sid=one; Path=/; Secure"), handshake=True)
    jar.commit()
    assert jar.pairs_for("https://demo.test/", handshake=False) == [("sid", "one")]


# ---------------------------------------------------------------------------
# What the target can make the jar hold (security audit 2026-11)
# ---------------------------------------------------------------------------


def test_a_held_name_keeps_a_bounded_number_of_path_variants() -> None:
    """Rotations under many paths do not grow the live jar past the per-name limit."""
    jar = SessionJar("demo.test")
    _committed(jar, _URL, "sid=one; Path=/")
    for i in range(200):
        jar.absorb(_response(_URL, f"sid=v{i}; Path=/p{i}"), handshake=False)
    assert sum(1 for _ in jar._live.jar) == _MAX_VARIANTS_PER_NAME


def test_a_handshake_keeps_a_bounded_number_of_cookies() -> None:
    """A login response that sets hundreds of cookies leaves at most the jar limit pending."""
    jar = SessionJar("demo.test")
    jar.begin()
    jar.absorb(_response(_URL, *(f"c{i}=x{i}; Path=/" for i in range(300))), handshake=True)
    jar.commit()
    assert len(jar.names) == _MAX_JAR_COOKIES


def test_endless_rotation_gives_the_session_up() -> None:
    """Past the scrub limit the jar stops sending the session, so no unscrubbed value leaves."""
    jar = SessionJar("demo.test")
    _committed(jar, _URL, "sid=first; Path=/")
    for i in range(1_100):
        jar.absorb(_response(_URL, f"sid=value{i}; Path=/"), handshake=False)
    assert jar.overflowed
    assert jar.pairs_for(_URL, handshake=False) == []
    assert len(jar.values) == _MAX_SCRUB_VALUES + 1  # the value that went past the limit
    _committed(jar, _URL, "sid=again; Path=/")  # a re-login does not bring it back
    assert jar.pairs_for(_URL, handshake=False) == []


def test_ordinary_rotation_keeps_the_session() -> None:
    """A few rotations are the normal case: the newest value is sent, nothing is given up."""
    jar = SessionJar("demo.test")
    _committed(jar, _URL, "sid=one; Path=/")
    for i in range(10):
        jar.absorb(_response(_URL, f"sid=r{i}; Path=/"), handshake=False)
    assert not jar.overflowed
    assert jar.pairs_for(_URL, handshake=False) == [("sid", "r9")]


# ---------------------------------------------------------------------------
# Cookies outside ASCII
# ---------------------------------------------------------------------------


def _raw_response(url: str, *set_cookie: bytes) -> httpx2.Response:
    """
    Args:
        url (str): The URL the response answers; becomes the response's request.
        *set_cookie (bytes): One raw ``Set-Cookie`` value per argument.

    Returns:
        httpx2.Response: A 200 carrying those exact bytes.
    """
    headers = [(b"set-cookie", value) for value in set_cookie]
    return httpx2.Response(200, headers=headers, request=httpx2.Request("GET", url))


def _committed_raw(url: str, *set_cookie: bytes) -> SessionJar:
    """
    Args:
        url (str): The URL the handshake response answers.
        *set_cookie (bytes): The raw ``Set-Cookie`` values it carries.

    Returns:
        SessionJar: A jar with those cookies committed.
    """
    jar = SessionJar("demo.test")
    jar.begin()
    jar.absorb(_raw_response(url, *set_cookie), handshake=True)
    jar.commit()
    return jar


@pytest.mark.parametrize(
    "value",
    [
        "café".encode(),
        "à".encode(),  # UTF-8 ends in 0xA0, which str.strip removes when read as Latin-1
        "日本語".encode(),
        b"caf\xe9",  # Latin-1: not valid UTF-8
        b"x\x85",
        b"\xa0x\xa0",
    ],
    ids=["utf8", "utf8-ends-a0", "utf8-cjk", "latin1", "ends-85", "edges-a0"],
)
def test_a_value_outside_ascii_comes_back_byte_for_byte(value: bytes) -> None:
    """Whatever encoding the server chose, the session is the bytes it sent."""
    jar = _committed_raw(_URL, b"sid=" + value + b"; Path=/")

    ((name, held),) = jar.pairs_for(_URL, handshake=False)
    assert (name, cookie_bytes(held)) == ("sid", value)


def test_a_rotation_to_a_value_outside_ascii_is_taken() -> None:
    """The live path: a held name rotates to a non-ASCII value and the next request has it."""
    jar = _committed_raw(_URL, b"sid=first; Path=/")
    jar.absorb(_raw_response(_URL, "sid=café; Path=/".encode()), handshake=False)

    ((_name, held),) = jar.pairs_for(_URL, handshake=False)
    assert cookie_bytes(held) == "café".encode()


def test_two_cookies_in_different_encodings_each_keep_their_bytes() -> None:
    """One response can mix them, so the encoding is never decided for the whole header set."""
    jar = _committed_raw(_URL, "a=café; Path=/".encode(), b"b=caf\xe9; Path=/")

    held = {name: cookie_bytes(value) for name, value in jar.pairs_for(_URL, handshake=False)}
    assert held == {"a": "café".encode(), "b": b"caf\xe9"}


def test_a_name_outside_ascii_is_kept_and_reads_as_text() -> None:
    """The jar's form of a name goes back to the same bytes and to readable text."""
    jar = _committed_raw(_URL, "sessão=v; Path=/".encode())

    ((name, _value),) = jar.pairs_for(_URL, handshake=False)
    assert (cookie_bytes(name), readable_cookie(name)) == ("sessão".encode(), "sessão")


@pytest.mark.parametrize(
    ("raw", "text"),
    [(b"plain", "plain"), ("café".encode(), "café"), (b"caf\xe9", "café")],
    ids=["ascii", "utf8", "latin1"],
)
def test_readable_cookie_prefers_utf8_and_falls_back_to_latin1(raw: bytes, text: str) -> None:
    """Never a private-use character or a surrogate, which a report could not show or write."""
    assert readable_cookie(jar_text(raw)) == text


@pytest.mark.parametrize(
    ("url", "kept"),
    [("http://demo.test/signin", {"sid"}), ("https://demo.test/signin", {"sid", "tok"})],
    ids=["http-drops-secure", "https-keeps-secure"],
)
def test_the_secure_rule_still_applies_beside_a_value_outside_ascii(
    url: str, kept: set[str]
) -> None:
    """Over ``http`` the ``Secure`` line goes and the non-ASCII one stays; ``https`` keeps both."""
    jar = _committed_raw(url, "sid=café; Path=/".encode(), b"tok=abc; Path=/; Secure")

    assert {name for name, _value in jar.pairs_for(url, handshake=False)} == kept


def test_a_path_attribute_outside_ascii_still_matches_the_request() -> None:
    """Attributes stay text: the jar compares ``Path`` with the percent-encoded URL."""
    jar = _committed_raw("http://demo.test/café/", "sid=v; Path=/café".encode())

    assert jar.pairs_for("http://demo.test/caf%C3%A9/page", handshake=False) == [("sid", "v")]
    assert jar.pairs_for("http://demo.test/other", handshake=False) == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("café1234".encode(), {"café1234", "cafÃ©1234"}),
        (b"caf\xe91234", {"café1234"}),
        (b"plain1234", {"plain1234"}),
    ],
    ids=["utf8", "latin1", "ascii"],
)
def test_the_scrub_list_holds_the_value_as_a_page_would_show_it(
    raw: bytes, expected: set[str]
) -> None:
    """The report quotes decoded pages, so the jar's private form would never match them."""
    jar = _committed_raw(_URL, b"sid=" + raw + b"; Path=/")

    assert jar.values == expected

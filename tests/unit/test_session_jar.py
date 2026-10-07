"""
SessionJar — the cookie jar behind an automated login — spec 019 RF-07.

Responses are built by hand (``httpx.Response`` with a ``Set-Cookie`` header and its request)
and fed to ``absorb``; ``pairs_for`` is the observable: the cookies a request to a URL would
carry. No network, no transport: the jar is the standard ``http.cookiejar`` rules behind a
small wrapper, and these tests pin the wrapper (the two modes, the host rule, the value list)
and the rules the login depends on (``Secure``, ``Path``, expiry, odd hosts).
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.http.session import SessionJar

_URL = "http://demo.test/signin"


def _response(url: str, *set_cookie: str) -> httpx.Response:
    """
    Args:
        url (str): The URL the response answers; becomes the response's request.
        *set_cookie (str): One ``Set-Cookie`` header value per argument.

    Returns:
        httpx.Response: A 200 carrying those headers.
    """
    headers = [("set-cookie", value) for value in set_cookie]
    return httpx.Response(200, headers=headers, request=httpx.Request("GET", url))


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
    host = httpx.URL(requested).host
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

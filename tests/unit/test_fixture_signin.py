"""
The fixture's stateful login — spec 019 RF-12.

Pure unit of ``tests/fixtures/app.py``: ``/signin`` is driven through ``httpx.ASGITransport`` with
no scan. Only the guarantees the login tests lean on are checked — the form token is enforced,
the lockout counts wrong passwords (and only the hardened profile refuses), and an issued
session dies after ``session_ttl`` authenticated requests while a plain ``--cookie`` value stays
"logged in". What a page says is not asserted: the integration scans prove it is reached.
"""

from __future__ import annotations

import re

import httpx
import pytest
from starlette.applications import Starlette

from tests.fixtures.app import SIGNIN_LOCKOUT, SIGNIN_PASSWORD, SIGNIN_USER, make_app

_BASE = "http://demo.test"


def _client(app: Starlette) -> httpx.AsyncClient:
    """
    Args:
        app (Starlette): The fixture app.

    Returns:
        httpx.AsyncClient: A client wired to ``app`` in-process; it keeps cookies, like a browser.
    """
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)


async def _token(client: httpx.AsyncClient) -> str:
    """
    Args:
        client (httpx.AsyncClient): The client; receives the ``pre`` cookie.

    Returns:
        str: The form token of a fresh ``GET /signin``.
    """
    page = await client.get("/signin")
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]


async def _login(client: httpx.AsyncClient, password: str = SIGNIN_PASSWORD) -> httpx.Response:
    """
    Args:
        client (httpx.AsyncClient): The client.
        password (str): The password to submit. Defaults to the right one.

    Returns:
        httpx.Response: The answer to ``POST /signin`` (the redirect is not followed).
    """
    token = await _token(client)
    data = {"csrf": token, "email": SIGNIN_USER, "pass": password, "go": "Sign in"}
    return await client.post("/signin", data=data)


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_the_form_token_is_enforced(profile: str) -> None:
    """A post without the token, or with a token the ``pre`` cookie does not match, is a 400."""
    app = make_app(profile)
    async with _client(app) as client:
        await client.get("/signin")
        no_token = await client.post(
            "/signin", data={"email": SIGNIN_USER, "pass": SIGNIN_PASSWORD}
        )
        wrong = await client.post(
            "/signin", data={"csrf": "csrf-999", "email": SIGNIN_USER, "pass": SIGNIN_PASSWORD}
        )
    assert (no_token.status_code, wrong.status_code) == (400, 400)
    assert app.state.login_log == ["bad-csrf", "bad-csrf"]
    assert app.state.sessions == {}


@pytest.mark.parametrize("profile", ["insecure", "hardened"])
async def test_a_right_login_redirects_through_a_chain_ending_on_the_account(profile: str) -> None:
    """POST -> /signin/done -> /account; the hardened app sets the session on the first hop."""
    app = make_app(profile)
    async with _client(app) as client:
        first = await _login(client)
        assert first.status_code == 302 and first.headers["location"] == "/signin/done"
        sets_a_session = any("session" in c for c in first.headers.get_list("set-cookie"))
        final = await client.get("/signin/done", follow_redirects=True)
    # spec 020: the insecure app keeps the id it gave the anonymous visitor (fixation)
    assert sets_a_session is (profile == "hardened")
    assert final.status_code == 200 and final.url.path == "/account"
    assert app.state.login_log == ["ok"]


async def test_only_the_hardened_profile_locks_the_account_after_the_wrong_passwords() -> None:
    """The counter goes up per wrong password; hardened answers 429 past the limit."""
    for profile, locked in (("insecure", False), ("hardened", True)):
        app = make_app(profile)
        async with _client(app) as client:
            for _ in range(SIGNIN_LOCKOUT):
                await _login(client, "wrong")
            right = await _login(client)
        assert app.state.failed_logins == (SIGNIN_LOCKOUT if locked else 0), profile
        assert (right.status_code == 429) is locked, profile
        assert app.state.login_log[-1] == ("locked" if locked else "ok"), profile


async def test_an_issued_session_dies_after_its_ttl_but_a_plain_cookie_never_does() -> None:
    """After ``session_ttl`` requests the session is redirected; a plain ``--cookie`` is not."""
    app = make_app("insecure", session_ttl=2)
    async with _client(app) as client:
        await _login(client)
        statuses = [(await client.get("/account")).status_code for _ in range(3)]
        expired = await client.get("/account")
    assert statuses == [200, 200, 302]  # the third request outlived the ttl of two
    assert expired.status_code == 302 and expired.headers["location"] == "/login"
    assert len(app.state.expired) == 1

    async with _client(app) as plain:
        for _ in range(5):
            response = await plain.get("/account", headers={"cookie": "session=anything"})
            assert response.status_code == 200  # the any-cookie behaviour of spec 007

"""
The fixture's session behaviours — spec 020 RF-12.

Pure unit of ``tests/fixtures/app.py``: the insecure profile hands out counter ids, keeps the
anonymous id at login (fixation) and leaves the session valid after ``/logout``; the hardened one
hands out long random ids that differ per visit, issues a new id at login and ends the session on
the server at logout. Only the guarantees the integration scans lean on are checked; what a page
says is not.
"""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette

from tests.fixtures.app import SIGNIN_PASSWORD, SIGNIN_USER, make_app

_BASE = "http://demo.test"


def _client(app: Starlette) -> httpx.AsyncClient:
    """
    Args:
        app (Starlette): The fixture app.

    Returns:
        httpx.AsyncClient: A client wired to ``app`` in-process; it keeps cookies like a browser.
    """
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)


async def _anonymous_id(client: httpx.AsyncClient, name: str) -> str:
    """
    Args:
        client (httpx.AsyncClient): The client.
        name (str): The session cookie's name.

    Returns:
        str: The id ``GET /signin`` gave this visitor.
    """
    await client.get("/signin")
    return client.cookies[name]


async def _login(client: httpx.AsyncClient) -> httpx.Response:
    """
    Args:
        client (httpx.AsyncClient): A client that already did ``GET /signin``.

    Returns:
        httpx.Response: The answer to a right ``POST /signin`` (the redirect is not followed).
    """
    data = {
        "csrf": client.cookies["pre"],
        "email": SIGNIN_USER,
        "pass": SIGNIN_PASSWORD,
        "go": "Sign in",
    }
    return await client.post("/signin", data=data)


async def test_the_insecure_app_hands_out_counter_ids_and_keeps_them_at_login() -> None:
    """Visitors get 1001, 1002...; the login makes that same id the authenticated session."""
    app = make_app("insecure")
    async with _client(app) as first, _client(app) as second:
        one = await _anonymous_id(first, "session")
        two = await _anonymous_id(second, "session")
        assert (one, two) == ("1001", "1002")

        answer = await _login(first)
        assert not any("session" in c for c in answer.headers.get_list("set-cookie"))
    assert list(app.state.sessions) == [one]  # the anonymous id is now the authenticated session


async def test_the_hardened_app_issues_a_new_long_id_at_login() -> None:
    """The anonymous id stays anonymous; the login sets a different, long, random-looking one."""
    app = make_app("hardened")
    async with _client(app) as client:
        anonymous = await _anonymous_id(client, "__Host-session")
        answer = await _login(client)
        issued = [
            c for c in answer.headers.get_list("set-cookie") if c.startswith("__Host-session=")
        ]
    (cookie,) = issued
    token = cookie.split("=", 1)[1].split(";", 1)[0]
    assert token != anonymous and len(token) >= 32 and len(anonymous) >= 32
    assert list(app.state.sessions) == [token]  # the anonymous id was never authenticated


async def test_the_hardened_index_id_differs_on_every_visit_and_the_insecure_one_never_does() -> (
    None
):
    """A constant index cookie would be a "duplicates" finding of the sampling."""
    seen: dict[str, list[str]] = {}
    for profile, name in (("insecure", "session"), ("hardened", "__Host-session")):
        app = make_app(profile)
        async with _client(app) as client:
            values = []
            for _ in range(4):
                response = await client.get("/")
                cookie = next(c for c in response.headers.get_list("set-cookie") if name in c)
                values.append(cookie.split("=", 1)[1].split(";", 1)[0])
        seen[profile] = values
    assert len(set(seen["insecure"])) == 1
    assert len(set(seen["hardened"])) == 4 and all(len(v) == 32 for v in seen["hardened"])


@pytest.mark.parametrize(
    ("profile", "name", "still_valid"),
    [
        ("insecure", "session", True),
        ("hardened", "__Host-session", False),
    ],
)
async def test_only_the_hardened_logout_ends_the_session_on_the_server(
    profile: str, name: str, still_valid: bool
) -> None:
    """After ``/logout`` the old id still reaches ``/account`` in the insecure app only."""
    app = make_app(profile)
    async with _client(app) as client:
        await client.get("/signin")
        await _login(client)
        await client.get("/signin/done", follow_redirects=True)  # picks up the session cookie
        token = client.cookies[name]
        assert (await client.get("/account")).status_code == 200

        await client.get("/logout")
        replay = await client.get("/account", headers={"cookie": f"{name}={token}"})
    assert (replay.status_code == 200) is still_valid
    assert app.state.logout_log == [True]

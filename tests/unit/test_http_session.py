"""
HttpClient with a login session — attach, drop detection, single-flight re-login — spec 019.

Every test runs the real ``HttpClient`` against an in-process transport that plays a tiny
app (:class:`_App`): ``/signin`` issues a fresh ``sid`` cookie, every other path answers ``200``
for a live ``sid`` and ``401`` otherwise, and the test can expire the session at will. The
re-login is a three-line stand-in for the ``Authenticator`` (a handshake ``GET /signin`` that
commits the jar); what is under test is the client and the ``Session``, not the form parsing.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import httpx
import pytest

from tests.support import HandlerTransport
from webvigil.core.config import ScanConfig
from webvigil.core.target import Scope, Target
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient, Response
from webvigil.http.session import Session, SessionJar

_BASE = "http://demo.test"


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff so a failing request does not sleep."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


class _App:
    """A tiny target: a login that issues ``sid`` cookies and pages that check one."""

    def __init__(self) -> None:
        self.issued = 0
        self.valid: set[str] = set()
        self.cookie_seen: list[str] = []  # the Cookie header of every non-login request
        self.status_for: dict[str, int] = {}  # path -> forced status (403, 500 ...)
        self.bounce: set[str] = set()  # paths that always redirect to /signin
        self.honour = True  # False: /signin issues a cookie the pages never accept

    def expire(self) -> None:
        """Kill every live session, as a timeout would."""
        self.valid.clear()

    def handle(self, request: httpx.Request) -> httpx.Response:
        """
        Args:
            request (httpx.Request): The request the client sent.

        Returns:
            httpx.Response: The app's answer.
        """
        path = request.url.path
        if path == "/signin":
            self.issued += 1
            token = f"tok{self.issued}"
            if self.honour:
                self.valid.add(token)
            return httpx.Response(200, headers={"set-cookie": f"sid={token}; Path=/"}, text="form")
        self.cookie_seen.append(request.headers.get("cookie", ""))
        if path in self.status_for:
            return httpx.Response(self.status_for[path], text="blocked")
        if path in self.bounce:
            return httpx.Response(302, headers={"location": "/signin"})
        sid = next(
            (
                p.split("=", 1)[1]
                for p in request.headers.get("cookie", "").split("; ")
                if p.startswith("sid=")
            ),
            "",
        )
        if sid in self.valid:
            return httpx.Response(200, text="ok")
        return httpx.Response(401, text="no")


def _client(app: _App, *, cookies: list[str] | None = None) -> HttpClient:
    """
    Args:
        app (_App): The target the transport plays.
        cookies (list[str] | None): Static ``[auth]`` cookies. Defaults to none.

    Returns:
        HttpClient: A client for ``http://demo.test/`` wired to ``app``.
    """
    config = ScanConfig.model_validate({"auth": {"cookies": cookies}} if cookies else {})
    target = Target.parse(_BASE, scope=Scope.HOST)
    return HttpClient(target, config, transport=HandlerTransport(app.handle))


def _session(http: HttpClient, **kwargs: object) -> Session:
    """
    Args:
        http (HttpClient): The client the session is attached to.
        **kwargs (object): Overrides for the ``Session`` constructor.

    Returns:
        Session: A session whose ``relogin`` is the stand-in login, attached to ``http``.
    """
    holder: dict[str, Session] = {}

    async def relogin() -> bool:
        """The stand-in for ``Authenticator.login``: a handshake that commits the jar."""
        async with http.handshake():
            await http.get(f"{_BASE}/signin")
            holder["s"].jar.commit()
        holder["s"].committed()
        return True

    options: dict[str, object] = {
        "jar": SessionJar("demo.test"),
        "is_login_url": lambda url: urlsplit(url).path == "/signin",
        "relogin": relogin,
    }
    options.update(kwargs)
    session = Session(**options)  # type: ignore[arg-type]
    holder["s"] = session
    http.use_session(session)
    return session


async def _login(http: HttpClient, session: Session) -> None:
    """
    Args:
        http (HttpClient): The client.
        session (Session): Its session; receives the first committed login.
    """
    async with http.handshake():
        await http.get(f"{_BASE}/signin")
        session.jar.commit()
    session.committed()


# ---------------------------------------------------------------------------
# What a request carries
# ---------------------------------------------------------------------------


async def test_the_session_cookie_rides_on_target_requests_and_beats_a_static_one() -> None:
    """Static cookies stay, the login's cookie wins a name clash, nothing else is picked up."""
    app = _App()
    async with _client(app, cookies=["sid=static", "lang=en"]) as http:
        session = _session(http)
        await _login(http, session)
        await http.get(f"{_BASE}/page")

    assert app.cookie_seen == ["lang=en; sid=tok1"]


async def test_without_a_session_the_client_sends_only_what_is_configured() -> None:
    """A target's ``Set-Cookie`` is never replayed when no login is attached (spec 007)."""
    app = _App()
    async with _client(app, cookies=["lang=en"]) as http:
        await http.get(f"{_BASE}/signin")  # sets sid, which must not come back
        await http.get(f"{_BASE}/page")

    assert app.cookie_seen == ["lang=en"]


# ---------------------------------------------------------------------------
# A dropped session
# ---------------------------------------------------------------------------


async def test_a_dropped_session_is_re_logged_in_once_and_the_request_retried() -> None:
    """A 401 earns one re-login and the retry answers 200 with the new cookie."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        app.expire()

        response = await http.get(f"{_BASE}/page")

    assert response.status_code == 200
    assert (app.issued, session.relogins, session.generation) == (2, 1, 2)
    assert app.cookie_seen == ["sid=tok1", "sid=tok2"]


async def test_the_retry_is_returned_as_it_is_and_never_retried_again() -> None:
    """A retry that drops again comes back as a 401: one re-login, no second retry."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        app.expire()
        app.honour = False  # the new session is no better than the old one

        response = await http.get(f"{_BASE}/page")

    assert response.status_code == 401
    assert (app.issued, session.relogins) == (2, 1)


@pytest.mark.parametrize("status", [403, 500, 503])
async def test_a_block_page_or_a_server_error_is_not_a_dropped_session(status: int) -> None:
    """A payload that draws a 403 / 5xx never triggers a re-login."""
    app = _App()
    app.status_for["/blocked"] = status
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)

        response = await http.get(f"{_BASE}/blocked")

    assert response.status_code == status
    assert (app.issued, session.relogins) == (1, 0)


async def test_ten_concurrent_drops_cost_one_login() -> None:
    """Single flight: every request that noticed the drop waits for one re-login, then retries."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        app.expire()

        responses = await asyncio.gather(*(http.get(f"{_BASE}/p{i}") for i in range(10)))

    assert {r.status_code for r in responses} == {200}
    assert (app.issued, session.relogins) == (2, 1)


async def test_the_relogin_cap_ends_in_a_lost_session_and_the_scan_goes_on() -> None:
    """After ``max_relogins`` the next drop is returned as it is and the session is lost."""
    app = _App()
    async with _client(app) as http:
        session = _session(http, max_relogins=1)
        await _login(http, session)
        app.expire()
        assert (await http.get(f"{_BASE}/a")).status_code == 200  # the one re-login
        app.expire()
        last = await http.get(f"{_BASE}/b")  # no budget left

    assert last.status_code == 401
    assert (session.relogins, session.lost) == (1, True)
    assert session.summary().session_lost is True
    assert any("lost" in line for line in session.warnings())


async def test_a_failed_relogin_counts_and_the_request_is_not_retried() -> None:
    """A re-login that does not commit is a spent attempt, a warning and a plain 401."""
    app = _App()

    async def refuses() -> bool:
        return False

    async with _client(app) as http:
        session = _session(http, relogin=refuses)
        await _login(http, session)
        app.expire()

        response = await http.get(f"{_BASE}/page")

    assert response.status_code == 401
    assert (session.relogins, session.failed_relogins) == (1, 1)
    assert any("failed" in line for line in session.warnings())


# ---------------------------------------------------------------------------
# A redirect to the login page, and check_url
# ---------------------------------------------------------------------------


async def test_a_page_that_always_bounces_to_login_costs_one_relogin_then_is_learned() -> None:
    """ADR-6: an unauthorised-redirect page is learned after one wasted re-login."""
    app = _App()
    app.bounce.add("/admin")
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)

        await http.get(f"{_BASE}/admin")
        await http.get(f"{_BASE}/admin")

    assert session.relogins == 1
    assert f"{_BASE}/admin" in session.known_login_redirects


async def test_check_url_vetoes_a_re_login_the_page_does_not_justify() -> None:
    """When the confirmation says the session is fine, no login happens and the URL is learned."""
    app = _App()
    app.bounce.add("/admin")
    calls: list[int] = []

    async def still_logged_in() -> bool:
        calls.append(1)
        return False  # "check_url does not look logged out"

    async with _client(app) as http:
        session = _session(http, confirm_dropped=still_logged_in)
        await _login(http, session)

        await http.get(f"{_BASE}/admin")
        await http.get(f"{_BASE}/admin")

    assert (session.relogins, len(calls)) == (0, 1)  # asked once, then the page is known


async def test_check_url_confirming_the_drop_lets_the_re_login_through() -> None:
    """A confirmation that says "logged out" is followed by the usual re-login and retry."""
    app = _App()

    async def logged_out() -> bool:
        return True

    async with _client(app) as http:
        session = _session(http, confirm_dropped=logged_out)
        await _login(http, session)
        app.expire()

        response = await http.get(f"{_BASE}/page")

    assert (response.status_code, session.relogins) == (200, 1)


def _page(text: str) -> Response:
    """
    Args:
        text (str): A response body.

    Returns:
        Response: A 200 answer for ``/page`` with that body, no redirects.
    """
    return Response(
        url=f"{_BASE}/page",
        requested_url=f"{_BASE}/page",
        status_code=200,
        headers=httpx.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


async def test_a_logged_out_marker_in_the_body_is_a_drop() -> None:
    """The marker catches a drop that answers 200 with the login form in the same URL."""
    session = Session(
        jar=SessionJar("demo.test"),
        is_login_url=lambda url: False,
        logged_out_marker=r"Please sign in",
    )
    assert session.looks_dropped(_page("<p>Please sign in</p>"))
    assert not session.looks_dropped(_page("welcome"))
    session.learn(f"{_BASE}/page")  # a known bouncer is never a drop, marker or not
    assert not session.looks_dropped(_page("<p>Please sign in</p>"))


# ---------------------------------------------------------------------------
# The handshake is scoped to its task
# ---------------------------------------------------------------------------


async def test_a_handshake_does_not_leak_into_a_concurrent_request() -> None:
    """A request made by another task while a handshake runs still uses the live jar."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        go = asyncio.Event()

        async def concurrent() -> httpx.Response:
            await go.wait()
            return await http.get(f"{_BASE}/page")

        task = asyncio.create_task(concurrent())
        async with http.handshake():
            go.set()
            await task  # runs while this task is inside the handshake
            session.jar.rollback()

    assert app.cookie_seen[-1] == "sid=tok1"
    assert task.result().status_code == 200


async def test_a_401_page_unrelated_to_the_session_is_vetoed_once_then_learned() -> None:
    """A page that answers 401 even for a live session costs one confirmation, never a login."""
    app = _App()
    app.status_for["/api"] = 401
    calls: list[int] = []

    async def still_logged_in() -> bool:
        calls.append(1)
        return False  # the reference page is fine: the 401 is about this page, not the session

    async with _client(app) as http:
        session = _session(http, confirm_dropped=still_logged_in)
        await _login(http, session)

        first = await http.get(f"{_BASE}/api")
        second = await http.get(f"{_BASE}/api")

    assert (first.status_code, second.status_code) == (401, 401)
    assert (session.relogins, len(calls), app.issued) == (0, 1, 1)

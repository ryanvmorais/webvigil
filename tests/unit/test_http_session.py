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

import httpx2
import pytest

from tests.support import HandlerTransport
from webvigil.core.config import ScanConfig
from webvigil.core.errors import RequestFailed
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
        self.rotate: dict[str, str] = {}  # path -> a new sid value its answer sets
        self.honour = True  # False: /signin issues a cookie the pages never accept

    def expire(self) -> None:
        """Kill every live session, as a timeout would."""
        self.valid.clear()

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The request the client sent.

        Returns:
            httpx2.Response: The app's answer.
        """
        path = request.url.path
        if path == "/signin":
            self.issued += 1
            token = f"tok{self.issued}"
            if self.honour:
                self.valid.add(token)
            return httpx2.Response(200, headers={"set-cookie": f"sid={token}; Path=/"}, text="form")
        self.cookie_seen.append(request.headers.get("cookie", ""))
        response = self._page(request)
        if path in self.rotate:
            response.headers["set-cookie"] = f"sid={self.rotate[path]}; Path=/"
        return response

    def _page(self, request: httpx2.Request) -> httpx2.Response:
        """
        Answer a page request, before any cookie rotation is added.

        Args:
            request (httpx2.Request): A request for any path but ``/signin``.

        Returns:
            httpx2.Response: The forced status, the bounce, or 200 / 401 by the ``sid`` sent.
        """
        path = request.url.path
        if path in self.status_for:
            return httpx2.Response(self.status_for[path], text="blocked")
        if path in self.bounce:
            return httpx2.Response(302, headers={"location": "/signin"})
        sid = next(
            (
                p.split("=", 1)[1]
                for p in request.headers.get("cookie", "").split("; ")
                if p.startswith("sid=")
            ),
            "",
        )
        if sid in self.valid:
            return httpx2.Response(200, text="ok")
        return httpx2.Response(401, text="no")


def _client(
    app: _App, *, cookies: list[str] | None = None, scope: Scope = Scope.HOST
) -> HttpClient:
    """
    Args:
        app (_App): The target the transport plays.
        cookies (list[str] | None): Static ``[auth]`` cookies. Defaults to none.
        scope (Scope): The target scope. Defaults to ``Scope.HOST``.

    Returns:
        HttpClient: A client for ``http://demo.test/`` wired to ``app``.
    """
    config = ScanConfig.model_validate({"auth": {"cookies": cookies}} if cookies else {})
    target = Target.parse(_BASE, scope=scope)
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
        "jar": SessionJar(Target.parse(_BASE)),
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


class _RawCookieApp(_App):
    """A target whose login sets one exact byte string and that records the bytes it gets back."""

    def __init__(self, value: bytes) -> None:
        """
        Args:
            value (bytes): The raw ``sid`` value the login sets.
        """
        super().__init__()
        self.value = value
        self.received: list[tuple[list[bytes], str | None]] = []  # (Cookie lines, x-test)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The request the client sent.

        Returns:
            httpx2.Response: The login's ``Set-Cookie``, or a plain page.
        """
        if request.url.path == "/signin":
            cookie = b"sid=" + self.value + b"; Path=/"
            return httpx2.Response(200, headers=[(b"set-cookie", cookie)], text="form")
        lines = [v for k, v in request.headers.raw if k.lower() == b"cookie"]
        self.received.append((lines, request.headers.get("x-test")))
        return httpx2.Response(200, text="ok")


@pytest.mark.parametrize(
    "value",
    ["café".encode(), "à".encode(), b"caf\xe9"],
    ids=["utf8", "utf8-ends-a0", "latin1"],
)
async def test_a_session_cookie_outside_ascii_goes_out_as_its_own_bytes(value: bytes) -> None:
    """One Cookie line with the server's bytes, a UTF-8 static cookie, the other headers intact."""
    app = _RawCookieApp(value)
    async with _client(app, cookies=["lang=português"]) as http:
        session = _session(http)
        await _login(http, session)
        await http.get(f"{_BASE}/page", headers={"x-test": "kept"})

    assert app.received == [(["lang=português".encode() + b"; sid=" + value], "kept")]


async def test_a_static_cookie_outside_ascii_goes_out_as_utf8_without_a_session() -> None:
    """The ``--cookie`` path alone: no login attached, the value is the UTF-8 the user typed."""
    app = _RawCookieApp(b"unused")
    async with _client(app, cookies=["lang=português"]) as http:
        await http.get(f"{_BASE}/page")

    assert app.received == [(["lang=português".encode()], None)]


async def test_without_a_session_the_client_sends_only_what_is_configured() -> None:
    """A target's ``Set-Cookie`` is never replayed when no login is attached (spec 007)."""
    app = _App()
    async with _client(app, cookies=["lang=en"]) as http:
        await http.get(f"{_BASE}/signin")  # sets sid, which must not come back
        await http.get(f"{_BASE}/page")

    assert app.cookie_seen == ["lang=en"]


@pytest.mark.parametrize("value", [b"plain", "café".encode()], ids=["ascii", "non-ascii"])
async def test_a_retry_carries_no_cookie_the_target_set(value: bytes) -> None:
    """A cookie set by the failed attempt stays out of the retry, whatever its bytes."""
    seen: list[str | None] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        """Fail the first attempt with a ``Set-Cookie``, then answer."""
        seen.append(request.headers.get("cookie"))
        if len(seen) == 1:
            return httpx2.Response(503, headers=[(b"set-cookie", b"picked=" + value + b"; Path=/")])
        return httpx2.Response(200)

    target = Target.parse(_BASE, scope=Scope.HOST)
    async with HttpClient(target, ScanConfig(), transport=HandlerTransport(handle)) as http:
        response = await http.get(f"{_BASE}/page")

    assert response.status_code == 200
    assert seen == [None, None]  # two attempts, neither with a cookie


class _HeldTransport(httpx2.AsyncBaseTransport):
    """Holds the first request open, so another one is waiting when its answer lands."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.cookies: dict[str, str | None] = {}

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The request; its path and ``Cookie`` header are recorded.

        Returns:
            httpx2.Response: A ``200``; the first request's also sets a parent-domain cookie.
        """
        self.cookies[request.url.path] = request.headers.get("cookie")
        if request.url.path != "/first":
            return httpx2.Response(200, stream=httpx2.ByteStream(b""))
        self.entered.set()
        await self.release.wait()
        cookie = (b"set-cookie", b"sid=held; Domain=demo.test; Path=/")
        return httpx2.Response(200, headers=[cookie], stream=httpx2.ByteStream(b""))


@pytest.mark.parametrize(
    ("url", "anonymous"),
    [("http://other.demo.test/second", False), ("http://app.demo.test/second", True)],
    ids=["sibling-host", "anonymous"],
)
async def test_a_cookie_the_target_set_never_rides_on_a_waiting_request(
    url: str, anonymous: bool
) -> None:
    """An answer landing while another request waits for its slot leaves that request alone."""
    transport = _HeldTransport()
    config = ScanConfig.model_validate({"http": {"concurrency": 1, "delay_ms": 0}})
    target = Target.parse("http://app.demo.test", scope=Scope.SUBDOMAINS)

    async def second(http: HttpClient) -> None:
        """Send the request that waits for the slot the first one holds."""
        if anonymous:
            async with http.anonymous():
                await http.get(url)
        else:
            await http.get(url)

    async with HttpClient(target, config, transport=transport) as http:
        first = asyncio.create_task(http.get("http://app.demo.test/first"))
        await transport.entered.wait()
        waiting = asyncio.create_task(second(http))
        for _ in range(10):  # let it run up to the slot the first request holds
            await asyncio.sleep(0)
        assert "/second" not in transport.cookies
        transport.release.set()
        await asyncio.gather(first, waiting)

    assert transport.cookies == {"/first": None, "/second": None}


async def test_a_url_that_cannot_be_built_fails_alone_in_a_logged_in_scan() -> None:
    """The session reads the URL before the request: a bad link costs that URL, not the scan."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        with pytest.raises(RequestFailed, match="InvalidURL"):
            await http.get(f"{_BASE}/page\x1b")
        await http.get(f"{_BASE}/page")  # the session still works after it

    assert app.cookie_seen == ["sid=tok1"]  # the bad URL was never sent
    assert http.stats.failed == 0  # and does not read as a target that stopped answering


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


async def test_a_401_off_the_target_origin_is_not_a_dropped_session() -> None:
    """A sibling subdomain gets no session, so its 401 says nothing about it (spec 026)."""
    app = _App()
    async with _client(app, scope=Scope.SUBDOMAINS) as http:
        session = _session(http)
        await _login(http, session)

        sibling = await http.get("http://cdn.demo.test/page")
        assert sibling.status_code == 401
        assert (app.issued, session.relogins) == (1, 0)

        app.expire()  # the positive control: the same 401 on the origin earns the re-login
        origin = await http.get(f"{_BASE}/page")

    assert origin.status_code == 200
    assert (app.issued, session.relogins) == (2, 1)
    assert app.cookie_seen == ["", "sid=tok1", "sid=tok2"]


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
        headers=httpx2.Headers({"content-type": "text/html"}),
        text=text,
        content=text.encode(),
        elapsed_ms=1.0,
    )


async def test_a_logged_out_marker_in_the_body_is_a_drop() -> None:
    """The marker catches a drop that answers 200 with the login form in the same URL."""
    session = Session(
        jar=SessionJar(Target.parse(_BASE)),
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

        async def concurrent() -> httpx2.Response:
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


# ---------------------------------------------------------------------------
# anonymous() and close() (spec 020)
# ---------------------------------------------------------------------------


async def test_an_anonymous_request_carries_only_the_callers_own_headers() -> None:
    """No static cookie, no static header, no jar; an explicit Cookie header goes out as given."""
    app = _App()
    seen: list[httpx2.Headers] = []
    original = app.handle

    def spy(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers)
        return original(request)

    config = ScanConfig.model_validate(
        {"auth": {"cookies": ["lang=en"], "headers": ["X-Api-Key: k1"]}}
    )
    target = Target.parse(_BASE, scope=Scope.HOST)
    async with HttpClient(target, config, transport=HandlerTransport(spy)) as http:
        session = _session(http)
        await _login(http, session)
        seen.clear()

        await http.get(f"{_BASE}/page")  # a normal request: cookies and the header ride along
        async with http.anonymous():
            await http.get(f"{_BASE}/page")
            await http.get(f"{_BASE}/page", headers={"cookie": "sid=explicit"})

    normal, bare, explicit = seen
    assert normal["cookie"] == "lang=en; sid=tok1" and normal["x-api-key"] == "k1"
    assert "cookie" not in bare and "x-api-key" not in bare
    assert explicit["cookie"] == "sid=explicit" and "x-api-key" not in explicit


async def test_a_live_request_takes_a_rotated_session_cookie() -> None:
    """The control for the anonymous test below: outside ``anonymous()`` a new ``sid`` is kept."""
    app = _App()
    app.rotate["/page"] = "anon"
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)

        await http.get(f"{_BASE}/page")

    assert session.jar.pairs_for(f"{_BASE}/page", handshake=False) == [("sid", "anon")]


async def test_an_anonymous_request_neither_absorbs_cookies_nor_triggers_a_relogin() -> None:
    """A 401 that sets a new ``sid`` inside ``anonymous()`` is returned as it is; the jar stays."""
    app = _App()
    app.rotate["/page"] = "anon"
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        app.expire()

        async with http.anonymous():
            response = await http.get(f"{_BASE}/page", headers={"cookie": "sid=tok1"})
        assert response.status_code == 401
        assert response.headers["set-cookie"] == "sid=anon; Path=/"

    assert (app.issued, session.relogins) == (1, 0)
    assert session.jar.pairs_for(f"{_BASE}/page", handshake=False) == [("sid", "tok1")]


async def test_anonymous_is_scoped_to_its_task() -> None:
    """A request another task makes while this one is anonymous still carries the session."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        go = asyncio.Event()

        async def concurrent() -> httpx2.Response:
            await go.wait()
            return await http.get(f"{_BASE}/page")

        task = asyncio.create_task(concurrent())
        async with http.anonymous():
            go.set()
            await task
    assert app.cookie_seen[-1] == "sid=tok1"


async def test_a_closed_session_is_not_recovered() -> None:
    """After ``close()`` a drop is returned as it is: no re-login after the logout test."""
    app = _App()
    async with _client(app) as http:
        session = _session(http)
        await _login(http, session)
        session.close()
        app.expire()

        response = await http.get(f"{_BASE}/page")

    assert response.status_code == 401
    assert (app.issued, session.relogins, session.closed) == (1, 0, True)

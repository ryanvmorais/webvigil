"""
Authenticator — the automated login handshake — spec 019 RF-02 to RF-06.

The real ``HttpClient`` and ``Authenticator`` run against a hand-written site (:class:`_Site`)
served by ``HandlerTransport``: ``GET /signin`` returns a login page and a pre-login cookie,
``POST /signin`` checks the password and either redirects to ``/home`` with a session cookie or
shows the form again. What is under test is the form picking, the body, the single ``POST``,
the scope and scheme gates, the verification order and the messages (none may carry the
password or a cookie value); the cookie rules live in ``test_session_jar.py`` and the
drop / re-login logic in ``test_http_session.py``.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable
from urllib.parse import parse_qsl

import httpx
import pytest

from tests.support import HandlerTransport
from webvigil.auth.login import Authenticator, Credentials
from webvigil.core.config import LoginSection, ScanConfig
from webvigil.core.errors import LoginFailedError
from webvigil.core.target import Scope, Target
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient

_PASSWORD = "s3cret-pw"
_USER = "scanner@example.com"

_FORM = (
    '<form method="post" action="/signin">'
    '<input type="hidden" name="csrf" value="tkn1">'
    '<input type="text" name="email">'
    '<input type="password" name="pass">'
    '<input type="submit" name="go" value="Sign in">'
    "</form>"
)


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff so a failing request does not sleep."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


def _html(*parts: str) -> httpx.Response:
    """
    Args:
        *parts (str): HTML fragments for the body.

    Returns:
        httpx.Response: A 200 HTML page.
    """
    return httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="<html><body>" + "".join(parts) + "</body></html>",
    )


class _Site:
    """A target with a login page, a login endpoint and a home page."""

    def __init__(
        self,
        *,
        login_page: str = _FORM,
        pre_cookie: bool = True,
        post: Callable[[httpx.Request, dict[str, str]], httpx.Response] | None = None,
        pages: dict[str, Callable[[httpx.Request], httpx.Response]] | None = None,
    ) -> None:
        """
        Args:
            login_page (str): The body of ``GET /signin``. Defaults to one login form.
            pre_cookie (bool): Whether ``GET /signin`` sets a pre-login cookie.
            post (Callable | None): Overrides the answer to ``POST /signin``; gets the request
                and the parsed form body.
            pages (dict | None): Extra paths, each answered by its callable.
        """
        self.login_page = login_page
        self.pre_cookie = pre_cookie
        self.post = post or self._default_post
        self.pages = pages or {}
        self.requests: list[httpx.Request] = []

    @property
    def posts(self) -> list[httpx.Request]:
        """
        Returns:
            list[httpx.Request]: Every ``POST`` the site received.
        """
        return [r for r in self.requests if r.method == "POST"]

    @staticmethod
    def _default_post(request: httpx.Request, body: dict[str, str]) -> httpx.Response:
        """
        Args:
            request (httpx.Request): The login ``POST``.
            body (dict[str, str]): Its parsed form body.

        Returns:
            httpx.Response: A redirect to ``/home`` with a session cookie for the right
                password, the login page again otherwise.
        """
        if body.get("pass") == _PASSWORD and body.get("csrf") == "tkn1":
            return httpx.Response(
                302, headers={"location": "/home", "set-cookie": "sid=sess-9f3a; Path=/"}
            )
        return _html(_FORM, "<p>Invalid credentials</p>")

    def handle(self, request: httpx.Request) -> httpx.Response:
        """
        Args:
            request (httpx.Request): The request the client sent.

        Returns:
            httpx.Response: The site's answer.
        """
        self.requests.append(request)
        path = request.url.path
        if path == "/signin" and request.method == "GET":
            answer = _html(self.login_page)
            if self.pre_cookie:
                answer.headers["set-cookie"] = "pre=pre-77aa; Path=/"
            return answer
        if path == "/signin" and request.method == "POST":
            body = dict(parse_qsl(request.content.decode(), keep_blank_values=True))
            return self.post(request, body)
        if path in self.pages:
            return self.pages[path](request)
        if path == "/home":
            return _html("<p>Welcome</p>")
        return httpx.Response(404, text="nope")


@contextlib.asynccontextmanager
async def _open(
    site: _Site, *, base: str = "http://demo.test/", **login: object
) -> AsyncIterator[Authenticator]:
    """
    Args:
        site (_Site): The target to play.
        base (str): The scan target. Defaults to ``http://demo.test/``.
        **login (object): ``[auth.login]`` keys; ``url`` defaults to ``<base>signin``.

    Yields:
        Authenticator: One wired to a real ``HttpClient`` on ``site``, session attached.
    """
    options: dict[str, object] = {"url": f"{base}signin", "username": _USER}
    options.update(login)
    section = LoginSection(**options)  # type: ignore[arg-type]
    target = Target.parse(base, scope=Scope.HOST)
    http = HttpClient(target, ScanConfig(), transport=HandlerTransport(site.handle))
    async with http:
        auth = Authenticator(http, target, section, Credentials(_USER, _PASSWORD))
        http.use_session(auth.session)
        yield auth


def _no_secret(error: LoginFailedError) -> None:
    """
    Args:
        error (LoginFailedError): A failure message.
    """
    text = str(error)
    for secret in (_PASSWORD, "sess-9f3a", "pre-77aa", "tkn1"):
        assert secret not in text, secret


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


async def test_the_handshake_posts_the_form_once_and_commits_every_hop() -> None:
    """One ``POST`` with the form's own fields and the account; the chain's cookies commit."""
    site = _Site()
    async with _open(site) as auth:
        result = await auth.login()

        assert result.confirmed
        assert auth.session.generation == 1
        assert sorted(auth.session.jar.pairs_for("http://demo.test/home", handshake=False)) == [
            ("pre", "pre-77aa"),
            ("sid", "sess-9f3a"),
        ]
    (post,) = site.posts
    body = dict(parse_qsl(post.content.decode()))
    assert body == {"csrf": "tkn1", "email": _USER, "pass": _PASSWORD, "go": "Sign in"}
    assert post.headers["origin"] == "http://demo.test"
    assert post.headers["referer"] == "http://demo.test/signin"
    assert post.headers["cookie"] == "pre=pre-77aa"  # the pre-login cookie rides on the POST


async def test_the_password_and_every_cookie_value_are_registered_as_secrets() -> None:
    """The session knows what to scrub: the password and the values the target issued."""
    async with _open(_Site()) as auth:
        await auth.login()
        assert {_PASSWORD, "pre-77aa", "sess-9f3a"} <= auth.session.secrets


# ---------------------------------------------------------------------------
# Picking the form and the fields
# ---------------------------------------------------------------------------

_OTHER_FORM = (
    '<form method="post" action="/other"><input type="text" name="u">'
    '<input type="password" name="p"><input type="submit" value="go"></form>'
)
_SEARCH_FORM = '<form method="get" action="/s"><input type="text" name="q"></form>'

# (login page, [auth.login] keys, a fragment the message must contain)
_FORM_FAILURES = [
    (_SEARCH_FORM, {}, "no login form"),  # no POST form with a password input
    (_FORM + _OTHER_FORM, {}, "2 login forms"),  # ambiguous and no form_index
    (_FORM, {"form_index": 3}, "form_index 3"),
    (_FORM, {"password_field": "secret"}, "password_field 'secret'"),
    (_FORM, {"username_field": "login"}, "username_field 'login'"),
    ('<form method="post"><input type="password" name="pass"></form>', {}, "no username input"),
]


@pytest.mark.parametrize(("page", "login", "fragment"), _FORM_FAILURES)
async def test_a_form_that_cannot_be_picked_fails_with_what_was_found(
    page: str, login: dict[str, object], fragment: str
) -> None:
    """Zero or several candidates, a bad index or an override the form lacks name the problem."""
    site = _Site(login_page=page)
    async with _open(site, **login) as auth:
        with pytest.raises(LoginFailedError, match=fragment) as caught:
            await auth.login()
    _no_secret(caught.value)
    assert site.posts == []  # nothing was submitted
    assert auth.session.jar.names == frozenset()


async def test_form_index_picks_among_several_login_forms() -> None:
    """``form_index`` selects the second form, which posts to its own action."""
    site = _Site(login_page=_FORM + _OTHER_FORM)
    site.pages["/other"] = lambda r: httpx.Response(
        302, headers={"location": "/home", "set-cookie": "sid=sess-9f3a; Path=/"}
    )
    async with _open(site, form_index=1) as auth:
        await auth.login()
    (post,) = site.posts
    assert post.url.path == "/other"
    assert dict(parse_qsl(post.content.decode()))["u"] == _USER


async def test_overrides_and_extras_shape_the_body() -> None:
    """A field override renames the target input; an extra the form lacks is appended."""
    page = (
        '<form method="post" action="/signin"><input type="hidden" name="csrf" value="tkn1">'
        '<input type="text" name="nick"><input type="text" name="email">'
        '<input type="password" name="pass"><input type="hidden" name="tenant" value="old"></form>'
    )
    site = _Site(login_page=page)
    async with _open(
        site, username_field="nick", extra_fields=["tenant=acme", "remember=1"]
    ) as auth:
        await auth.login()
    body = dict(parse_qsl(site.posts[0].content.decode(), keep_blank_values=True))
    assert body["nick"] == _USER and body["email"] == ""
    assert body["tenant"] == "acme" and body["remember"] == "1"  # replaced, and appended


async def test_the_nearest_text_input_before_the_password_is_the_username() -> None:
    """With two text inputs the one just above the password is the account."""
    page = (
        '<form method="post" action="/signin"><input type="hidden" name="csrf" value="tkn1">'
        '<input type="text" name="search"><input type="email" name="mail">'
        '<input type="password" name="pass"></form>'
    )
    site = _Site(login_page=page)
    async with _open(site) as auth:
        await auth.login()
    assert dict(parse_qsl(site.posts[0].content.decode()))["mail"] == _USER


async def test_a_multipart_login_form_is_sent_as_multipart_text_parts() -> None:
    """A form with ``enctype=multipart/form-data`` is submitted as multipart, no file."""
    page = _FORM.replace('method="post"', 'method="post" enctype="multipart/form-data"')
    site = _Site(
        login_page=page,
        post=lambda r, b: httpx.Response(
            302, headers={"location": "/home", "set-cookie": "sid=sess-9f3a; Path=/"}
        ),
    )
    async with _open(site) as auth:
        await auth.login()
    post = site.posts[0]
    assert post.headers["content-type"].startswith("multipart/form-data")
    assert b'name="pass"' in post.content and _PASSWORD.encode() in post.content


# ---------------------------------------------------------------------------
# Gates: scope, scheme, delegated login
# ---------------------------------------------------------------------------


async def test_a_login_page_out_of_scope_fails_before_any_request() -> None:
    """The login URL must be in scope; nothing is sent to another host."""
    site = _Site()
    async with _open(site, url="http://elsewhere.test/signin") as auth:
        with pytest.raises(LoginFailedError, match="out of scope"):
            await auth.login()
    assert site.requests == []


async def test_the_password_is_never_sent_in_clear_to_an_https_target() -> None:
    """An ``http`` login page, or a form action that downgrades, fails on an ``https`` target."""
    site = _Site()
    async with _open(site, base="https://demo.test/", url="http://demo.test/signin") as auth:
        with pytest.raises(LoginFailedError, match="not https"):
            await auth.login()
    assert site.requests == []

    downgrade = _FORM.replace('action="/signin"', 'action="http://demo.test/signin"')
    site = _Site(login_page=downgrade)
    async with _open(site, base="https://demo.test/") as auth:
        with pytest.raises(LoginFailedError, match="not https"):
            await auth.login()
    assert site.posts == []


async def test_a_login_that_redirects_to_another_host_is_delegated_and_refused() -> None:
    """An SSO hop stops the handshake; the credentials only went to the in-scope action."""
    site = _Site(
        post=lambda r, b: httpx.Response(
            302, headers={"location": "https://idp.example/authorize?s=1"}
        )
    )
    async with _open(site) as auth:
        with pytest.raises(LoginFailedError, match=r"idp\.example: delegated login") as caught:
            await auth.login()
    _no_secret(caught.value)
    assert auth.session.jar.names == frozenset()


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------


async def test_a_wrong_password_fails_after_exactly_one_attempt() -> None:
    """The form is still there: the login failed, was never retried, and committed nothing."""
    site = _Site(post=lambda r, b: _html(_FORM, "<p>Invalid credentials</p>"))
    async with _open(site) as auth:
        with pytest.raises(LoginFailedError, match="still there") as caught:
            await auth.login()
    _no_secret(caught.value)
    assert len(site.posts) == 1
    assert (auth.session.generation, auth.session.jar.names) == (0, frozenset())


async def test_a_server_error_on_the_login_is_a_failed_login_and_is_not_retried() -> None:
    """A ``500`` on the ``POST`` fails the login; the single-attempt rule holds."""
    site = _Site(post=lambda r, b: httpx.Response(500, text="boom"))
    async with _open(site) as auth:
        with pytest.raises(LoginFailedError, match="500"):
            await auth.login()
    assert len(site.posts) == 1


_HOME_OK = {"/home": lambda r: _html("<p>Welcome back</p>")}
_HOME_OUT = {"/home": lambda r: _html("<p>Please sign in</p>")}


@pytest.mark.parametrize(
    ("login", "pages", "outcome"),
    [
        ({"logged_in_marker": "Welcome back"}, _HOME_OK, "confirmed"),
        ({"logged_in_marker": "Dashboard"}, _HOME_OK, "logged_in_marker not found"),
        ({"logged_out_marker": "Please sign in"}, _HOME_OUT, "logged_out_marker matched"),
        # the logged-out marker beats the logged-in one
        (
            {"logged_in_marker": "sign", "logged_out_marker": "sign in"},
            _HOME_OUT,
            "logged_out_marker matched",
        ),
        (
            {"check_url": "http://demo.test/account"},
            {**_HOME_OK, "/account": lambda r: _html("ok")},
            "confirmed",
        ),
        (
            {"check_url": "http://demo.test/account"},
            {**_HOME_OK, "/account": lambda r: httpx.Response(401)},
            "still looks logged out",
        ),
    ],
)
async def test_the_verification_order_markers_then_check_url(
    login: dict[str, object],
    pages: dict[str, Callable[[httpx.Request], httpx.Response]],
    outcome: str,
) -> None:
    """A marker decides first, then ``check_url``; each says what it saw when it fails."""
    site = _Site(pages=pages)
    async with _open(site, **login) as auth:
        if outcome == "confirmed":
            assert (await auth.login()).confirmed
            assert auth.session.generation == 1
        else:
            with pytest.raises(LoginFailedError, match=outcome) as caught:
                await auth.login()
            _no_secret(caught.value)
            assert auth.session.jar.names == frozenset()


async def test_without_a_marker_or_a_new_cookie_the_login_is_unconfirmed_not_failed() -> None:
    """No password form and no new cookie: nothing can tell, so it continues unconfirmed."""
    site = _Site(post=lambda r, b: httpx.Response(302, headers={"location": "/home"}))
    async with _open(site) as auth:
        result = await auth.login()
    assert not result.confirmed
    assert auth.session.generation == 1  # it is committed: the scan goes on, with a warning


async def test_a_rotated_cookie_value_counts_as_a_new_cookie() -> None:
    """A session id the target replaced at login (same name, new value) confirms the login."""
    site = _Site(
        post=lambda r, b: httpx.Response(
            302, headers={"location": "/home", "set-cookie": "pre=rotated-1; Path=/"}
        )
    )
    async with _open(site) as auth:
        assert (await auth.login()).confirmed


# ---------------------------------------------------------------------------
# Re-login and the confirmation callback
# ---------------------------------------------------------------------------


async def test_relogin_reports_a_failure_as_false_and_remembers_why() -> None:
    """The session's callback never raises: it returns ``False`` and notes the message."""
    site = _Site(post=lambda r, b: _html(_FORM))
    async with _open(site) as auth:
        assert await auth.relogin() is False
    assert auth.session.warnings() == []  # not counted yet: the Session counts, not the callback
    auth.session.failed_relogins += 1
    assert any("still there" in line for line in auth.session.warnings())


async def test_confirm_dropped_reads_the_check_url_with_the_live_session() -> None:
    """The confirmation says "logged out" for a 401 and "fine" for a 200."""
    state = {"status": 200}
    site = _Site(pages={"/account": lambda r: httpx.Response(state["status"], text="x")})
    async with _open(site, check_url="http://demo.test/account") as auth:
        await auth.login()
        assert await auth.confirm_dropped() is False
        state["status"] = 401
        assert await auth.confirm_dropped() is True


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_credentials_hide_the_password_in_repr_and_read_it_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``repr`` never prints the password; a missing variable is a clear failure."""
    assert _PASSWORD not in repr(Credentials(_USER, _PASSWORD))
    monkeypatch.setenv("WV_TEST_PW", _PASSWORD)
    assert Credentials.from_environment(_USER, "WV_TEST_PW").password == _PASSWORD
    monkeypatch.delenv("WV_TEST_PW")
    with pytest.raises(LoginFailedError, match="WV_TEST_PW"):
        Credentials.from_environment(_USER, "WV_TEST_PW")


async def test_confirm_dropped_falls_back_to_the_page_the_login_landed_on() -> None:
    """With no ``check_url`` the reference is the landing page; with neither, assume dropped."""
    state = {"status": 200}
    site = _Site(
        pages={
            "/home": lambda r: httpx.Response(
                state["status"], headers={"content-type": "text/html"}, text="<p>Welcome</p>"
            )
        }
    )
    async with _open(site) as auth:
        assert await auth.confirm_dropped() is True  # no login yet, nothing to ask
        await auth.login()  # lands on /home
        assert await auth.confirm_dropped() is False
        state["status"] = 401
        assert await auth.confirm_dropped() is True

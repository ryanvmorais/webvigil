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

import httpx2
import pytest

from tests.support import HandlerTransport
from webvigil.auth.login import Authenticator, Credentials
from webvigil.core.config import LoginSection, ScanConfig
from webvigil.core.errors import LoginFailedError
from webvigil.core.secrets import Secret, SecretKind, collect_secrets
from webvigil.core.target import Scope, Target
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient
from webvigil.http.session import MARKER_BODY_CHARS

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


def _html(*parts: str) -> httpx2.Response:
    """
    Args:
        *parts (str): HTML fragments for the body.

    Returns:
        httpx2.Response: A 200 HTML page.
    """
    return httpx2.Response(
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
        post: Callable[[httpx2.Request, dict[str, str]], httpx2.Response] | None = None,
        pages: dict[str, Callable[[httpx2.Request], httpx2.Response]] | None = None,
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
        self.requests: list[httpx2.Request] = []

    @property
    def posts(self) -> list[httpx2.Request]:
        """
        Returns:
            list[httpx2.Request]: Every ``POST`` the site received.
        """
        return [r for r in self.requests if r.method == "POST"]

    @staticmethod
    def _default_post(request: httpx2.Request, body: dict[str, str]) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The login ``POST``.
            body (dict[str, str]): Its parsed form body.

        Returns:
            httpx2.Response: A redirect to ``/home`` with a session cookie for the right
                password, the login page again otherwise.
        """
        if body.get("pass") == _PASSWORD and body.get("csrf") == "tkn1":
            return httpx2.Response(
                302, headers={"location": "/home", "set-cookie": "sid=sess-9f3a; Path=/"}
            )
        return _html(_FORM, "<p>Invalid credentials</p>")

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """
        Args:
            request (httpx2.Request): The request the client sent.

        Returns:
            httpx2.Response: The site's answer.
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
        return httpx2.Response(404, text="nope")


@contextlib.asynccontextmanager
async def _open(
    site: _Site, *, base: str = "http://demo.test/", scope: Scope = Scope.HOST, **login: object
) -> AsyncIterator[Authenticator]:
    """
    Args:
        site (_Site): The target to play.
        base (str): The scan target. Defaults to ``http://demo.test/``.
        scope (Scope): The target scope. Defaults to ``Scope.HOST``.
        **login (object): ``[auth.login]`` keys; ``url`` defaults to ``<base>signin``.

    Yields:
        Authenticator: One wired to a real ``HttpClient`` on ``site``, session attached.
    """
    options: dict[str, object] = {"url": f"{base}signin", "username": _USER}
    options.update(login)
    section = LoginSection(**options)  # type: ignore[arg-type]
    target = Target.parse(base, scope=scope)
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


async def test_the_session_holds_what_the_target_issued_and_the_credentials_the_password() -> None:
    """The scrub list's two sources: the session's issued values, the login's own password."""
    async with _open(_Site()) as auth:
        await auth.login()
        issued = {value.reveal() for value in auth.session.secrets}
        assert {"pre-77aa", "sess-9f3a"} <= issued
        assert {value.kind for value in auth.session.secrets} == {SecretKind.SESSION}
        # spec 024, RF-07: the password reaches the scrub through the credentials, not the jar
        assert _PASSWORD not in issued
        assert collect_secrets(auth.credentials) == {Secret(_PASSWORD, kind=SecretKind.PASSWORD)}


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
    site.pages["/other"] = lambda r: httpx2.Response(
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
        post=lambda r, b: httpx2.Response(
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
        with pytest.raises(LoginFailedError, match="not the target origin"):
            await auth.login()
    assert site.requests == []

    downgrade = _FORM.replace('action="/signin"', 'action="http://demo.test/signin"')
    site = _Site(login_page=downgrade)
    async with _open(site, base="https://demo.test/") as auth:
        with pytest.raises(LoginFailedError, match="not the target origin"):
            await auth.login()
    assert site.posts == []


@pytest.mark.parametrize(
    ("location", "scope"),
    [
        ("http://demo.test/home?next=1", Scope.HOST),
        ("https://other.demo.test/home?next=1", Scope.SUBDOMAINS),
        ("https://demo.test:8443/home?next=1", Scope.HOST),
    ],
    ids=["plain-http", "in-scope-subdomain", "same-host-other-port"],
)
async def test_a_login_body_is_not_replayed_where_the_password_may_not_go(
    location: str, scope: Scope
) -> None:
    """The login fails with an error that names the reason and no URL; the password stays."""
    site = _Site(post=lambda r, b: httpx2.Response(307, headers={"location": location}))
    async with _open(site, base="https://demo.test/", scope=scope) as auth:
        with pytest.raises(LoginFailedError) as caught:
            await auth.login()
    assert str(caught.value) == (
        "login redirects to a destination that may not receive the password"
    )
    _no_secret(caught.value)
    assert [(r.method, str(r.url)) for r in site.requests] == [
        ("GET", "https://demo.test/signin"),
        ("POST", "https://demo.test/signin"),
    ]
    assert auth.session.jar.names == frozenset()


async def test_a_login_body_still_follows_the_https_upgrade() -> None:
    """The ``https`` form of an ``http`` target may get the password: the ``307`` is followed."""
    site = _Site(
        post=lambda r, b: httpx2.Response(307, headers={"location": "https://demo.test/signin2"}),
        pages={"/signin2": lambda r: _html("<p>Welcome</p>")},
    )
    async with _open(site) as auth:
        await auth.login()
    assert [str(r.url) for r in site.posts] == [
        "http://demo.test/signin",
        "https://demo.test/signin2",
    ]
    assert dict(parse_qsl(site.posts[1].content.decode()))["pass"] == _PASSWORD


async def test_a_login_that_redirects_to_another_host_is_delegated_and_refused() -> None:
    """An SSO hop stops the handshake; the credentials only went to the in-scope action."""
    site = _Site(
        post=lambda r, b: httpx2.Response(
            302, headers={"location": "https://idp.example/authorize?s=1"}
        )
    )
    async with _open(site) as auth:
        with pytest.raises(LoginFailedError) as caught:
            await auth.login()
    assert str(caught.value) == "login redirects to idp.example: delegated login is not supported"
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
    site = _Site(post=lambda r, b: httpx2.Response(500, text="boom"))
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
            {**_HOME_OK, "/account": lambda r: httpx2.Response(401)},
            "still looks logged out",
        ),
    ],
)
async def test_the_verification_order_markers_then_check_url(
    login: dict[str, object],
    pages: dict[str, Callable[[httpx2.Request], httpx2.Response]],
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


async def test_the_markers_read_only_the_head_of_the_body() -> None:
    """A marker past ``MARKER_BODY_CHARS`` is not seen: the regex never runs on the whole body."""
    padding = "x" * MARKER_BODY_CHARS
    pages = {"/home": lambda r: _html(padding, "<p>Welcome back</p>")}
    async with _open(_Site(pages=pages), logged_in_marker="Welcome back") as auth:
        with pytest.raises(LoginFailedError, match="logged_in_marker not found"):
            await auth.login()
    pages = {"/home": lambda r: _html("<p>Welcome back</p>", padding, "Please sign in")}
    async with _open(
        _Site(pages=pages), logged_in_marker="Welcome back", logged_out_marker="Please sign in"
    ) as auth:
        assert (await auth.login()).confirmed


async def test_without_a_marker_or_a_new_cookie_the_login_is_unconfirmed_not_failed() -> None:
    """No password form and no new cookie: nothing can tell, so it continues unconfirmed."""
    site = _Site(post=lambda r, b: httpx2.Response(302, headers={"location": "/home"}))
    async with _open(site) as auth:
        result = await auth.login()
    assert not result.confirmed
    assert auth.session.generation == 1  # it is committed: the scan goes on, with a warning


async def test_a_rotated_cookie_value_counts_as_a_new_cookie() -> None:
    """A session id the target replaced at login (same name, new value) confirms the login."""
    site = _Site(
        post=lambda r, b: httpx2.Response(
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
    site = _Site(pages={"/account": lambda r: httpx2.Response(state["status"], text="x")})
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
    """The password is a secret however it arrives; a missing variable is a clear failure."""
    given = Credentials(_USER, _PASSWORD)  # a plain string, wrapped at once
    assert isinstance(given.password, Secret)
    assert (given.password.kind, given.password.reveal()) == (SecretKind.PASSWORD, _PASSWORD)
    assert _PASSWORD not in repr(given) + str(given)
    kept = Secret(_PASSWORD, kind=SecretKind.PASSWORD)
    assert Credentials(_USER, kept).password is kept  # a secret is kept as it is
    monkeypatch.setenv("WV_TEST_PW", _PASSWORD)
    read = Credentials.from_environment(_USER, "WV_TEST_PW").password
    assert isinstance(read, Secret)
    assert (read.kind, read.reveal()) == (SecretKind.PASSWORD, _PASSWORD)
    monkeypatch.delenv("WV_TEST_PW")
    with pytest.raises(LoginFailedError, match="WV_TEST_PW"):
        Credentials.from_environment(_USER, "WV_TEST_PW")


async def test_confirm_dropped_falls_back_to_the_page_the_login_landed_on() -> None:
    """With no ``check_url`` the reference is the landing page; with neither, assume dropped."""
    state = {"status": 200}
    site = _Site(
        pages={
            "/home": lambda r: httpx2.Response(
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


# ---------------------------------------------------------------------------
# The cookie transition and the reference page (spec 020)
# ---------------------------------------------------------------------------


async def test_the_transition_holds_the_cookies_before_and_after_the_post() -> None:
    """``pre`` is what the login page set, ``post`` what the chain ended with; both are values."""
    site = _Site()
    async with _open(site) as auth:
        assert auth.transition is None
        await auth.login()

    assert auth.transition is not None
    pre, post = auth.transition.pre, auth.transition.post
    assert {name: value.reveal() for name, value in pre.items()} == {"pre": "pre-77aa"}
    assert {name: value.reveal() for name, value in post.items()} == {
        "pre": "pre-77aa",
        "sid": "sess-9f3a",
    }
    # spec 024, RF-05: the values are session secrets, and the record prints no value
    assert all(value.kind is SecretKind.SESSION for value in [*pre.values(), *post.values()])
    assert "sess-9f3a" not in repr(auth.transition)
    assert "sid" in repr(auth.transition)  # the positive control: the names are there


async def test_a_failed_login_records_no_transition_and_a_relogin_replaces_it() -> None:
    """Only a committed login leaves a transition behind; the next one overwrites it."""
    site = _Site(post=lambda r, b: _html(_FORM, "<p>Invalid credentials</p>"))
    async with _open(site) as auth:
        with pytest.raises(LoginFailedError):
            await auth.login()
        assert auth.transition is None

        site.post = _Site._default_post
        await auth.login()
        first = auth.transition
        await auth.login()
        assert auth.transition is not first and auth.transition == first


async def test_the_reference_page_is_check_url_else_the_landing_page() -> None:
    """``reference_url``: none before a login, then ``check_url`` if set, else the landing page."""
    site = _Site(pages={"/account": lambda r: _html("ok")})
    async with _open(site) as plain:
        assert plain.reference_url is None
        await plain.login()
        assert plain.reference_url == "http://demo.test/home"
    async with _open(site, check_url="http://demo.test/account") as checked:
        assert checked.reference_url == "http://demo.test/account"

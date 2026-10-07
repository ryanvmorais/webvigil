"""
SessionScanner — the seen-id, sampling, fixation and logout steps — spec 020 RF-03 to RF-09.

The real ``HttpClient`` and ``SessionScanner`` run against a hand-written site (:class:`_Site`)
served by ``HandlerTransport``. The site keeps one log of every request with its ``Cookie``
header, which is how the tests prove what each step sent: the samples carried no cookie, the
fixation confirmation sent the session minus one cookie, the logout test asked the oracle first,
logged out with the live session and replayed the snapshot anonymously. The authenticator is a
stand-in (a transition and a reference page); the login itself is tested in ``test_auth_login``.

The last test of the file is the one that matters most for users: no hit, anywhere, contains a
cookie value.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest

from tests.support import HandlerTransport, make_page
from webvigil.auth.login import CookieTransition
from webvigil.checks.session.scanner import SessionHit, SessionScanner, kinds_for
from webvigil.core.config import ScanConfig
from webvigil.core.findings import Confidence, Severity
from webvigil.core.target import Scope, Target
from webvigil.crawler.forms import Form, FormField
from webvigil.http import client as client_mod
from webvigil.http.client import HttpClient
from webvigil.http.session import Session, SessionJar

_BASE = "http://demo.test"
_REF = f"{_BASE}/account"
_HEX32 = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero the retry backoff so a failing request does not sleep."""
    monkeypatch.setattr(client_mod, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(client_mod, "BACKOFF_JITTER_S", 0.0)


class _Site:
    """A target with a protected ``/account``, a ``/logout`` and an entry page."""

    def __init__(self) -> None:
        self.log: list[tuple[str, str, str]] = []  # (method, path, Cookie header)
        self.valid = {"ok"}  # session values /account accepts
        self.public_account = False  # /account answers 200 to everyone
        self.account_needs_cookie = True  # False: /account ignores the cookie entirely
        self.logout_invalidates = True
        self.logout_status = 200
        self.entry_cookies: Callable[[int], list[str]] = lambda n: []
        self.hits = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        """
        Args:
            request (httpx.Request): The request the client sent.

        Returns:
            httpx.Response: The site's answer.
        """
        cookie = request.headers.get("cookie", "")
        self.log.append((request.method, request.url.path, cookie))
        path = request.url.path
        if path == "/":
            self.hits += 1
            headers = [("set-cookie", value) for value in self.entry_cookies(self.hits)]
            headers.append(("content-type", "text/html"))
            return httpx.Response(200, headers=headers, text="<html>entry</html>")
        if path == "/account":
            sid = dict(p.split("=", 1) for p in cookie.split("; ") if "=" in p).get("sid", "")
            if self.public_account or not self.account_needs_cookie or sid in self.valid:
                return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>hi</p>")
            return httpx.Response(401, text="no")
        if path == "/logout":
            if self.logout_status < 500 and self.logout_invalidates:
                self.valid.clear()
            return httpx.Response(self.logout_status, text="bye")
        return httpx.Response(404, text="nope")


def _config(**session: object) -> ScanConfig:
    """
    Args:
        **session (object): ``[session]`` keys.

    Returns:
        ScanConfig: A configuration with a login (for ``logout_url`` and friends) and ``session``.
    """
    return ScanConfig.model_validate(
        {
            "session": session,
            "auth": {"login": {"url": f"{_BASE}/signin", "username": "u"}},
        }
    )


def _committed_session(*cookies: str) -> Session:
    """
    Args:
        *cookies (str): ``Set-Cookie`` values the (stand-in) login ended with.

    Returns:
        Session: A session whose jar holds those cookies, as after a committed login.
    """
    jar = SessionJar("demo.test")
    jar.begin()
    answer = httpx.Response(
        200,
        headers=[("set-cookie", c) for c in cookies],
        request=httpx.Request("GET", f"{_BASE}/"),
    )
    jar.absorb(answer, handshake=True)
    jar.commit()
    return Session(jar=jar, is_login_url=lambda url: urlsplit(url).path == "/signin")


def _auth(
    pre: dict[str, str], post: dict[str, str], reference: str | None = _REF
) -> SimpleNamespace:
    """
    Args:
        pre (dict[str, str]): The cookies before the login.
        post (dict[str, str]): The cookies after it.
        reference (str | None): The reference page URL. Defaults to ``/account``.

    Returns:
        SimpleNamespace: The two attributes the scanner reads from an ``Authenticator``.
    """
    return SimpleNamespace(transition=CookieTransition(pre=pre, post=post), reference_url=reference)


def _scanner(
    site: _Site,
    *,
    kinds: set[str],
    config: ScanConfig | None = None,
    pages: tuple = (),
    forms: tuple = (),
    session: Session | None = None,
    auth: SimpleNamespace | None = None,
) -> tuple[SessionScanner, HttpClient]:
    """
    Args:
        site (_Site): The target to play.
        kinds (set[str]): The hit kinds to run.
        config (ScanConfig | None): Defaults to a login and no switches.
        pages (tuple): Crawled pages.
        forms (tuple): The form inventory.
        session (Session | None): The login session.
        auth (SimpleNamespace | None): The authenticator stand-in.

    Returns:
        tuple[SessionScanner, HttpClient]: The scanner and its (not yet opened) client.
    """
    target = Target.parse(_BASE, scope=Scope.HOST)
    cfg = config or _config()
    http = HttpClient(target, cfg, transport=HandlerTransport(site.handle))
    scanner = SessionScanner(
        http,
        target,
        cfg,
        pages,
        forms,
        session=session,
        authenticator=auth,  # type: ignore[arg-type]
        kinds=frozenset(kinds),
    )
    if session is not None:
        http.use_session(session)  # as the orchestrator does after the login
    return scanner, http


def _page(url: str, *set_cookies: str, text: str = "<html></html>"):  # type: ignore[no-untyped-def]
    """
    Args:
        url (str): The page URL.
        *set_cookies (str): Raw ``Set-Cookie`` values.
        text (str): The body.

    Returns:
        Page: A crawled page.
    """
    return make_page(url=url, set_cookies=set_cookies, text=text)


# ---------------------------------------------------------------------------
# Weak ids
# ---------------------------------------------------------------------------


async def test_a_weak_cookie_the_crawl_saw_is_one_hit_with_structural_facts() -> None:
    """One hit per weak name, on its first value and first page; good ids and plain cookies pass."""
    pages = (
        _page(f"{_BASE}/", "session=abc123; Path=/", f"sid={_HEX32}; Path=/", "lang=en"),
        _page(f"{_BASE}/other", "session=zzz999; Path=/"),
    )
    scanner, http = _scanner(_Site(), kinds={"weak"}, pages=pages)
    async with http:
        hits = await scanner.run()

    (hit,) = hits
    assert (hit.kind, hit.name, hit.url) == ("weak", "session", f"{_BASE}/")
    assert hit.severity is Severity.MEDIUM and hit.confidence is Confidence.MEDIUM
    facts = dict(hit.facts)
    assert facts["length"] == "6" and facts["alphabet"] == "lower hex"
    assert facts["estimated bits"] == "24" and "shorter than 16" in facts["rules"]
    assert "samples" not in facts


async def test_nothing_is_sent_without_the_sampling_switch() -> None:
    """Judging the cookies already seen is local: not one request."""
    site = _Site()
    scanner, http = _scanner(site, kinds={"weak"}, pages=(_page(f"{_BASE}/", "sid=abc123"),))
    async with http:
        await scanner.run()
    assert site.log == []


async def test_sampling_visits_the_entry_url_anonymously_and_finds_a_counter() -> None:
    """``sample_count`` cookie-less visits; a counter id is a HIGH, high-confidence hit."""
    site = _Site()
    site.entry_cookies = lambda n: [f"sid={1000 + n}; Path=/"]
    config = _config(sample_ids=True, sample_count=5)
    scanner, http = _scanner(site, kinds={"weak"}, config=config)
    async with http:
        hits = await scanner.run()

    assert [path for _m, path, _c in site.log] == ["/"] * 5
    assert all(cookie == "" for _m, _p, cookie in site.log)  # no state carried between visits
    (hit,) = hits
    assert hit.severity is Severity.HIGH and hit.confidence is Confidence.HIGH
    facts = dict(hit.facts)
    assert facts["samples"] == "5" and "consecutive numbers" in facts["rules"]


async def test_the_seen_and_sampled_judgements_of_one_cookie_are_one_hit() -> None:
    """A weak cookie seen in the crawl and repeated across visits is a single finding."""
    site = _Site()
    site.entry_cookies = lambda n: ["session=abc123; Path=/"]
    config = _config(sample_ids=True, sample_count=4)
    pages = (_page(f"{_BASE}/about", "session=abc123; Path=/"),)
    scanner, http = _scanner(site, kinds={"weak"}, config=config, pages=pages)
    async with http:
        hits = await scanner.run()

    (hit,) = hits
    assert hit.url == f"{_BASE}/about"  # where the crawl first saw it
    assert "anonymous visits got an id another visit had" in dict(hit.facts)["rules"]


async def test_a_target_that_issues_no_session_cookie_to_a_visitor_says_so() -> None:
    """No cookie in any sample: a warning, no hit."""
    site = _Site()
    scanner, http = _scanner(site, kinds={"weak"}, config=_config(sample_ids=True, sample_count=3))
    async with http:
        hits = await scanner.run()
    assert hits == []
    assert any("issued no session cookie" in w for w in scanner.warnings)


async def test_random_long_ids_are_clean() -> None:
    """Good ids, seen and sampled, produce no hit."""
    site = _Site()
    ids = ["9f8e7d6c5b4a39281706f5e4d3c2b1a0", "03a7c1e95d2b48f6a0c9e1b3d5f7a2c4"]
    site.entry_cookies = lambda n: [f"sid={ids[n % 2]}{n:02d}; Path=/"]
    scanner, http = _scanner(site, kinds={"weak"}, config=_config(sample_ids=True, sample_count=4))
    async with http:
        assert await scanner.run() == []


# ---------------------------------------------------------------------------
# Fixation
# ---------------------------------------------------------------------------


async def _fixation(
    site: _Site,
    pre: dict[str, str],
    post: dict[str, str],
    *,
    reference: str | None = _REF,
    confirmed: bool = True,
    cookies: tuple[str, ...] = ("sid=ok; Path=/", "lang=en; Path=/"),
) -> tuple[list[SessionHit], SessionScanner]:
    """
    Args:
        site (_Site): The target.
        pre (dict[str, str]): Cookies before the login.
        post (dict[str, str]): Cookies after it.
        reference (str | None): The reference page. Defaults to ``/account``.
        confirmed (bool): Whether the login was confirmed. Defaults to ``True``.
        cookies (tuple[str, ...]): What the live session holds.

    Returns:
        tuple[list[SessionHit], SessionScanner]: The hits and the scanner (for warnings).
    """
    session = _committed_session(*cookies)
    session.confirmed = confirmed
    scanner, http = _scanner(
        site, kinds={"fixation"}, session=session, auth=_auth(pre, post, reference)
    )
    async with http:
        return await scanner.run(), scanner


async def test_an_unchanged_cookie_the_page_needs_is_a_confirmed_fixation() -> None:
    """Same value before and after, and the page is logged out without it: HIGH."""
    site = _Site()
    hits, _scn = await _fixation(site, {"sid": "ok"}, {"sid": "ok"})

    (hit,) = hits
    assert (hit.kind, hit.name, hit.severity) == ("fixation", "sid", Severity.MEDIUM)
    assert hit.confidence is Confidence.HIGH and hit.url == f"{_BASE}/signin"
    assert dict(hit.facts)["verified"].startswith("yes")
    # the one confirming request: the reference page, with the session minus the candidate
    assert site.log == [("GET", "/account", "lang=en")]


@pytest.mark.parametrize(
    ("pre", "post"),
    [
        ({"sid": "anon"}, {"sid": "new"}),  # renewed at login: fine
        ({}, {"sid": "new"}),  # appeared only after the login
        ({"sid": "anon"}, {}),  # cleared
        ({"lang": "en"}, {"lang": "en"}),  # unchanged, but not a session-looking name
    ],
)
async def test_a_cookie_that_changed_or_is_not_a_session_is_never_a_candidate(
    pre: dict[str, str], post: dict[str, str]
) -> None:
    """Renewed, appeared, cleared or not session-looking: no hit and no request."""
    site = _Site()
    hits, _scn = await _fixation(site, pre, post)
    assert hits == [] and site.log == []


async def test_a_jwt_shaped_cookie_is_skipped() -> None:
    """A signed token is not a random id; an unchanged one is not fixation."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
    site = _Site()
    hits, _scn = await _fixation(site, {"auth_token": jwt}, {"auth_token": jwt})
    assert hits == [] and site.log == []


async def test_an_unchanged_cookie_the_page_does_not_need_is_not_fixation() -> None:
    """If the page still answers without it, it is a tracking id, not the session."""
    site = _Site()
    site.account_needs_cookie = False
    hits, _scn = await _fixation(site, {"sessionid": "a"}, {"sessionid": "a"})
    assert hits == []


@pytest.mark.parametrize(("reference", "confirmed"), [(None, True), (_REF, False)])
async def test_without_a_reference_or_a_confirmed_login_the_hit_is_medium_and_says_so(
    reference: str | None, confirmed: bool
) -> None:
    """The requirement could not be verified: MEDIUM confidence, no request, a fact that says so."""
    site = _Site()
    hits, _scn = await _fixation(
        site, {"sid": "ok"}, {"sid": "ok"}, reference=reference, confirmed=confirmed
    )
    (hit,) = hits
    assert hit.confidence is Confidence.MEDIUM and dict(hit.facts)["verified"] == "no"
    assert site.log == []


async def test_at_most_three_candidates_are_confirmed() -> None:
    """Five unchanged session cookies cost three confirming requests, in name order."""
    site = _Site()
    names = {f"sess{i}": "ok" for i in range(5)}
    hits, _scn = await _fixation(
        site, names, names, cookies=tuple(f"{n}=ok; Path=/" for n in names)
    )
    assert [h.name for h in hits] == ["sess0", "sess1", "sess2"]
    assert len(site.log) == 3


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

_LOGOUT_PAGE = '<html><a href="/home">home</a> <a href="/logout">Log out</a></html>'


async def _logout(
    site: _Site,
    *,
    pages: tuple = (),
    forms: tuple = (),
    logout_url: str | None = None,
) -> tuple[list[SessionHit], SessionScanner, Session]:
    """
    Args:
        site (_Site): The target.
        pages (tuple): The crawled pages (where a logout link is looked for).
        forms (tuple): The form inventory (where a logout form is looked for).
        logout_url (str | None): ``[auth.login] logout_url``. Defaults to ``None``.

    Returns:
        tuple[list[SessionHit], SessionScanner, Session]: The hits, the scanner and the session.
    """
    session = _committed_session("sid=ok; Path=/")
    config = ScanConfig.model_validate(
        {
            "session": {"test_logout": True},
            "auth": {
                "login": {"url": f"{_BASE}/signin", "username": "u", "logout_url": logout_url}
            },
        }
    )
    scanner, http = _scanner(
        site,
        kinds={"logout"},
        config=config,
        pages=pages,
        forms=forms,
        session=session,
        auth=_auth({}, {}),
    )
    async with http:
        hits = await scanner.run()
    return hits, scanner, session


async def test_a_logout_that_leaves_the_session_valid_is_a_hit() -> None:
    """Oracle, logout with the session, then the snapshot replayed anonymously: still valid."""
    site = _Site()
    site.logout_invalidates = False
    hits, _scn, session = await _logout(site, pages=(_page(f"{_BASE}/", text=_LOGOUT_PAGE),))

    (hit,) = hits
    assert (hit.kind, hit.name, hit.severity) == ("logout", "sid", Severity.MEDIUM)
    assert hit.confidence is Confidence.HIGH and hit.url == f"{_BASE}/logout"
    assert site.log == [
        ("GET", "/account", ""),  # the oracle: anonymous, must look logged out
        ("GET", "/logout", "sid=ok"),  # the logout, with the live session
        ("GET", "/account", "sid=ok"),  # the replay: the snapshot, nothing else
    ]
    assert session.closed  # no re-login after the logout


async def test_a_logout_that_invalidates_the_session_is_not_a_hit() -> None:
    """The replay is rejected: the logout works, nothing is reported."""
    site = _Site()
    hits, _scn, session = await _logout(site, pages=(_page(f"{_BASE}/", text=_LOGOUT_PAGE),))
    assert hits == [] and session.closed


async def test_the_configured_logout_url_wins_over_the_crawl() -> None:
    """``logout_url`` is requested; a link in the crawl is not looked for."""
    site = _Site()
    site.logout_invalidates = False
    hits, _scn, _session = await _logout(
        site,
        pages=(_page(f"{_BASE}/", text='<a href="/logout">out</a>'),),
        logout_url=f"{_BASE}/logout",
    )
    assert len(hits) == 1
    assert [p for _m, p, _c in site.log] == ["/account", "/logout", "/account"]


async def test_a_post_logout_form_is_submitted_with_its_own_fields() -> None:
    """With no link, the first POST logout form is submitted (token and defaults)."""
    seen: dict[str, str] = {}
    site = _Site()
    site.logout_invalidates = False
    original = site.handle

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/logout":
            seen["method"] = request.method
            seen["body"] = request.content.decode()
        return original(request)

    site.handle = handle  # type: ignore[method-assign]
    form = Form(
        method="POST",
        action=f"{_BASE}/logout",
        enctype="application/x-www-form-urlencoded",
        fields=(FormField(name="csrf", type="hidden", value="t0k"),),
        source_url=f"{_BASE}/",
    )
    hits, _scn, _session = await _logout(site, forms=(form,))
    assert len(hits) == 1
    assert seen == {"method": "POST", "body": "csrf=t0k"}


@pytest.mark.parametrize(
    "page",
    [
        _page(f"{_BASE}/", text='<a href="https://evil.test/logout">out</a>'),  # out of scope
        _page(f"{_BASE}/", text='<a href="/home">home</a>'),  # no logout link at all
    ],
)
async def test_without_an_in_scope_logout_endpoint_the_test_is_skipped_with_a_warning(page) -> None:  # type: ignore[no-untyped-def]
    """No guessing of ``/logout``: a warning and not one request."""
    site = _Site()
    hits, scanner, session = await _logout(site, pages=(page,))
    assert hits == [] and site.log == [] and not session.closed
    assert any("no logout endpoint found" in w for w in scanner.warnings)


async def test_a_public_reference_page_makes_the_test_meaningless_so_it_is_skipped() -> None:
    """If an anonymous visitor reaches the page, "still valid" proves nothing: no logout is sent."""
    site = _Site()
    site.public_account = True
    hits, scanner, session = await _logout(site, pages=(_page(f"{_BASE}/", text=_LOGOUT_PAGE),))
    assert hits == [] and not session.closed
    assert [p for _m, p, _c in site.log] == ["/account"]  # the oracle only
    assert any("reference page is public" in w for w in scanner.warnings)


async def test_a_failing_logout_request_is_skipped_and_leaves_the_session_open() -> None:
    """A 5xx on the logout: a warning, no replay, the session still usable."""
    site = _Site()
    site.logout_status = 503
    hits, scanner, session = await _logout(site, pages=(_page(f"{_BASE}/", text=_LOGOUT_PAGE),))
    assert hits == [] and not session.closed
    assert [p for _m, p, _c in site.log][-1] == "/logout"
    assert any("answered 503" in w for w in scanner.warnings)


# ---------------------------------------------------------------------------
# The pass as a whole
# ---------------------------------------------------------------------------


async def test_a_step_that_fails_costs_a_warning_not_the_other_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One broken step is reported; the others still run and return their hits."""
    site = _Site()
    scanner, http = _scanner(
        site, kinds={"weak", "fixation"}, pages=(_page(f"{_BASE}/", "session=abc123"),)
    )

    async def boom() -> list[SessionHit]:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(scanner, "_fixation", boom)
    async with http:
        hits = await scanner.run()

    assert [h.kind for h in hits] == ["weak"]
    assert any("fixation step failed: kaboom" in w for w in scanner.warnings)


def test_kinds_follow_the_selected_check_ids() -> None:
    """Only the kinds whose checks are selected are asked for."""
    assert kinds_for(["session.id.weak", "http.cookies.flags"]) == {"weak"}
    assert kinds_for(["session.fixation", "session.logout.not-invalidated"]) == {
        "fixation",
        "logout",
    }
    assert kinds_for([]) == frozenset()


async def test_no_hit_contains_a_cookie_value() -> None:
    """RNF-07 across every path: plant a recognisable value in each source, search every hit."""
    secret = "SECRETv4lue"  # 11 chars: weak, so a hit exists
    site = _Site()
    site.entry_cookies = lambda n: [f"session={secret}; Path=/"]
    site.logout_invalidates = False
    site.valid = {secret}
    config = ScanConfig.model_validate(
        {
            "session": {"sample_ids": True, "sample_count": 3, "test_logout": True},
            "auth": {"login": {"url": f"{_BASE}/signin", "username": "u"}},
        }
    )
    session = _committed_session(f"sid={secret}; Path=/")
    pages = (_page(f"{_BASE}/", f"session={secret}; Path=/", text=_LOGOUT_PAGE),)
    scanner, http = _scanner(
        site,
        kinds={"weak", "fixation", "logout"},
        config=config,
        pages=pages,
        session=session,
        auth=_auth({"sid": secret}, {"sid": secret}),
    )
    async with http:
        hits = await scanner.run()

    assert {h.kind for h in hits} == {"weak", "fixation", "logout"}
    for hit in hits:
        assert secret not in repr(hit)
        assert secret[:4] not in repr(hit.facts) and secret[-4:] not in repr(hit.facts)
    assert not any(secret in w for w in scanner.warnings)

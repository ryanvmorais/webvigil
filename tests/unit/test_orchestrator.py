"""
Orchestrator: mode gating, check selection, error isolation, dedupe — RF-11, RF-15.

The autouse ``_stub_crawler`` fixture replaces the crawler with one that returns
a single blank page, so the tests exercise the orchestrator's own logic — the
Active gate, fingerprint dedup, per-check error isolation, warning surfacing —
with no HTTP. The check classes (:class:`PassiveOne`, :class:`Boom`, ...) are
tiny local stand-ins that emit canned findings or raise.
"""

from __future__ import annotations

import asyncio
import os
from typing import ClassVar

import httpx2
import pytest

from webvigil.auth.login import Credentials, LoginResult
from webvigil.checks.base import Check
from webvigil.checks.session.checks import (
    LogoutNotInvalidatedCheck,
    SessionFixationCheck,
    WeakSessionIdCheck,
)
from webvigil.checks.session.scanner import SessionHit
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page, ScanContext
from webvigil.core.errors import ActiveModeNotAuthorized, LoginFailedError, ScanDeadlineExceeded
from webvigil.core.findings import Category, Confidence, Finding, Location, ScanMode, Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import LoginSummary
from webvigil.core.target import Target
from webvigil.http.addresses import AddressGuard, AddressNotices
from webvigil.http.session import Session, SessionJar

_TARGET = "https://example.com/"


def _page() -> Page:
    """
    Returns:
        Page: A single blank HTML page at the target URL.
    """
    return Page(
        requested_url=_TARGET,
        url=_TARGET,
        status_code=200,
        headers=httpx2.Headers({"content-type": "text/html"}),
        text="<html></html>",
        elapsed_ms=1.0,
    )


class _StubCrawler:
    """A crawler that discovers exactly one blank page and finds no forms."""

    forms: tuple[object, ...] = ()
    skipped_destructive = 0
    skipped_by_robots = 0
    robots_unreadable: str | None = None
    limit_warning: str | None = None
    post_summary = None  # spec 018: the real crawler exposes the POST phase tally

    def __init__(self, *_args: object, **_kwargs: object) -> None: ...

    async def discover(self) -> list[Page]:
        return [_page()]


@pytest.fixture(autouse=True)
def _stub_crawler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the orchestrator's ``Crawler`` for :class:`_StubCrawler`."""
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


class _Base(Check):
    """
    Shared base for the local test checks: a HEADERS check whose ``_finding`` builds
    a deduplicable finding keyed by an arbitrary string.
    """

    name = "test check"
    category = Category.HEADERS
    default_severity = Severity.LOW

    def _finding(self, key: str) -> object:
        loc = Location(url=_TARGET, header="X-Test")
        return self.finding(
            title="t",
            description="d",
            remediation="r",
            location=loc,
            confidence=Confidence.HIGH,
            dedup_key=key,
        )


class PassiveOne(_Base):
    id = "test.passive.one"

    async def run(self, ctx: ScanContext) -> list[object]:
        return [self._finding("a")]


class PassiveTwo(_Base):
    id = "test.passive.two"

    async def run(self, ctx: ScanContext) -> list[object]:
        # Same finding emitted twice (e.g. seen on two pages) plus a distinct one.
        return [self._finding("a"), self._finding("a"), self._finding("b")]


class ActiveOne(_Base):
    id = "test.active.one"
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[object]:
        return [self._finding("active")]


class Boom(_Base):
    id = "test.boom"

    async def run(self, ctx: ScanContext) -> list[object]:
        raise RuntimeError("kaboom")


async def test_findings_are_deduped_by_fingerprint() -> None:
    """Findings with the same fingerprint collapse to one; distinct ones are kept."""
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne, PassiveTwo]).run(_TARGET)
    # The fingerprint carries the check id, so PassiveOne("a") and PassiveTwo("a") are two
    # findings; PassiveTwo's own repeat of "a" collapses -> one("a"), two("a"), two("b").
    assert len(result.findings) == 3
    assert sorted(f.fingerprint for f in result.findings) == sorted(
        {f.fingerprint for f in result.findings}
    )
    assert result.metadata.pages_scanned == 1


async def test_the_same_finding_from_two_checks_is_reported_once() -> None:
    """Two check classes that share an id (a subclass, a plugin) report one finding, not two."""

    class PassiveOneAgain(PassiveOne):
        pass

    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne, PassiveOneAgain]).run(
        _TARGET
    )
    assert [f.check_id for f in result.findings] == ["test.passive.one"]


class _Many(_Base):
    """A check that reports ``count`` distinct findings."""

    id = "test.many"
    count: ClassVar[int] = 0

    async def run(self, ctx: ScanContext) -> list[object]:
        return [self._finding(str(n)) for n in range(type(self).count)]


@pytest.mark.parametrize(("count", "cut"), [(3, False), (4, True)])
async def test_a_check_keeps_at_most_the_cap_of_distinct_findings(
    monkeypatch: pytest.MonkeyPatch, count: int, cut: bool
) -> None:
    """At the cap every finding stays; one past it, the first ``cap`` stay and the scan says so."""
    monkeypatch.setattr(orch_mod, "FINDINGS_PER_CHECK_CAP", 3)
    monkeypatch.setattr(_Many, "count", count)
    result = await Orchestrator(ScanConfig(), check_types=[_Many]).run(_TARGET)
    assert len(result.findings) == 3
    warned = [w for w in result.warnings if "reported more than 3 findings" in w]
    assert warned == (
        ["check test.many reported more than 3 findings; the first 3 are kept"] if cut else []
    )


async def test_a_raising_check_is_isolated() -> None:
    """A check that raises is recorded as an error; the other checks' findings still land."""
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne, Boom]).run(_TARGET)
    assert len(result.findings) == 1
    assert [e.check_id for e in result.errors] == ["test.boom"]
    assert result.errors[0].message == "RuntimeError"


async def test_a_check_traceback_carries_no_local_path() -> None:
    """The traceback travels with the JSON report: no install directory, no OS user name."""
    from pathlib import Path

    result = await Orchestrator(ScanConfig(), check_types=[Boom]).run(_TARGET)
    traceback = result.errors[0].traceback
    assert traceback.splitlines()[-1] == "RuntimeError"
    assert str(Path(__file__).resolve().parents[2]) not in traceback
    assert str(Path.home()) not in traceback
    assert "test_orchestrator.py" in traceback  # the frame is still named
    # a frame inside the package keeps its path in it: only an absolute path is cut short
    package_frame = os.path.join("webvigil", "core", "orchestrator.py")
    assert f'File "{package_frame}", line ' in traceback


@pytest.mark.parametrize(
    "where",
    ["/srv/plugins/acme/check.py", "D:\\work\\acme\\check.py", "D:/work/acme/check.py"],
)
def test_a_frame_outside_the_install_and_home_keeps_only_its_file_name(where: str) -> None:
    r"""A plugin outside every known directory (a Windows runner's ``D:\a\...``) is cut too."""
    from webvigil.core.output import portable_traceback

    try:
        exec(compile("raise RuntimeError('kaboom')", where, "exec"))
    except RuntimeError as exc:
        text = portable_traceback(exc)
    assert 'File "check.py", line 1' in text
    assert "acme" not in text


async def test_a_static_cookie_or_header_echoed_into_evidence_is_redacted() -> None:
    """``--cookie`` / ``--header`` values are scrubbed with no login, bearer token included."""
    token = "eyJhbGciOiJIUzI1NiJ9.e30.c2ln"

    class Echo(_Base):
        id = "test.echo"

        async def run(self, ctx: ScanContext) -> list[object]:
            finding = self._finding("echo")
            assert isinstance(finding, Finding)  # _finding is typed object; this narrows it
            echoed = f"echoed: sid=c00kieVALUE9 and token {token}"
            return [finding.model_copy(update={"description": echoed})]

    config = ScanConfig.model_validate(
        {"auth": {"cookies": ["sid=c00kieVALUE9"], "headers": [f"Authorization: Bearer {token}"]}}
    )
    result = await Orchestrator(config, check_types=[Echo]).run(_TARGET)
    rendered = result.model_dump_json()
    assert "c00kieVALUE9" not in rendered
    assert token not in rendered
    assert "[redacted]" in result.findings[0].description


def test_printing_the_orchestrator_shows_no_credential() -> None:
    """Its state, printed, keeps the names and hides every value (spec 024, RF-04)."""
    config = ScanConfig.model_validate(
        {
            "auth": {
                "cookies": ["sid=c00kie-VALUE"],
                "headers": ["Authorization: Bearer t0ken-VALUE"],
            }
        }
    )
    orchestrator = Orchestrator(config, credentials=Credentials("scanner", "pa55-VALUE"))
    shown = repr(vars(orchestrator))
    assert "sid" in shown and "Authorization" in shown and "scanner" in shown  # it was printed
    for value in ("c00kie-VALUE", "t0ken-VALUE", "pa55-VALUE"):
        assert value not in shown


async def test_active_mode_without_authorization_is_rejected() -> None:
    """Active mode with no ``authorized_by`` raises :class:`ActiveModeNotAuthorized`."""
    config = ScanConfig.model_validate({"scan": {"mode": "active"}})
    with pytest.raises(ActiveModeNotAuthorized):
        await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)


async def test_gated_active_run_records_authorization_and_runs_active_checks() -> None:
    """A properly gated active run records ``authorized_by`` and runs the ACTIVE checks."""
    config = ScanConfig.model_validate(
        {"scan": {"mode": "active"}, "active": {"authorized_by": "Jane / #7"}}
    )
    result = await Orchestrator(config, check_types=[ActiveOne]).run(_TARGET)
    assert result.metadata.authorized_by == "Jane / #7"
    assert len(result.findings) == 1


async def test_authenticated_flag_reflects_configured_cookies() -> None:
    """``metadata.authenticated`` is true only when auth cookies were configured."""
    anon = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert anon.metadata.authenticated is False

    config = ScanConfig.model_validate({"auth": {"cookies": ["session=abc"]}})
    authed = await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)
    assert authed.metadata.authenticated is True


async def test_forms_reach_a_check_via_ctx(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forms the crawler found are handed to checks through ``ctx.forms``."""
    from webvigil.crawler.forms import Form, FormField

    form = Form(
        method="POST",
        action="https://example.com/x",
        enctype="application/x-www-form-urlencoded",
        fields=(FormField(name="a", type="text", value=""),),
        source_url=_TARGET,
    )
    monkeypatch.setattr(_StubCrawler, "forms", (form,))
    seen: list[object] = []

    class FormReader(_Base):
        id = "test.formreader"

        async def run(self, ctx: ScanContext) -> list[object]:
            seen.extend(ctx.forms)
            return []

    await Orchestrator(ScanConfig(), check_types=[FormReader]).run(_TARGET)
    assert seen == [form]
    monkeypatch.setattr(_StubCrawler, "forms", ())


async def test_destructive_skip_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """The crawler's destructive-link skip count is surfaced as a scan warning."""
    monkeypatch.setattr(_StubCrawler, "skipped_destructive", 3)
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert any("declined to follow 3 link(s)" in w for w in result.warnings)
    monkeypatch.setattr(_StubCrawler, "skipped_destructive", 0)


async def test_robots_skip_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """URLs that robots.txt kept out of the crawl are surfaced, with the way to include them."""
    monkeypatch.setattr(_StubCrawler, "skipped_by_robots", 4)
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert any("robots.txt kept the crawler from 4 URL(s)" in w for w in result.warnings)
    assert any("follow_robots = false" in w for w in result.warnings)
    monkeypatch.setattr(_StubCrawler, "skipped_by_robots", 0)
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("robots.txt" in w for w in quiet.warnings)


async def test_an_unreadable_robots_file_becomes_one_warning_in_place_of_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cause is named, with the way out; the count would hide it (spec 027, ADR-6)."""
    monkeypatch.setattr(_StubCrawler, "skipped_by_robots", 4)
    monkeypatch.setattr(_StubCrawler, "robots_unreadable", "HTTP 503")
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert [w for w in result.warnings if "robots.txt" in w] == [
        "robots.txt could not be read (HTTP 503): only the target URL was crawled; "
        "set follow_robots = false under [scan] to crawl without it"
    ]


async def test_a_crawl_limit_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one-line notice of a limit the crawl reached is surfaced, and absent when none was."""
    line = "the site declared more than the crawl keeps (links): the rest was left out"
    monkeypatch.setattr(_StubCrawler, "limit_warning", line)
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert line in result.warnings
    monkeypatch.setattr(_StubCrawler, "limit_warning", None)
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("the crawl keeps" in w for w in quiet.warnings)


async def test_javascript_app_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A crawl that stopped at a client-rendered shell says so, and only then."""
    monkeypatch.setattr(
        orch_mod, "script_app_warning", lambda pages, **_: "looks like a JavaScript app"
    )
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert "looks like a JavaScript app" in result.warnings
    monkeypatch.setattr(orch_mod, "script_app_warning", lambda pages, **_: None)
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("JavaScript" in w for w in quiet.warnings)


async def test_the_javascript_app_warning_knows_whether_a_har_was_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a HAR the advice differs (the recording is already the way in), so the flag matters."""
    seen: list[bool] = []

    def warning(pages: object, *, har: bool) -> None:
        seen.append(har)

    monkeypatch.setattr(orch_mod, "script_app_warning", warning)
    monkeypatch.setattr(Orchestrator, "_load_har", lambda self, *_a: ())
    await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    with_har = ScanConfig.model_validate({"scan": {"har": "recording.har"}})
    await Orchestrator(with_har, check_types=[PassiveOne]).run(_TARGET)
    assert seen == [False, True]


async def test_truncated_bodies_become_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Responses cut at the body limit are reported, and only then, with the configured limit."""
    limits: list[int] = []

    def truncated(stats: object, limit: int) -> str:
        limits.append(limit)
        return "bodies were cut"

    monkeypatch.setattr(orch_mod, "truncated_warning", truncated)
    config = ScanConfig.model_validate({"http": {"max_body_bytes": 123_456}})
    result = await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)
    assert "bodies were cut" in result.warnings
    assert limits == [123_456]  # the warning names the limit the scan ran with
    monkeypatch.setattr(orch_mod, "truncated_warning", lambda stats, limit: None)
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("cut" in w for w in quiet.warnings)


async def test_a_page_read_in_part_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A page a check parsed only in part is counted by its scan, and only by it, and reported."""
    from webvigil.core import html

    monkeypatch.setattr(html, "MAX_PARSE_CHARS", 64 * 1024)

    class LongPageReader(_Base):
        id = "test.longpagereader"

        async def run(self, ctx: ScanContext) -> list[object]:
            html.parse_html("<p>text</p>" * 8_000)
            return []

    result = await Orchestrator(ScanConfig(), check_types=[LongPageReader]).run(_TARGET)
    assert sum("parsed only up to it" in w for w in result.warnings) == 1
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("parsed only up to it" in w for w in quiet.warnings)


async def test_a_blocked_address_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A name that resolved to an address the scan refuses is reported, and only then."""
    monkeypatch.setattr(orch_mod, "blocked_address_warning", lambda stats: "an address was refused")
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert "an address was refused" in result.warnings
    monkeypatch.setattr(orch_mod, "blocked_address_warning", lambda stats: None)
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("refused" in w for w in quiet.warnings)


async def test_the_address_notices_become_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    """What the scan's address guard recorded reaches the result's warnings — RF-06, RF-07."""
    notices = AddressNotices(internal_target="app.example.com", left_out=(("api.example.com", 2),))
    monkeypatch.setattr(AddressGuard, "notices", lambda self: notices)
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert any(
        w.startswith("the target host app.example.com is a public name") for w in result.warnings
    )
    assert any(w.startswith("api.example.com resolves to 2 internal") for w in result.warnings)
    monkeypatch.setattr(AddressGuard, "notices", lambda self: AddressNotices())
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("internal address" in w for w in quiet.warnings)


async def test_unreachable_target_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A target that stopped answering is reported, and only then."""
    monkeypatch.setattr(
        orch_mod, "unreachable_warning", lambda stats: "the target stopped answering"
    )
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert "the target stopped answering" in result.warnings
    monkeypatch.setattr(orch_mod, "unreachable_warning", lambda stats: None)
    quiet = await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert not any("stopped answering" in w for w in quiet.warnings)


async def test_registry_selection_filters_by_mode_and_reports_unknown_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    With no explicit check types, selection comes from the registry and an unknown
    disabled id is surfaced as a warning.

    The registry is asked with the scan's own mode and ``disabled`` list: a Passive scan that
    asked for the Active checks, or dropped the list, would run what the user turned off.
    """
    asked: list[tuple[ScanMode, list[str]]] = []
    unknown_asked: list[list[str]] = []

    def iter_checks(*, mode: ScanMode, disabled: list[str]) -> list[type[Check]]:
        asked.append((mode, list(disabled)))
        return [PassiveOne]

    def unknown_check_ids(disabled: list[str]) -> list[str]:
        unknown_asked.append(list(disabled))
        return ["ghost"]

    monkeypatch.setattr(orch_mod, "load_plugins", lambda: None)
    monkeypatch.setattr(orch_mod, "iter_checks", iter_checks)
    monkeypatch.setattr(orch_mod, "unknown_check_ids", unknown_check_ids)

    config = ScanConfig.model_validate({"checks": {"disabled": ["ghost", "http.headers.csp"]}})
    result = await Orchestrator(config).run(_TARGET)

    assert asked == [(ScanMode.PASSIVE, ["ghost", "http.headers.csp"])]
    assert unknown_asked == [["ghost", "http.headers.csp"]]
    assert result.warnings == ("unknown disabled check id: ghost",)
    assert len(result.findings) == 1

    active = ScanConfig.model_validate(
        {"scan": {"mode": "active"}, "active": {"authorized_by": "Jane / #7"}}
    )
    await Orchestrator(active).run(_TARGET)
    assert asked[1] == (ScanMode.ACTIVE, [])


# ---------------------------------------------------------------------------
# Automated login (spec 019)
# ---------------------------------------------------------------------------

_PASSWORD = "hunter2-pw"
_LOGIN_CFG = {
    "url": "https://example.com/signin",
    "username": "scanner",
    "password_env": "WV_ORCH_PW",
}


class _StubAuth:
    """An ``Authenticator`` stand-in: records what the orchestrator hands it and the order."""

    instances: ClassVar[list[_StubAuth]] = []
    confirmed: ClassVar[bool] = True
    events: ClassVar[list[str]] = []

    def __init__(self, http: object, target: object, login: object, credentials: object) -> None:
        self.credentials = credentials
        self.login_cfg = login
        self.session = Session(
            jar=SessionJar(Target.parse(_TARGET)),
            is_login_url=lambda _url: False,
        )
        type(self).instances.append(self)

    async def login(self) -> LoginResult:
        type(self).events.append("login")
        return LoginResult(confirmed=type(self).confirmed)


@pytest.fixture
def _stub_auth(monkeypatch: pytest.MonkeyPatch) -> type[_StubAuth]:
    """Swap the orchestrator's ``Authenticator`` and record when the OpenAPI load runs."""
    _StubAuth.instances = []
    _StubAuth.events = []
    _StubAuth.confirmed = True
    monkeypatch.setattr(orch_mod, "Authenticator", _StubAuth)

    async def load_openapi(self: object, *_a: object, **_k: object) -> list[object]:
        _StubAuth.events.append("openapi")
        return []

    monkeypatch.setattr(Orchestrator, "_load_openapi", load_openapi)
    return _StubAuth


def _login_config(mode: str = "active") -> ScanConfig:
    """
    Args:
        mode (str): ``"active"`` (gated) or ``"passive"``.

    Returns:
        ScanConfig: A scan with ``[auth.login]`` set.
    """
    raw: dict[str, object] = {"scan": {"mode": mode}, "auth": {"login": _LOGIN_CFG}}
    if mode == "active":
        raw["active"] = {"authorized_by": "Jane / #7"}
    return ScanConfig.model_validate(raw)


async def test_an_active_scan_logs_in_once_before_the_openapi_load(
    _stub_auth: type[_StubAuth],
) -> None:
    """The login runs first (the OpenAPI document may sit behind it) and shows in the metadata."""
    result = await Orchestrator(
        _login_config(), check_types=[ActiveOne], credentials=Credentials("scanner", _PASSWORD)
    ).run(_TARGET)

    assert _stub_auth.events == ["login", "openapi"]
    (auth,) = _stub_auth.instances
    assert auth.credentials.password.reveal() == _PASSWORD  # type: ignore[attr-defined]
    assert result.metadata.authenticated is True
    assert result.metadata.login == LoginSummary(relogins=0, session_lost=False, confirmed=True)


async def test_without_explicit_credentials_the_password_comes_from_the_environment(
    _stub_auth: type[_StubAuth], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The variable ``[auth.login] password_env`` names is read; unset is a failed login."""
    monkeypatch.setenv("WV_ORCH_PW", _PASSWORD)
    await Orchestrator(_login_config(), check_types=[ActiveOne]).run(_TARGET)
    used = _stub_auth.instances[0].credentials  # type: ignore[attr-defined]
    assert used.password.reveal() == _PASSWORD

    monkeypatch.delenv("WV_ORCH_PW")
    with pytest.raises(LoginFailedError, match="WV_ORCH_PW"):
        await Orchestrator(_login_config(), check_types=[ActiveOne]).run(_TARGET)


async def test_a_passive_scan_with_a_login_sends_nothing_and_says_so(
    _stub_auth: type[_StubAuth],
) -> None:
    """Passive never logs in: a warning, no authenticator, nothing authenticated."""
    result = await Orchestrator(
        _login_config("passive"), check_types=[PassiveOne], credentials=Credentials("s", _PASSWORD)
    ).run(_TARGET)

    assert _stub_auth.instances == []
    assert any("requires --mode active" in w and "login" in w for w in result.warnings)
    assert result.metadata.login is None
    assert result.metadata.authenticated is False


async def test_an_unconfirmed_login_continues_with_a_warning(_stub_auth: type[_StubAuth]) -> None:
    """When nothing can tell whether the login worked, the scan goes on and says so."""
    _stub_auth.confirmed = False
    result = await Orchestrator(
        _login_config(), check_types=[ActiveOne], credentials=Credentials("s", _PASSWORD)
    ).run(_TARGET)

    assert result.metadata.login.confirmed is False  # type: ignore[union-attr]
    assert any("could not be confirmed" in w for w in result.warnings)


class _Leaky(_Base):
    id = "test.leaky"
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[object]:
        finding = self._finding("leak")
        return [finding.model_copy(update={"description": f"the page echoed {_PASSWORD}"})]


async def test_the_password_a_target_reflected_is_scrubbed_from_the_result(
    _stub_auth: type[_StubAuth],
) -> None:
    """A finding that quotes the password comes out with ``[redacted]`` in its place."""
    result = await Orchestrator(
        _login_config(), check_types=[_Leaky], credentials=Credentials("s", _PASSWORD)
    ).run(_TARGET)

    assert _PASSWORD not in result.model_dump_json()
    assert result.findings[0].description == "the page echoed [redacted]"


async def test_a_password_read_from_the_environment_is_scrubbed_from_the_result(
    _stub_auth: type[_StubAuth], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The password the login used is collected, though the orchestrator was given none."""
    monkeypatch.setenv("WV_ORCH_PW", _PASSWORD)
    result = await Orchestrator(_login_config(), check_types=[_Leaky]).run(_TARGET)

    used = _stub_auth.instances[0].credentials  # type: ignore[attr-defined]
    assert used.password.reveal() == _PASSWORD
    assert _PASSWORD not in result.model_dump_json()
    assert result.findings[0].description == "the page echoed [redacted]"


# Long and mixed-case, as a generated session id is: the scrubber treats it as a secret.
_ISSUED_ID = "Ab12Cd34Ef56Gh78Ij90"


class _IssuingAuth(_StubAuth):
    """A login whose answer sets a session cookie, as a real one does."""

    issued: ClassVar[str] = _ISSUED_ID

    async def login(self) -> LoginResult:
        jar = self.session.jar
        jar.begin()
        request = httpx2.Request("POST", "https://example.com/signin")
        jar.absorb(
            httpx2.Response(200, headers={"set-cookie": f"sid={self.issued}"}, request=request),
            handshake=True,
        )
        jar.commit()
        return await super().login()


class _EchoesTheSession(_Base):
    """A check whose finding quotes the session id the login was issued."""

    id = "test.echoes-session"
    mode = ScanMode.ACTIVE

    async def run(self, ctx: ScanContext) -> list[object]:
        finding = self._finding("session")
        echoed = f"the page echoed {_IssuingAuth.issued}"
        return [finding.model_copy(update={"description": echoed})]


async def test_the_session_id_the_login_was_issued_is_scrubbed_from_the_result(
    _stub_auth: type[_StubAuth], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The jar's values are secrets too: a page that quotes the session id does not leak it."""
    monkeypatch.setattr(orch_mod, "Authenticator", _IssuingAuth)
    result = await Orchestrator(
        _login_config(), check_types=[_EchoesTheSession], credentials=Credentials("s", _PASSWORD)
    ).run(_TARGET)

    jar = _IssuingAuth.instances[0].session.jar
    assert {value.reveal() for value in jar.values} == {_ISSUED_ID}  # the login set it
    assert _ISSUED_ID not in result.model_dump_json()
    assert result.findings[0].description == "the page echoed [redacted]"


async def test_a_session_value_that_is_a_common_word_is_left_in_the_result(
    _stub_auth: type[_StubAuth], monkeypatch: pytest.MonkeyPatch
) -> None:
    """What the target issued is scrubbed only when it looks like a session id (RF-07)."""
    monkeypatch.setattr(orch_mod, "Authenticator", _IssuingAuth)
    monkeypatch.setattr(_IssuingAuth, "issued", "echoed")
    result = await Orchestrator(
        _login_config(), check_types=[_EchoesTheSession], credentials=Credentials("s", _PASSWORD)
    ).run(_TARGET)

    jar = _IssuingAuth.instances[0].session.jar
    assert {value.reveal() for value in jar.values} == {"echoed"}  # the login set it
    assert result.findings[0].description == "the page echoed echoed"


# ---------------------------------------------------------------------------
# The session-security pass (spec 020)
# ---------------------------------------------------------------------------


class _StubSessionScanner:
    """A ``SessionScanner`` stand-in: records its arguments and returns canned hits."""

    built: ClassVar[list[dict[str, object]]] = []
    hits: ClassVar[list[SessionHit]] = []
    warnings_to_add: ClassVar[list[str]] = []
    boom: ClassVar[bool] = False

    def __init__(self, *args: object, **kwargs: object) -> None:
        type(self).built.append({"args": args, **kwargs})
        self.warnings: list[str] = list(type(self).warnings_to_add)

    async def run(self) -> list[SessionHit]:
        if type(self).boom:
            raise RuntimeError("kaboom")
        return list(type(self).hits)


@pytest.fixture
def _stub_session_scanner(monkeypatch: pytest.MonkeyPatch) -> type[_StubSessionScanner]:
    """Swap the orchestrator's ``SessionScanner`` and reset what it records."""
    _StubSessionScanner.built = []
    _StubSessionScanner.hits = []
    _StubSessionScanner.warnings_to_add = []
    _StubSessionScanner.boom = False
    monkeypatch.setattr(orch_mod, "SessionScanner", _StubSessionScanner)
    return _StubSessionScanner


_WEAK_HIT = SessionHit(
    kind="weak",
    name="session",
    url=_TARGET,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rule="short",
    facts=(("length", "6"),),
)


async def test_the_session_pass_feeds_the_session_checks(
    _stub_session_scanner: type[_StubSessionScanner],
) -> None:
    """A selected ``session.*`` check gets the pass's hits and reports them."""
    _stub_session_scanner.hits = [_WEAK_HIT]
    _stub_session_scanner.warnings_to_add = ["session sampling: nothing issued"]

    result = await Orchestrator(ScanConfig(), check_types=[WeakSessionIdCheck]).run(_TARGET)

    assert [f.check_id for f in result.findings] == ["session.id.weak"]
    assert "session sampling: nothing issued" in result.warnings
    assert _stub_session_scanner.built[0]["kinds"] == frozenset({"weak"})


async def test_the_pass_does_not_run_when_no_session_check_is_selected(
    _stub_session_scanner: type[_StubSessionScanner],
) -> None:
    """Without a ``session.*`` check the scanner is never built."""
    await Orchestrator(ScanConfig(), check_types=[PassiveOne]).run(_TARGET)
    assert _stub_session_scanner.built == []


async def test_the_logout_step_needs_the_switch_even_when_its_check_is_selected(
    _stub_session_scanner: type[_StubSessionScanner],
) -> None:
    """``test_logout`` off: the pass is asked for fixation only."""
    config = ScanConfig.model_validate(
        {"scan": {"mode": "active"}, "active": {"authorized_by": "Jane / #7"}}
    )
    checks = [SessionFixationCheck, LogoutNotInvalidatedCheck]
    await Orchestrator(config, check_types=checks).run(_TARGET)
    assert _stub_session_scanner.built[0]["kinds"] == frozenset({"fixation"})

    config = config.with_overrides(session={"test_logout": True})
    await Orchestrator(config, check_types=checks).run(_TARGET)
    assert _stub_session_scanner.built[1]["kinds"] == frozenset({"fixation", "logout"})


async def test_a_session_pass_bug_becomes_a_warning(
    _stub_session_scanner: type[_StubSessionScanner],
) -> None:
    """A pass that raises costs a warning, not the scan."""
    _stub_session_scanner.boom = True
    result = await Orchestrator(ScanConfig(), check_types=[WeakSessionIdCheck]).run(_TARGET)
    assert result.findings == ()
    assert "session checks failed: RuntimeError" in result.warnings


async def test_the_session_pass_runs_after_the_csrf_pass(
    _stub_session_scanner: type[_StubSessionScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Last: the logout test ends the session, so nothing may run after it."""
    order: list[str] = []

    async def csrf(self: object, *_a: object, **_k: object) -> tuple[()]:
        order.append("csrf")
        return ()

    class _Recording(_StubSessionScanner):
        async def run(self) -> list[SessionHit]:
            order.append("session")
            return []

    monkeypatch.setattr(Orchestrator, "_scan_csrf", csrf)
    monkeypatch.setattr(orch_mod, "SessionScanner", _Recording)
    await Orchestrator(ScanConfig(), check_types=[WeakSessionIdCheck]).run(_TARGET)
    assert order == ["csrf", "session"]


_ACTIVE_RAW = {"scan": {"mode": "active"}, "active": {"authorized_by": "x"}}


@pytest.mark.parametrize(
    ("raw", "warned"),
    [
        ({"session": {"test_logout": True}}, True),  # Passive
        ({**_ACTIVE_RAW, "session": {"test_logout": True}}, True),  # Active but no login
        (_ACTIVE_RAW, False),
        # every precondition met: the switch, Active Mode and a login (the case a warning
        # on the switch alone would get wrong)
        ({**_ACTIVE_RAW, "auth": {"login": _LOGIN_CFG}, "session": {"test_logout": True}}, False),
    ],
)
async def test_the_logout_test_warns_when_its_preconditions_are_missing(
    _stub_session_scanner: type[_StubSessionScanner],
    _stub_auth: type[_StubAuth],
    raw: dict[str, object],
    warned: bool,
) -> None:
    """``test_logout`` outside Active Mode, or without a login, says it did not run."""
    result = await Orchestrator(
        ScanConfig.model_validate(raw),
        check_types=[PassiveOne],
        credentials=Credentials("scanner", _PASSWORD),
    ).run(_TARGET)
    assert any("logout test requires" in w for w in result.warnings) is warned


class _LateRequest(_Base):
    """A check that asks for a page once the scan deadline has passed (security audit 2026-11)."""

    id = "test.late-request"

    async def run(self, ctx: ScanContext) -> list[object]:
        await asyncio.sleep(0.1)
        with pytest.raises(ScanDeadlineExceeded):
            await ctx.http.get(_TARGET)
        return []


async def test_a_scan_past_its_deadline_reports_what_it_has_and_says_so() -> None:
    """The scan finishes with a result and a warning naming the setting."""
    config = ScanConfig.model_validate({"scan": {"max_duration_s": 0.05}})
    result = await Orchestrator(config, check_types=[_LateRequest]).run(_TARGET)
    assert not result.errors
    assert any("max_duration_s" in line for line in result.warnings)


# ---------------------------------------------------------------------------
# The opt-in passes: each runs only in Active Mode, opted in, with its check selected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("section", "switch", "warning"),
    [
        ("injection", "stored_xss", "stored-XSS testing requires --mode active"),
        ("injection", "file_upload", "file-upload testing requires --mode active"),
        ("injection", "csrf_confirm", "CSRF confirmation requires --mode active"),
        ("scan", "submit_post_forms", "POST crawling requires --mode active"),
    ],
)
async def test_an_opt_in_says_it_did_not_run_only_in_a_passive_scan(
    section: str, switch: str, warning: str
) -> None:
    """In Active Mode the switch takes effect, so the "did not run" line would be false."""
    raw: dict[str, object] = {section: {switch: True}}
    passive = await Orchestrator(ScanConfig.model_validate(raw), check_types=[PassiveOne]).run(
        _TARGET
    )
    assert any(w.startswith(warning) for w in passive.warnings)

    sections: dict[str, dict[str, object]] = {"scan": {"mode": "active"}}
    sections.setdefault(section, {})[switch] = True
    active = ScanConfig.model_validate({**sections, "active": {"authorized_by": "x"}})
    assert active.scan.mode is ScanMode.ACTIVE
    result = await Orchestrator(active, check_types=[PassiveOne]).run(_TARGET)
    assert not any(w.startswith(warning) for w in result.warnings)


class _Counted:
    """A stand-in pass that records each construction and finds nothing."""

    built: ClassVar[list[str]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        type(self).built.append(type(self).__name__)
        self.warnings: list[str] = []

    async def run(self) -> list[object]:
        return []


def _count(monkeypatch: pytest.MonkeyPatch, name: str) -> list[str]:
    """
    Replace an orchestrator pass with one that counts its constructions.

    A stand-in that raised would not do: the orchestrator turns a pass's exception into a
    warning, so a pass that ran when it should not would still leave the scan green.

    Args:
        monkeypatch (pytest.MonkeyPatch): The fixture that undoes the patch.
        name (str): The pass class name in ``webvigil.core.orchestrator``.

    Returns:
        list[str]: One entry per construction.
    """
    counted = type(name, (_Counted,), {"built": []})
    monkeypatch.setattr(orch_mod, name, counted)
    return counted.built


@pytest.mark.parametrize(
    ("raw", "runs"),
    [
        ({}, False),  # Passive: no TRACE / PUT / forged Host, whatever the selection
        (_ACTIVE_RAW, True),
    ],
    ids=["passive", "active"],
)
async def test_the_envelope_pass_needs_active_mode(
    monkeypatch: pytest.MonkeyPatch, raw: dict[str, object], runs: bool
) -> None:
    """Even when a caller of the engine selects the envelope checks by hand."""
    from webvigil.checks.envelope.checks import HostHeaderCheck, HttpMethodsCheck

    built = _count(monkeypatch, "EnvelopeScanner")
    config = ScanConfig.model_validate(raw)
    for check in (HostHeaderCheck, HttpMethodsCheck):
        await Orchestrator(config, check_types=[check]).run(_TARGET)
    assert len(built) == (2 if runs else 0)


async def test_the_envelope_pass_needs_one_of_its_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Active Mode alone sends nothing: the pass is for its two checks only."""
    built = _count(monkeypatch, "EnvelopeScanner")
    await Orchestrator(ScanConfig.model_validate(_ACTIVE_RAW), check_types=[ActiveOne]).run(_TARGET)
    assert built == []


@pytest.mark.parametrize(
    ("raw", "selected", "runs"),
    [
        ({"injection": {"file_upload": True}}, True, False),  # Passive
        (_ACTIVE_RAW, True, False),  # not opted in
        ({**_ACTIVE_RAW, "injection": {"file_upload": True}}, False, False),  # not selected
        ({**_ACTIVE_RAW, "injection": {"file_upload": True}}, True, True),
    ],
    ids=["passive", "no-opt-in", "not-selected", "all-three"],
)
async def test_the_upload_pass_needs_active_mode_the_opt_in_and_its_check(
    monkeypatch: pytest.MonkeyPatch, raw: dict[str, object], selected: bool, runs: bool
) -> None:
    """It leaves files on the target, so each of the three conditions is enough to stop it."""
    from webvigil.checks.upload.checks import UnrestrictedUploadCheck

    built = _count(monkeypatch, "UploadScanner")
    checks: list[type[Check]] = [UnrestrictedUploadCheck] if selected else [ActiveOne]
    await Orchestrator(ScanConfig.model_validate(raw), check_types=checks).run(_TARGET)
    assert len(built) == (1 if runs else 0)


async def test_the_result_keeps_the_first_and_last_warnings_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan with more warnings than ``WARNINGS_CAP`` reports both ends and counts the rest."""
    raw: dict[str, object] = {
        "injection": {"stored_xss": True, "file_upload": True, "csrf_confirm": True},
        "scan": {"submit_post_forms": True},
    }
    config = ScanConfig.model_validate(raw)
    everything = (await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)).warnings
    assert len(everything) >= 4  # the control: four opt-ins that did not run, at least
    monkeypatch.setattr(orch_mod, "WARNINGS_CAP", 2)
    capped = (await Orchestrator(config, check_types=[PassiveOne]).run(_TARGET)).warnings
    assert capped == (
        everything[0],
        f"{len(everything) - 2} more warnings were not kept",
        everything[-1],
    )

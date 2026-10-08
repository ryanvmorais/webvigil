"""
Orchestrator: mode gating, check selection, error isolation, dedupe — RF-11, RF-15.

The autouse ``_stub_crawler`` fixture replaces the crawler with one that returns
a single blank page, so the tests exercise the orchestrator's own logic — the
Active gate, fingerprint dedup, per-check error isolation, warning surfacing —
with no HTTP. The check classes (:class:`PassiveOne`, :class:`Boom`, ...) are
tiny local stand-ins that emit canned findings or raise.
"""

from __future__ import annotations

from typing import ClassVar

import httpx
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
from webvigil.core.errors import ActiveModeNotAuthorized, LoginFailedError
from webvigil.core.findings import Category, Confidence, Location, ScanMode, Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import LoginSummary
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
        headers=httpx.Headers({"content-type": "text/html"}),
        text="<html></html>",
        elapsed_ms=1.0,
    )


class _StubCrawler:
    """A crawler that discovers exactly one blank page and finds no forms."""

    forms: tuple[object, ...] = ()
    skipped_destructive = 0
    skipped_by_robots = 0
    post_summary = None  # spec 018: the real crawler exposes the POST phase tally

    def __init__(self, *_args: object, **_kwargs: object) -> None: ...

    async def discover(self) -> list[Page]:
        return [_page()]


@pytest.fixture(autouse=True)
def _stub_crawler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the orchestrator's ``Crawler`` for :class:`_StubCrawler`."""
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


class _Base(Check):
    """Shared base for the local test checks: a HEADERS check whose ``_finding`` builds
    a deduplicable finding keyed by an arbitrary string."""

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
    # PassiveOne("a"), PassiveTwo("a") once (deduped from 2), PassiveTwo("b") -> 3 total.
    assert len(result.findings) == 3
    assert sorted(f.fingerprint for f in result.findings) == sorted(
        {f.fingerprint for f in result.findings}
    )
    assert result.metadata.pages_scanned == 1


async def test_a_raising_check_is_isolated() -> None:
    """A check that raises is recorded as an error; the other checks' findings still land."""
    result = await Orchestrator(ScanConfig(), check_types=[PassiveOne, Boom]).run(_TARGET)
    assert len(result.findings) == 1
    assert [e.check_id for e in result.errors] == ["test.boom"]
    assert "kaboom" in result.errors[0].message


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
    """With no explicit check types, selection comes from the registry and an unknown
    disabled id is surfaced as a warning."""
    monkeypatch.setattr(orch_mod, "load_plugins", lambda: None)
    monkeypatch.setattr(orch_mod, "iter_checks", lambda *, mode, disabled: [PassiveOne])
    monkeypatch.setattr(orch_mod, "unknown_check_ids", lambda disabled: ["ghost"])

    config = ScanConfig.model_validate({"checks": {"disabled": ["ghost"]}})
    result = await Orchestrator(config).run(_TARGET)

    assert result.warnings == ("unknown disabled check id: ghost",)
    assert len(result.findings) == 1


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
            jar=SessionJar("example.com"),
            is_login_url=lambda _url: False,
            secrets=[credentials.password],  # type: ignore[attr-defined]
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
    assert auth.credentials.password == _PASSWORD  # type: ignore[attr-defined]
    assert result.metadata.authenticated is True
    assert result.metadata.login == LoginSummary(relogins=0, session_lost=False, confirmed=True)


async def test_without_explicit_credentials_the_password_comes_from_the_environment(
    _stub_auth: type[_StubAuth], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The variable ``[auth.login] password_env`` names is read; unset is a failed login."""
    monkeypatch.setenv("WV_ORCH_PW", _PASSWORD)
    await Orchestrator(_login_config(), check_types=[ActiveOne]).run(_TARGET)
    assert _stub_auth.instances[0].credentials.password == _PASSWORD  # type: ignore[attr-defined]

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
    assert any("session checks failed: kaboom" in w for w in result.warnings)


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
    ],
)
async def test_the_logout_test_warns_when_its_preconditions_are_missing(
    _stub_session_scanner: type[_StubSessionScanner], raw: dict[str, object], warned: bool
) -> None:
    """``test_logout`` outside Active Mode, or without a login, says it did not run."""
    result = await Orchestrator(ScanConfig.model_validate(raw), check_types=[PassiveOne]).run(
        _TARGET
    )
    assert any("logout test requires" in w for w in result.warnings) is warned

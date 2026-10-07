"""
Orchestrator wiring for the active-injection pass — spec 006 RF-01, RF-12, ADR-2.

The autouse ``_stub_crawler`` fixture replaces the crawler with one that returns
a single seed page, so the tests exercise pass selection (Active gate, an
injection check selected, the stored-XSS opt-in) without any real crawl. The
scanner passes themselves — ``InjectionScanner`` and ``StoredXssScanner`` — are
monkeypatched per test: a boom stub when the pass must not run, a canned-report
stub when it must.
"""

from __future__ import annotations

import re

import httpx
import pytest

from webvigil.checks.csrf.checks import TokenNotEnforcedCheck
from webvigil.checks.csrf.scanner import CsrfHit
from webvigil.checks.headers.hsts import HstsCheck
from webvigil.checks.injection.checks import (
    ExpressionLanguageInjectionCheck,
    OsCommandInjectionCheck,
    ReflectedXssCheck,
    SsrfMetadataCheck,
    StoredXssCheck,
    TemplateInjectionCheck,
)
from webvigil.checks.injection.models import InjectionHit, StoredXssReport
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.findings import Confidence, Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.crawler.crawler import PostSummary
from webvigil.crawler.openapi import ApiOperation

_TARGET = "https://example.com/"
_SEED = "https://example.com/s?q=hi"

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)


class _StubCrawler:
    """A crawler that discovers exactly one seed page and re-crawls to nothing."""

    forms: tuple[object, ...] = ()
    skipped_destructive = 0
    skipped_by_robots = 0
    post_summary = None  # spec 018: the real crawler exposes the POST phase tally

    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def recrawl(self, *_a: object, **_k: object) -> list[Page]:
        return []

    async def discover(self) -> list[Page]:
        return [
            Page(
                requested_url=_SEED,
                url=_SEED,
                status_code=200,
                headers=httpx.Headers({"content-type": "text/html"}),
                text="<html><body>ok</body></html>",
                elapsed_ms=1.0,
            )
        ]


@pytest.fixture(autouse=True)
def _stub_crawler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the orchestrator's ``Crawler`` for :class:`_StubCrawler`."""
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


def _active(**checks_kw: object) -> ScanConfig:
    """
    Args:
        **checks_kw (object): Extra config sections (e.g. ``injection={...}``).

    Returns:
        ScanConfig: A config in Active mode with ``authorized_by`` set.
    """
    return ScanConfig.model_validate(
        {"scan": {"mode": "active"}, "active": {"authorized_by": "test"}, **checks_kw}
    )


def _boom(*_a: object, **_k: object) -> object:
    """A stand-in that fails the test if ``InjectionScanner`` is constructed."""
    raise AssertionError("InjectionScanner must not run")


async def test_passive_scan_never_runs_the_injection_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In the default Passive mode the injection pass is never constructed."""
    monkeypatch.setattr(orch_mod, "InjectionScanner", _boom)
    result = await Orchestrator(ScanConfig(), check_types=[ReflectedXssCheck]).run(_TARGET)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_active_scan_with_no_injection_check_selected_does_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Active mode alone is not enough — with no injection check the pass is skipped."""
    monkeypatch.setattr(orch_mod, "InjectionScanner", _boom)
    result = await Orchestrator(_active(), check_types=[HstsCheck]).run(_TARGET)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_active_scan_reflected_xss_is_reported(httpx_mock: object) -> None:
    """Active mode + a reflecting endpoint + the XSS check yields an ``injection.xss.reflected``."""

    def router(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        return httpx.Response(
            200, text=f"<div>results for {value}</div>", headers={"content-type": "text/html"}
        )

    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    result = await Orchestrator(_active(), check_types=[ReflectedXssCheck]).run(_TARGET)
    xss = [f for f in result.findings if f.check_id == "injection.xss.reflected"]
    assert xss and xss[0].location.param == "q"


async def test_active_scan_ssrf_metadata_is_reported(httpx_mock: object) -> None:
    """A target that serves cloud creds for a metadata payload yields a CRITICAL SSRF finding."""

    def router(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        if "169.254.169.254" in value or "2852039166" in value:
            return httpx.Response(200, text='{"Code":"Success","AccessKeyId":"ASIAX"}')
        return httpx.Response(200, text="<div>ok</div>", headers={"content-type": "text/html"})

    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    result = await Orchestrator(_active(), check_types=[SsrfMetadataCheck]).run(_TARGET)
    ssrf = [f for f in result.findings if f.check_id == "injection.ssrf.metadata"]
    assert ssrf and ssrf[0].severity is Severity.CRITICAL
    assert ssrf[0].location.param == "q"


async def test_active_scan_command_injection_is_reported(httpx_mock: object) -> None:
    """A target that evaluates the injected arithmetic yields a CRITICAL command-injection."""

    def router(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        m = re.search(r"(wv[0-9a-f]+)=\$\(\((\d+)\*(\d+)\)\)", value)
        if m:
            body = f"{m.group(1)}={int(m.group(2)) * int(m.group(3))}"
            return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="<div>ok</div>", headers={"content-type": "text/html"})

    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    cfg = _active(injection={"time_based_cmdi": False})
    result = await Orchestrator(cfg, check_types=[OsCommandInjectionCheck]).run(_TARGET)
    cmdi = [f for f in result.findings if f.check_id == "injection.cmdi.os"]
    assert cmdi and cmdi[0].severity is Severity.CRITICAL
    assert cmdi[0].location.param == "q"


def _ognl_router(request: httpx.Request) -> httpx.Response:
    """A target whose ``q`` is evaluated as OGNL: ``%{a*b}`` and ``%{@Math@abs(-n)}`` run."""
    value = request.url.params.get("q", "")
    arith = re.search(r"(wv[0-9a-f]+)%\{(\d+)\*(\d+)\}", value)
    if arith:
        body = f"{arith.group(1)}{int(arith.group(2)) * int(arith.group(3))}"
        return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
    static = re.search(r"(wv[0-9a-f]+)%\{@java\.lang\.Math@abs\(-(\d+)\)\}", value)
    if static:
        body = f"{static.group(1)}{static.group(2)}"
        return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
    return httpx.Response(200, text="<div>ok</div>", headers={"content-type": "text/html"})


async def test_active_scan_expression_language_is_reported(httpx_mock: object) -> None:
    """A target that evaluates ``%{...}`` yields a CRITICAL OGNL finding (static call proved)."""
    httpx_mock.add_callback(_ognl_router, is_reusable=True)  # type: ignore[attr-defined]
    orchestrator = Orchestrator(_active(), check_types=[ExpressionLanguageInjectionCheck])
    result = await orchestrator.run(_TARGET)
    el = [f for f in result.findings if f.check_id == "injection.el"]
    assert el and el[0].severity is Severity.CRITICAL
    assert "OGNL" in el[0].title
    assert el[0].location.param == "q"


async def test_with_both_checks_selected_one_proof_is_one_finding(httpx_mock: object) -> None:
    """The combined detector reports the OGNL evaluation as ``injection.el``, never twice."""
    httpx_mock.add_callback(_ognl_router, is_reusable=True)  # type: ignore[attr-defined]
    orchestrator = Orchestrator(
        _active(), check_types=[TemplateInjectionCheck, ExpressionLanguageInjectionCheck]
    )
    result = await orchestrator.run(_TARGET)
    ids = [f.check_id for f in result.findings if f.check_id.startswith("injection.")]
    assert ids == ["injection.el"]


async def test_active_scan_sends_only_the_payloads_of_the_selected_checks(
    httpx_mock: object,
) -> None:
    """A check that is not selected sends none of its payloads (SSRF, shell, template, EL)."""
    seen: list[str] = []

    def router(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("q", ""))
        return httpx.Response(200, text="<div>ok</div>", headers={"content-type": "text/html"})

    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    # only XSS selected: no SSRF metadata or file:// payload, no shell-break or template payload
    await Orchestrator(_active(), check_types=[ReflectedXssCheck]).run(_TARGET)
    assert seen
    assert not any("169.254.169.254" in v or v.lower().startswith("file:") for v in seen)
    assert not any("$((" in v or "{{7*" in v or ";sleep" in v for v in seen)
    # only ``injection.ssti`` selected: the SSTI payloads go out, no EL-only form or type probe
    seen.clear()
    await Orchestrator(_active(), check_types=[TemplateInjectionCheck]).run(_TARGET)
    assert seen  # the SSTI payloads were sent
    assert not any("%{" in v or "T(java" in v or "'+(" in v or "${(" in v for v in seen)


async def test_a_raising_pass_becomes_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception from the injection pass degrades to a scan warning, not a crash."""

    class _Raises:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def run(self) -> object:
            raise RuntimeError("detector blew up")

    monkeypatch.setattr(orch_mod, "InjectionScanner", _Raises)
    result = await Orchestrator(_active(), check_types=[ReflectedXssCheck]).run(_TARGET)
    assert any("active injection pass failed" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# The stored-XSS pass (spec 008)
# ---------------------------------------------------------------------------


def _stored_boom(*_a: object, **_k: object) -> object:
    """A stand-in that fails the test if ``StoredXssScanner`` is constructed."""
    raise AssertionError("StoredXssScanner must not run")


class _StoredStub:
    """A stored-XSS pass that returns one canned hit plus a re-crawl-cap warning."""

    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def run(self) -> StoredXssReport:
        hit = InjectionHit(
            kind="xss-stored",
            check_id="injection.xss.stored",
            method="POST",
            url="https://example.com/gb",
            param="body",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Stored XSS via 'body'",
            payload="<wvstoredx>",
            evidence=(("Injection point", "POST https://example.com/gb"),),
        )
        return StoredXssReport(
            hits=[hit], warnings=["stored-XSS re-crawl stopped at the 3-page cap"]
        )


async def test_stored_pass_skipped_without_the_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``[injection] stored_xss`` the stored pass is never constructed."""
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _stored_boom)
    result = await Orchestrator(_active(), check_types=[StoredXssCheck]).run(_TARGET)
    assert not any(f.check_id == "injection.xss.stored" for f in result.findings)


async def test_stored_pass_skipped_when_check_not_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opt-in alone is not enough — with no stored-XSS check the pass is skipped."""
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _stored_boom)
    config = _active(injection={"stored_xss": True})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert not any(f.check_id == "injection.xss.stored" for f in result.findings)


async def test_stored_pass_runs_and_merges_its_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the opt-in and the check, the pass runs and its hits and warnings reach the result."""
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _StoredStub)
    config = _active(injection={"stored_xss": True})
    result = await Orchestrator(config, check_types=[StoredXssCheck]).run(_TARGET)
    stored = [f for f in result.findings if f.check_id == "injection.xss.stored"]
    assert stored and stored[0].location.param == "body"
    assert any("3-page cap" in w for w in result.warnings)


async def test_a_raising_stored_pass_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception from the stored-XSS pass degrades to a scan warning."""

    class _Raises:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def run(self) -> object:
            raise RuntimeError("recrawl blew up")

    monkeypatch.setattr(orch_mod, "StoredXssScanner", _Raises)
    config = _active(injection={"stored_xss": True})
    result = await Orchestrator(config, check_types=[StoredXssCheck]).run(_TARGET)
    assert any("stored-XSS pass failed" in w for w in result.warnings)


async def test_stored_opt_in_without_active_mode_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stored-XSS opt-in in Passive mode is a no-op that warns it needs ``--mode active``."""
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _stored_boom)
    config = ScanConfig.model_validate({"injection": {"stored_xss": True}})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert any("requires --mode active" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# The active CSRF confirmation pass (spec 017, RF-11, ADR-6, ADR-7)
# ---------------------------------------------------------------------------


def _csrf_boom(*_a: object, **_k: object) -> object:
    """A stand-in that fails the test if ``CsrfScanner`` is constructed."""
    raise AssertionError("CsrfScanner must not run")


class _CsrfStub:
    """A CSRF pass that confirms one form and reports a tally line."""

    def __init__(self, *_a: object, **_k: object) -> None:
        self.warnings = ["CSRF confirmation: 1 form tested — 1 confirmed"]

    async def run(self) -> list[CsrfHit]:
        return [
            CsrfHit(
                url="https://example.com/settings",
                source_url=_TARGET,
                replay="no token field",
                token_fields=(),
                control="POST /settings -> 200",
                attack="POST /settings -> 200",
            )
        ]


async def test_csrf_pass_skipped_without_the_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``[injection] csrf_confirm`` the CSRF pass is never constructed."""
    monkeypatch.setattr(orch_mod, "CsrfScanner", _csrf_boom)
    result = await Orchestrator(_active(), check_types=[TokenNotEnforcedCheck]).run(_TARGET)
    assert not any(f.check_id == "csrf.form.token-not-enforced" for f in result.findings)


async def test_csrf_pass_skipped_when_check_not_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opt-in alone is not enough — with the check disabled the pass is skipped."""
    monkeypatch.setattr(orch_mod, "CsrfScanner", _csrf_boom)
    config = _active(injection={"csrf_confirm": True})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert not any(f.check_id == "csrf.form.token-not-enforced" for f in result.findings)


async def test_csrf_pass_runs_and_reaches_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the opt-in and the check, the hit becomes a finding and the tally a warning."""
    monkeypatch.setattr(orch_mod, "CsrfScanner", _CsrfStub)
    config = _active(injection={"csrf_confirm": True})
    result = await Orchestrator(config, check_types=[TokenNotEnforcedCheck]).run(_TARGET)
    found = [f for f in result.findings if f.check_id == "csrf.form.token-not-enforced"]
    assert [f.location.url for f in found] == ["https://example.com/settings"]
    assert any("CSRF confirmation: 1 form tested" in w for w in result.warnings)


async def test_a_raising_csrf_pass_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception from the CSRF pass degrades to a scan warning."""

    class _Raises:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def run(self) -> object:
            raise RuntimeError("replay blew up")

    monkeypatch.setattr(orch_mod, "CsrfScanner", _Raises)
    config = _active(injection={"csrf_confirm": True})
    result = await Orchestrator(config, check_types=[TokenNotEnforcedCheck]).run(_TARGET)
    assert any("CSRF confirmation pass failed" in w for w in result.warnings)


async def test_csrf_opt_in_without_active_mode_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-in in Passive mode is a no-op that warns it needs ``--mode active``."""
    monkeypatch.setattr(orch_mod, "CsrfScanner", _csrf_boom)
    config = ScanConfig.model_validate({"injection": {"csrf_confirm": True}})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert any("CSRF confirmation requires --mode active" in w for w in result.warnings)


async def test_csrf_pass_runs_after_the_upload_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CSRF pass is last: it is the one that changes server state (ADR-6)."""
    order: list[str] = []

    class _Upload:
        def __init__(self, *_a: object, **_k: object) -> None:
            self.warnings: list[str] = []

        async def run(self) -> list[object]:
            order.append("upload")
            return []

    class _Csrf(_CsrfStub):
        async def run(self) -> list[CsrfHit]:
            order.append("csrf")
            return []

    from webvigil.checks.upload.checks import UnrestrictedUploadCheck

    monkeypatch.setattr(orch_mod, "UploadScanner", _Upload)
    monkeypatch.setattr(orch_mod, "CsrfScanner", _Csrf)
    config = _active(injection={"csrf_confirm": True, "file_upload": True})
    await Orchestrator(config, check_types=[UnrestrictedUploadCheck, TokenNotEnforcedCheck]).run(
        _TARGET
    )
    assert order == ["upload", "csrf"]


# ---------------------------------------------------------------------------
# The crawler's POST phase (spec 018, RF-01, RF-03, RF-08, ADR-7)
# ---------------------------------------------------------------------------


def _operation(method: str, path: str) -> ApiOperation:
    """
    Args:
        method (str): ``GET`` or ``POST``.
        path (str): The operation path.

    Returns:
        ApiOperation: A bodiless operation on the target.
    """
    return ApiOperation(
        method=method,
        url=f"https://example.com{path}",
        url_template=f"https://example.com{path}",
        query=(),
        path_params=(),
        body_fields=(),
        body_json=None,
        operation_id="",
    )


async def test_post_operations_reach_the_crawler_and_get_ones_stay_seeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``POST`` operations go to ``post_operations``; ``GET`` ones stay ``extra_seeds`` (013)."""
    seen: dict[str, object] = {}

    class _Capturing(_StubCrawler):
        def __init__(self, *_a: object, **kwargs: object) -> None:
            seen.update(kwargs)

    async def _ops(self: Orchestrator, *_a: object) -> tuple[ApiOperation, ...]:
        return (_operation("GET", "/api/list"), _operation("POST", "/api/notes"))

    monkeypatch.setattr(orch_mod, "Crawler", _Capturing)
    monkeypatch.setattr(Orchestrator, "_load_openapi", _ops)
    await Orchestrator(_active(), check_types=[HstsCheck]).run(_TARGET)
    assert seen["extra_seeds"] == ["https://example.com/api/list"]
    assert [op.url for op in seen["post_operations"]] == ["https://example.com/api/notes"]  # type: ignore[attr-defined]


async def test_the_post_crawl_summary_becomes_one_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The crawler's tally reaches the result as a single ``POST crawl:`` warning."""

    class _Summarising(_StubCrawler):
        post_summary = PostSummary(forms=2, operations=1, skipped=3)

    monkeypatch.setattr(orch_mod, "Crawler", _Summarising)
    result = await Orchestrator(_active(), check_types=[HstsCheck]).run(_TARGET)
    assert [w for w in result.warnings if w.startswith("POST crawl:")] == [
        "POST crawl: 3 submitted — 2 forms, 1 API operation, 3 skipped, 0 not submitted (cap)"
    ]


async def test_no_post_crawl_warning_when_the_phase_did_not_run() -> None:
    """No tally line without a summary (the default stub has none)."""
    result = await Orchestrator(_active(), check_types=[HstsCheck]).run(_TARGET)
    assert not any(w.startswith("POST crawl:") for w in result.warnings)


async def test_post_crawl_opt_in_without_active_mode_warns() -> None:
    """The opt-in in Passive mode is a no-op that warns it needs ``--mode active``."""
    config = ScanConfig.model_validate({"scan": {"submit_post_forms": True}})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert any("POST crawling requires --mode active" in w for w in result.warnings)

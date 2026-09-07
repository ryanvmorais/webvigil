"""Orchestrator wiring for the active-injection pass — spec 006 RF-01, RF-12, ADR-2."""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.headers.hsts import HstsCheck
from webvigil.checks.injection.checks import ReflectedXssCheck, StoredXssCheck
from webvigil.checks.injection.models import InjectionHit, StoredXssReport
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.findings import Confidence, Severity
from webvigil.core.orchestrator import Orchestrator

_TARGET = "https://example.com/"
_SEED = "https://example.com/s?q=hi"

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)


class _StubCrawler:
    forms: tuple[object, ...] = ()
    skipped_destructive = 0

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
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


def _active(**checks_kw: object) -> ScanConfig:
    return ScanConfig.model_validate(
        {"scan": {"mode": "active"}, "active": {"authorized_by": "test"}, **checks_kw}
    )


def _boom(*_a: object, **_k: object) -> object:
    raise AssertionError("InjectionScanner must not run")


async def test_passive_scan_never_runs_the_injection_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orch_mod, "InjectionScanner", _boom)
    result = await Orchestrator(ScanConfig(), check_types=[ReflectedXssCheck]).run(_TARGET)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_active_scan_with_no_injection_check_selected_does_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orch_mod, "InjectionScanner", _boom)
    result = await Orchestrator(_active(), check_types=[HstsCheck]).run(_TARGET)
    assert not any(f.check_id.startswith("injection.") for f in result.findings)


async def test_active_scan_reflected_xss_is_reported(httpx_mock: object) -> None:
    def router(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        return httpx.Response(
            200, text=f"<div>results for {value}</div>", headers={"content-type": "text/html"}
        )

    httpx_mock.add_callback(router, is_reusable=True)  # type: ignore[attr-defined]
    result = await Orchestrator(_active(), check_types=[ReflectedXssCheck]).run(_TARGET)
    xss = [f for f in result.findings if f.check_id == "injection.xss.reflected"]
    assert xss and xss[0].location.param == "q"


async def test_a_raising_pass_becomes_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Raises:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def run(self) -> object:
            raise RuntimeError("detector blew up")

    monkeypatch.setattr(orch_mod, "InjectionScanner", _Raises)
    result = await Orchestrator(_active(), check_types=[ReflectedXssCheck]).run(_TARGET)
    assert any("active injection pass failed" in w for w in result.warnings)


# --- spec 008: the stored-XSS pass -------------------------------------------------


def _stored_boom(*_a: object, **_k: object) -> object:
    raise AssertionError("StoredXssScanner must not run")


class _StoredStub:
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
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _stored_boom)
    result = await Orchestrator(_active(), check_types=[StoredXssCheck]).run(_TARGET)
    assert not any(f.check_id == "injection.xss.stored" for f in result.findings)


async def test_stored_pass_skipped_when_check_not_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _stored_boom)
    config = _active(injection={"stored_xss": True})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert not any(f.check_id == "injection.xss.stored" for f in result.findings)


async def test_stored_pass_runs_and_merges_its_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _StoredStub)
    config = _active(injection={"stored_xss": True})
    result = await Orchestrator(config, check_types=[StoredXssCheck]).run(_TARGET)
    stored = [f for f in result.findings if f.check_id == "injection.xss.stored"]
    assert stored and stored[0].location.param == "body"
    assert any("3-page cap" in w for w in result.warnings)


async def test_a_raising_stored_pass_becomes_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Raises:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def run(self) -> object:
            raise RuntimeError("recrawl blew up")

    monkeypatch.setattr(orch_mod, "StoredXssScanner", _Raises)
    config = _active(injection={"stored_xss": True})
    result = await Orchestrator(config, check_types=[StoredXssCheck]).run(_TARGET)
    assert any("stored-XSS pass failed" in w for w in result.warnings)


async def test_stored_opt_in_without_active_mode_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "StoredXssScanner", _stored_boom)
    config = ScanConfig.model_validate({"injection": {"stored_xss": True}})
    result = await Orchestrator(config, check_types=[HstsCheck]).run(_TARGET)
    assert any("requires --mode active" in w for w in result.warnings)

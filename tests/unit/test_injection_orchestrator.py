"""Orchestrator wiring for the active-injection pass — spec 006 RF-01, RF-12, ADR-2."""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.headers.hsts import HstsCheck
from webvigil.checks.injection.checks import ReflectedXssCheck
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.orchestrator import Orchestrator

_TARGET = "https://example.com/"
_SEED = "https://example.com/s?q=hi"

pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)


class _StubCrawler:
    def __init__(self, *_a: object, **_k: object) -> None: ...

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

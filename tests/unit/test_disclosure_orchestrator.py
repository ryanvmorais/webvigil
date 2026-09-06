"""Orchestrator wiring for the disclosure probe pass — RF-04, RF-09, ADR-2."""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.disclosure.checks import DotenvExposedCheck, VcsExposedCheck
from webvigil.checks.disclosure.errors import ErrorPageCheck
from webvigil.checks.headers.hsts import HstsCheck
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.orchestrator import Orchestrator

_TARGET = "https://example.com/"
_GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n"


class _StubCrawler:
    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def discover(self) -> list[Page]:
        return [
            Page(
                requested_url=_TARGET,
                url=_TARGET,
                status_code=200,
                headers=httpx.Headers({"content-type": "text/html"}),
                text="<html><body>ok</body></html>",
                elapsed_ms=1.0,
            )
        ]


@pytest.fixture(autouse=True)
def _stub_crawler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


pytestmark = pytest.mark.httpx_mock(assert_all_responses_were_requested=False)


def _router(request: httpx.Request) -> httpx.Response:
    if str(request.url) == "https://example.com/.git/config":
        return httpx.Response(200, text=_GIT_CONFIG, headers={"content-type": "text/plain"})
    return httpx.Response(404, text="nope", headers={"content-type": "text/html"})


def _boom(*_a: object, **_k: object) -> object:
    raise AssertionError("DisclosureProbe must not run")


async def test_probe_off_by_default_does_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "DisclosureProbe", _boom)
    result = await Orchestrator(ScanConfig(), check_types=[VcsExposedCheck]).run(_TARGET)
    assert not any(f.check_id.startswith("disclosure.") for f in result.findings)


async def test_probe_on_but_no_probe_fed_check_does_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orch_mod, "DisclosureProbe", _boom)
    config = ScanConfig(disclosure={"probe": True})
    # ErrorPageCheck is a disclosure check but NOT probe-fed
    result = await Orchestrator(config, check_types=[ErrorPageCheck, HstsCheck]).run(_TARGET)
    assert all(not f.check_id.startswith("disclosure.vcs") for f in result.findings)


async def test_probe_on_with_a_probe_fed_check_emits_findings(httpx_mock: object) -> None:
    httpx_mock.add_callback(_router, is_reusable=True)  # type: ignore[attr-defined]
    config = ScanConfig(disclosure={"probe": True})
    result = await Orchestrator(config, check_types=[VcsExposedCheck, DotenvExposedCheck]).run(
        _TARGET
    )
    vcs = [f for f in result.findings if f.check_id == "disclosure.vcs.exposed"]
    assert vcs and "/.git/config" in vcs[0].title


async def test_probe_warnings_surface_on_the_result(
    httpx_mock: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orch_mod, "_PROBE_FAMILIES", frozenset({"vcs"}))
    monkeypatch.setattr("webvigil.checks.disclosure.probe._REQUEST_CAP", 3)
    httpx_mock.add_callback(_router, is_reusable=True)  # type: ignore[attr-defined]
    config = ScanConfig(disclosure={"probe": True})
    result = await Orchestrator(config, check_types=[VcsExposedCheck]).run(_TARGET)
    assert any("3-request cap" in w for w in result.warnings)

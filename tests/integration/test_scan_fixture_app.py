"""End-to-end: insecure profile reports the expected findings, hardened reports none — RF-27."""

from __future__ import annotations

import functools

import httpx
import pytest

from tests.fixtures.app import make_app
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.result import ScanResult
from webvigil.http.client import HttpClient

_TARGET = "http://demo.test/"
# The fixture app is plain HTTP; TLS findings are covered by the socket-based unit tests.
_DISABLED = ["tls.https"]


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch):
    async def _run(profile: str) -> ScanResult:
        transport = httpx.ASGITransport(app=make_app(profile))
        monkeypatch.setattr(
            orch_mod, "HttpClient", functools.partial(HttpClient, transport=transport)
        )
        config = ScanConfig.model_validate({"checks": {"disabled": _DISABLED}})
        return await Orchestrator(config).run(_TARGET)

    return _run


async def test_insecure_profile_reports_every_expected_check(scan) -> None:
    result = await scan("insecure")
    reported = {finding.check_id for finding in result.findings}
    assert {
        "http.headers.csp",
        "http.headers.frame-options",
        "http.headers.content-type-options",
        "http.headers.referrer-policy",
        "http.headers.permissions-policy",
        "http.headers.cross-origin-isolation",
        "http.headers.revealing",
        "http.cookies.flags",
        "http.cors.misconfiguration",
    } <= reported
    assert result.errors == ()


async def test_hardened_profile_reports_nothing(scan) -> None:
    result = await scan("hardened")
    assert result.findings == ()
    assert result.errors == ()


async def test_crawler_reaches_the_linked_pages(scan) -> None:
    result = await scan("hardened")
    assert result.metadata.pages_scanned == 3

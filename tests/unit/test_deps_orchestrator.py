"""Orchestrator wiring for the dependency fingerprint pass — RF-12, RF-22, ADR-1, ADR-3."""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.deps.check import LibraryDetectedCheck, VulnerableLibraryCheck
from webvigil.checks.headers.hsts import HstsCheck
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.orchestrator import Orchestrator

_TARGET = "https://example.com/"
_HTML = (
    "<html><head><script>/*! jQuery v3.4.1 | (c) JS Foundation */</script></head>"
    "<body>ok</body></html>"
)


class _StubCrawler:
    forms: tuple[object, ...] = ()
    skipped_destructive = 0

    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def discover(self) -> list[Page]:
        return [
            Page(
                requested_url=_TARGET,
                url=_TARGET,
                status_code=200,
                headers=httpx.Headers({"content-type": "text/html"}),
                text=_HTML,
                elapsed_ms=1.0,
            )
        ]


@pytest.fixture(autouse=True)
def _stub_crawler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


async def test_deps_check_selected_populates_the_inventory_and_finds_the_vulnerability() -> None:
    result = await Orchestrator(
        ScanConfig(), check_types=[VulnerableLibraryCheck, LibraryDetectedCheck]
    ).run(_TARGET)

    assert [(t.name, t.version, t.vulnerable) for t in result.technologies] == [
        ("jquery", "3.4.1", True)
    ]
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)


async def test_no_deps_check_means_no_fingerprint_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> object:
        raise AssertionError("Fingerprinter must not run without a DEPS check")

    monkeypatch.setattr(orch_mod, "Fingerprinter", _boom)

    result = await Orchestrator(ScanConfig(), check_types=[HstsCheck]).run(_TARGET)
    assert result.technologies == ()


async def test_stale_database_adds_a_scan_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "staleness_warning", lambda _rules: ["advisory data is old"])
    result = await Orchestrator(ScanConfig(), check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert "advisory data is old" in result.warnings

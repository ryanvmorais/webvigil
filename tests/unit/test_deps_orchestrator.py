"""
Orchestrator wiring for the dependency fingerprint pass — RF-12, RF-22, ADR-1, ADR-3.
"""

from __future__ import annotations

import httpx
import pytest

from webvigil.checks.deps.advisories import Advisory
from webvigil.checks.deps.check import LibraryDetectedCheck, VulnerableLibraryCheck
from webvigil.checks.deps.osv import OsvLookupError, OsvResult
from webvigil.checks.headers.hsts import HstsCheck
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Page
from webvigil.core.findings import Severity
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


# --- spec 010: the opt-in OSV.dev lookup pass -------------------------------------

_OSV_ADVISORY = Advisory(
    identifiers=("GHSA-orch", "CVE-9000-1"),
    summary="from osv",
    severity=Severity.HIGH,
    severity_from_upstream=True,
    first_safe_version="3.5.0",
    info_urls=("https://osv.dev/vulnerability/GHSA-orch",),
    cwe=(79,),
)


def _osv_boom(*_a: object, **_k: object) -> object:
    raise AssertionError("OsvProvider must not run")


class _StubOsv:
    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def lookup(self, _detections: object) -> OsvResult:
        return OsvResult(advisories={("jquery", "3.4.1"): (_OSV_ADVISORY,)}, warnings=("osv note",))


async def test_osv_lookup_is_skipped_without_the_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "OsvProvider", _osv_boom)
    result = await Orchestrator(ScanConfig(), check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)


async def test_osv_lookup_is_skipped_when_no_deps_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch_mod, "OsvProvider", _osv_boom)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[HstsCheck]).run(_TARGET)
    assert result.technologies == ()


async def test_osv_lookup_runs_and_merges_into_the_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orch_mod, "OsvProvider", _StubOsv)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert "osv note" in result.warnings
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert "GHSA-orch" in " ".join(e.content for e in finding.evidence)


async def test_osv_lookup_failure_is_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Boom:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def lookup(self, _detections: object) -> OsvResult:
            raise OsvLookupError("connection refused")

    monkeypatch.setattr(orch_mod, "OsvProvider", _Boom)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any("OSV.dev lookup failed" in w for w in result.warnings)
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)

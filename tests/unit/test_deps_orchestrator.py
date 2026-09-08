"""
Orchestrator wiring for the dependency fingerprint pass — RF-12, RF-22, ADR-1, ADR-3.

The autouse ``_stub_crawler`` fixture replaces the crawler with one that returns
a single page carrying a jQuery banner, so the tests exercise the orchestrator's
pass selection without any HTTP. ``OsvProvider`` is monkeypatched per test — to
a boom stub when it must not run, to a canned-result stub when it must.
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
    """A crawler that discovers exactly one HTML page carrying a jQuery 3.4.1 banner."""

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
    """Swap the orchestrator's ``Crawler`` for :class:`_StubCrawler`."""
    monkeypatch.setattr(orch_mod, "Crawler", _StubCrawler)


# ---------------------------------------------------------------------------
# The offline fingerprint pass
# ---------------------------------------------------------------------------


async def test_deps_check_selected_populates_the_inventory_and_finds_the_vulnerability() -> None:
    """With a DEPS check selected, the pass runs, the inventory fills, and the finding appears."""
    result = await Orchestrator(
        ScanConfig(), check_types=[VulnerableLibraryCheck, LibraryDetectedCheck]
    ).run(_TARGET)

    assert [(t.name, t.version, t.vulnerable) for t in result.technologies] == [
        ("jquery", "3.4.1", True)
    ]
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)


async def test_no_deps_check_means_no_fingerprint_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """With only a non-DEPS check selected, the Fingerprinter is never constructed."""

    def _boom(*_a: object, **_k: object) -> object:
        raise AssertionError("Fingerprinter must not run without a DEPS check")

    monkeypatch.setattr(orch_mod, "Fingerprinter", _boom)

    result = await Orchestrator(ScanConfig(), check_types=[HstsCheck]).run(_TARGET)
    assert result.technologies == ()


async def test_stale_database_adds_a_scan_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A staleness warning from the rules is surfaced on the scan result."""
    monkeypatch.setattr(orch_mod, "staleness_warning", lambda _rules: ["advisory data is old"])
    result = await Orchestrator(ScanConfig(), check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert "advisory data is old" in result.warnings


# ---------------------------------------------------------------------------
# The opt-in OSV.dev lookup pass (spec 010)
# ---------------------------------------------------------------------------

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
    """A stand-in that fails the test if the OSV provider is constructed at all."""
    raise AssertionError("OsvProvider must not run")


class _StubOsv:
    """An OSV provider that always returns one advisory for jquery 3.4.1 and a warning."""

    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def lookup(self, _detections: object) -> OsvResult:
        return OsvResult(advisories={("jquery", "3.4.1"): (_OSV_ADVISORY,)}, warnings=("osv note",))


async def test_osv_lookup_is_skipped_without_the_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``[deps] osv_online`` the provider is never constructed."""
    monkeypatch.setattr(orch_mod, "OsvProvider", _osv_boom)
    result = await Orchestrator(ScanConfig(), check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)


async def test_osv_lookup_is_skipped_when_no_deps_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-in alone is not enough — with no DEPS check the lookup is still skipped."""
    monkeypatch.setattr(orch_mod, "OsvProvider", _osv_boom)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[HstsCheck]).run(_TARGET)
    assert result.technologies == ()


async def test_osv_lookup_runs_and_merges_into_the_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the opt-in and a DEPS check, the OSV advisory and its warning reach the result."""
    monkeypatch.setattr(orch_mod, "OsvProvider", _StubOsv)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert "osv note" in result.warnings
    finding = next(f for f in result.findings if f.check_id == "deps.js.vulnerable-library")
    assert "GHSA-orch" in " ".join(e.content for e in finding.evidence)


async def test_osv_lookup_failure_is_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An :class:`OsvLookupError` degrades to a warning; the offline finding still stands."""

    class _Boom:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def lookup(self, _detections: object) -> OsvResult:
            raise OsvLookupError("connection refused")

    monkeypatch.setattr(orch_mod, "OsvProvider", _Boom)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any("OSV.dev lookup failed" in w for w in result.warnings)
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)

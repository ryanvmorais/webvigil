"""
Orchestrator wiring for the dependency fingerprint pass — RF-12, RF-22, ADR-1, ADR-3.

The autouse ``_stub_crawler`` fixture replaces the crawler with one that returns
a single page carrying a jQuery banner, so the tests exercise the orchestrator's
pass selection without any HTTP. ``OsvProvider`` is monkeypatched per test — to
a counting stub when it must not run, to a canned-result stub when it must.
"""

from __future__ import annotations

import httpx2
import pytest

from webvigil.checks.deps.advisories import Advisory
from webvigil.checks.deps.check import LibraryDetectedCheck, VulnerableLibraryCheck
from webvigil.checks.deps.osv import OsvLookupError, OsvResult
from webvigil.checks.headers.hsts import HstsCheck
from webvigil.core import orchestrator as orch_mod
from webvigil.core.config import ScanConfig
from webvigil.core.context import Detection, Page
from webvigil.core.findings import Severity
from webvigil.core.orchestrator import Orchestrator
from webvigil.core.technology import DetectionMethod

_TARGET = "https://example.com/"
_HTML = (
    "<html><head><script>/*! jQuery v3.4.1 | (c) JS Foundation */</script></head>"
    "<body>ok</body></html>"
)


class _StubCrawler:
    """A crawler that discovers exactly one HTML page carrying a jQuery 3.4.1 banner."""

    forms: tuple[object, ...] = ()
    skipped_destructive = 0
    skipped_by_robots = 0
    limit_warning: str | None = None
    post_summary = None  # spec 018: the real crawler exposes the POST phase tally

    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def discover(self) -> list[Page]:
        return [
            Page(
                requested_url=_TARGET,
                url=_TARGET,
                status_code=200,
                headers=httpx2.Headers({"content-type": "text/html"}),
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


class _CountingOsv:
    """
    An OSV provider that counts how often it is built.

    A provider that raised instead would prove nothing: ``_osv_lookup`` turns any exception from
    the lookup into a scan warning, so the scan would go on as if the provider had not run.
    """

    built = 0

    def __init__(self, *_a: object, **_k: object) -> None:
        type(self).built += 1

    async def lookup(self, _detections: object) -> OsvResult:
        return OsvResult(advisories={})


@pytest.fixture
def counting_osv(monkeypatch: pytest.MonkeyPatch) -> type[_CountingOsv]:
    """
    Args:
        monkeypatch (pytest.MonkeyPatch): The fixture that installs the stub.

    Returns:
        type[_CountingOsv]: The provider class installed in the orchestrator, its count at zero.
    """
    monkeypatch.setattr(_CountingOsv, "built", 0)
    monkeypatch.setattr(orch_mod, "OsvProvider", _CountingOsv)
    return _CountingOsv


class _StubOsv:
    """An OSV provider that always returns one advisory for jquery 3.4.1 and a warning."""

    def __init__(self, *_a: object, **_k: object) -> None: ...

    async def lookup(self, _detections: object) -> OsvResult:
        return OsvResult(advisories={("jquery", "3.4.1"): (_OSV_ADVISORY,)}, warnings=("osv note",))


async def test_osv_lookup_is_skipped_without_the_opt_in(
    counting_osv: type[_CountingOsv],
) -> None:
    """Without ``[deps] osv_online`` the provider is never constructed."""
    result = await Orchestrator(ScanConfig(), check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)
    assert counting_osv.built == 0
    # Control: the same scan with the opt-in builds it once.
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    await Orchestrator(cfg, check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert counting_osv.built == 1


async def test_osv_lookup_is_skipped_when_no_deps_check(counting_osv: type[_CountingOsv]) -> None:
    """The opt-in alone is not enough — with no DEPS check the lookup is still skipped."""
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[HstsCheck]).run(_TARGET)
    assert result.technologies == ()
    assert counting_osv.built == 0


async def test_osv_lookup_checks_for_a_deps_check_even_when_given_detections(
    counting_osv: type[_CountingOsv],
) -> None:
    """
    ``_osv_lookup`` keeps its own DEPS-check gate: a scan reaches it with detections only through
    the fingerprint pass, which has the same gate, so it is called here directly.
    """
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    detection = Detection("jquery", "3.4.1", DetectionMethod.FILENAME, _TARGET, "jquery.js")
    warnings: list[str] = []
    orchestrator = Orchestrator(cfg, check_types=[HstsCheck])
    assert await orchestrator._osv_lookup([HstsCheck], (detection,), warnings) == {}
    assert counting_osv.built == 0
    await orchestrator._osv_lookup([VulnerableLibraryCheck], (detection,), warnings)
    assert counting_osv.built == 1


async def test_osv_lookup_asks_only_about_detections_with_a_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A library without a version has no advisories to ask about; none at all asks nothing."""
    asked: list[tuple[Detection, ...]] = []

    class _Recording(_CountingOsv):
        async def lookup(self, detections: tuple[Detection, ...]) -> OsvResult:
            asked.append(tuple(detections))
            return OsvResult(advisories={})

    monkeypatch.setattr(orch_mod, "OsvProvider", _Recording)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    versioned = Detection("jquery", "3.4.1", DetectionMethod.FILENAME, _TARGET, "jquery.js")
    bare = Detection("react", None, DetectionMethod.URI, _TARGET, "react.js")
    orchestrator = Orchestrator(cfg, check_types=[VulnerableLibraryCheck])

    await orchestrator._osv_lookup([VulnerableLibraryCheck], (versioned, bare), [])
    assert asked == [(versioned,)]
    assert await orchestrator._osv_lookup([VulnerableLibraryCheck], (bare,), []) == {}
    assert asked == [(versioned,)]  # nothing with a version: no lookup at all


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
    assert result.pass_failed is False  # a third party being down is not a failed pass
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)


async def test_an_unexpected_osv_exception_is_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any other exception from the lookup also degrades to a warning, without its message."""

    class _Boom:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def lookup(self, _detections: object) -> OsvResult:
            raise KeyError("third-party text")

    monkeypatch.setattr(orch_mod, "OsvProvider", _Boom)
    cfg = ScanConfig.model_validate({"deps": {"osv_online": True}})
    result = await Orchestrator(cfg, check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any("OSV.dev lookup failed (KeyError)" in w for w in result.warnings)
    assert result.pass_failed is False
    assert not any("third-party text" in w for w in result.warnings)
    assert any(f.check_id == "deps.js.vulnerable-library" for f in result.findings)


async def test_a_raising_fingerprint_pass_becomes_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception from the fingerprint pass degrades to a scan warning."""

    async def _raises(*_a: object, **_k: object) -> object:
        raise ValueError("Invalid IPv6 URL")

    monkeypatch.setattr(orch_mod.Fingerprinter, "scan", _raises)
    result = await Orchestrator(ScanConfig(), check_types=[VulnerableLibraryCheck]).run(_TARGET)
    assert any("dependency fingerprint pass failed" in w for w in result.warnings)
    assert result.technologies == ()

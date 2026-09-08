"""
The DEPS checks: finding shape, INFO for unknown version, the inventory — RF-09, RF-10, RF-12.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from tests.support import make_context, make_page
from webvigil.checks.deps import check as check_mod
from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.advisories import Advisory, RetireJsProvider
from webvigil.checks.deps.check import LibraryDetectedCheck, VulnerableLibraryCheck
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.core.context import Detection, Observations
from webvigil.core.findings import Category, Confidence, ScanMode, Severity
from webvigil.core.technology import DetectionMethod

_MINI = Path(__file__).parent.parent / "data" / "retirejs-mini.json"


@pytest.fixture(autouse=True)
def _mini_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = RetireJsRules.from_raw(
        json.loads(_MINI.read_text("utf-8")),
        Provenance(
            source_url="x", retrieved=date(2026, 1, 1), license="Apache-2.0", attribution="t"
        ),
    )
    provider = RetireJsProvider(rules)
    check_mod._provider.cache_clear()
    monkeypatch.setattr(check_mod, "_provider", lambda: provider)


def _ctx(*detections: Detection):
    return make_context(make_page(), observations=Observations(detections=detections))


def _det(
    name: str, version: str | None, method: DetectionMethod = DetectionMethod.FILENAME
) -> Detection:
    return Detection(name, version, method, f"https://example.com/{name}.js", f"{name}-marker")


async def test_metadata() -> None:
    assert VulnerableLibraryCheck.category is Category.DEPS
    assert VulnerableLibraryCheck.mode is ScanMode.PASSIVE
    assert LibraryDetectedCheck.default_severity is Severity.INFO


async def test_vulnerable_library_finding_shape() -> None:
    ctx = _ctx(_det("jquery", "1.4.0"))
    findings = await VulnerableLibraryCheck().run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "deps.js.vulnerable-library"
    assert finding.severity is Severity.MEDIUM
    assert "jquery 1.4.0" in finding.title
    assert "CVE-2011-4969" in " ".join(e.content for e in finding.evidence)
    assert 79 in finding.cwe
    assert any("1.6.3" in r or "cwe.mitre.org" in r for r in finding.references)
    assert "Upgrade jquery to" in finding.remediation

    inventory = ctx.observations.technologies
    assert [(t.name, t.version, t.vulnerable) for t in inventory] == [("jquery", "1.4.0", True)]
    assert "CVE-2011-4969" in inventory[0].advisories


async def test_clean_version_is_inventory_only_no_finding() -> None:
    ctx = _ctx(_det("jquery", "3.6.0"))
    findings = await VulnerableLibraryCheck().run(ctx)
    assert findings == []
    assert [(t.name, t.vulnerable) for t in ctx.observations.technologies] == [("jquery", False)]


async def test_library_detected_only_for_unknown_version() -> None:
    ctx = _ctx(_det("jquery", None, DetectionMethod.URI), _det("lodash", "3.0.0"))

    info = await LibraryDetectedCheck().run(ctx)
    assert len(info) == 1
    assert info[0].check_id == "deps.js.library-detected"
    assert info[0].severity is Severity.INFO
    assert info[0].confidence is Confidence.LOW
    assert "version undetermined" in info[0].title

    assert [(t.name, t.version) for t in ctx.observations.technologies] == [("jquery", None)]


async def test_both_checks_share_one_inventory_entry_per_library() -> None:
    detections = (_det("jquery", "1.4.0"), _det("jquery", None, DetectionMethod.URI))
    ctx = make_context(make_page(), observations=Observations(detections=detections))

    await VulnerableLibraryCheck().run(ctx)
    await LibraryDetectedCheck().run(ctx)

    inventory = ctx.observations.technologies
    assert [(t.name, t.version) for t in inventory] == [("jquery", None), ("jquery", "1.4.0")]


async def test_multiple_advisories_take_the_highest_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # jquery 1.4.0 matches only the "below 1.6.3" entry in the mini DB (medium). Add a
    # high-severity entry that also covers it.
    raw = json.loads(_MINI.read_text("utf-8"))
    raw["components"]["jquery"]["vulnerabilities"].append(
        {
            "ranges": [{"below": "2.0.0"}],
            "severity": "high",
            "identifiers": ["CVE-9999-0001"],
            "summary": "test",
            "cwe": [],
            "info": [],
        }
    )
    provider = RetireJsProvider(
        RetireJsRules.from_raw(
            raw,
            Provenance(source_url="x", retrieved=date(2026, 1, 1), license="l", attribution="a"),
        )
    )
    monkeypatch.setattr(check_mod, "_provider", lambda: provider)

    findings = await VulnerableLibraryCheck().run(_ctx(_det("jquery", "1.4.0")))
    assert findings[0].severity is Severity.HIGH


def _osv(*ids: str, severity: Severity = Severity.HIGH, safe: str | None = None) -> Advisory:
    return Advisory(
        identifiers=ids,
        summary="from osv",
        severity=severity,
        severity_from_upstream=True,
        first_safe_version=safe,
        info_urls=(f"https://osv.dev/vulnerability/{ids[0]}",),
        cwe=(),
    )


async def test_osv_advisory_creates_a_finding_where_retirejs_found_nothing() -> None:
    # lodash 5.0.0 is clean in the mini DB, but the OSV lookup pass left an advisory for it.
    ctx = make_context(
        make_page(),
        observations=Observations(
            detections=(_det("lodash", "5.0.0"),),
            osv_advisories={("lodash", "5.0.0"): (_osv("GHSA-lodash-x", safe="5.1.0"),)},
        ),
    )
    findings = await VulnerableLibraryCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "GHSA-lodash-x" in " ".join(e.content for e in findings[0].evidence)
    assert any("osv.dev/vulnerability/GHSA-lodash-x" in r for r in findings[0].references)
    assert [(t.name, t.vulnerable) for t in ctx.observations.technologies] == [("lodash", True)]


async def test_osv_and_retirejs_advisories_for_the_same_cve_merge_into_one_finding() -> None:
    # jquery 1.4.0 -> Retire.js CVE-2011-4969 (medium). OSV returns the same CVE at HIGH.
    ctx = make_context(
        make_page(),
        observations=Observations(
            detections=(_det("jquery", "1.4.0"),),
            osv_advisories={
                ("jquery", "1.4.0"): (_osv("GHSA-jq", "CVE-2011-4969", severity=Severity.HIGH),)
            },
        ),
    )
    findings = await VulnerableLibraryCheck().run(ctx)
    assert len(findings) == 1
    identifiers = " ".join(e.content for e in findings[0].evidence)
    assert "CVE-2011-4969" in identifiers and "GHSA-jq" in identifiers
    assert findings[0].severity is Severity.HIGH  # the higher of the two sources

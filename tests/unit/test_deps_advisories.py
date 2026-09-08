"""
RetireJsProvider: range semantics, severity mapping, first safe version — RF-07, RF-08.

The ``provider`` fixture is backed by ``tests/data/retirejs-mini.json`` (a
jquery + lodash slice), so range and severity behaviour is asserted against a
known, small database rather than the real vendored one.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.advisories import Advisory, RetireJsProvider, merge_advisories
from webvigil.checks.deps.rules import RetireJsRules
from webvigil.core.findings import Severity

_MINI = Path(__file__).parent.parent / "data" / "retirejs-mini.json"
_PROVENANCE = Provenance(
    source_url="https://example/retire.js",
    retrieved=date(2026, 1, 1),
    license="Apache-2.0",
    attribution="test",
)


@pytest.fixture
def provider() -> RetireJsProvider:
    """
    Returns:
        RetireJsProvider: A provider over the mini database.
    """
    return RetireJsProvider(
        RetireJsRules.from_raw(json.loads(_MINI.read_text("utf-8")), _PROVENANCE)
    )


# ---------------------------------------------------------------------------
# Version-range matching
# ---------------------------------------------------------------------------


def test_below_only_range_matches_old_version(provider: RetireJsProvider) -> None:
    """A ``below``-only range matches every version under the bound."""
    hits = provider.match("jquery", "1.4.0")
    assert any("CVE-2011-4969" in a.identifiers for a in hits)


def test_at_or_above_and_below_range(provider: RetireJsProvider) -> None:
    """A half-open ``[atOrAbove, below)`` range excludes versions above ``below``."""
    assert provider.match("jquery", "3.4.1")  # inside [1.0.0, 3.5.0)
    assert not any(  # 3.6.0 is above every jquery range in the mini DB
        "CVE-2020-11022" in a.identifiers for a in provider.match("jquery", "3.6.0")
    )


def test_boundary_is_exclusive(provider: RetireJsProvider) -> None:
    """The ``below`` bound itself is not vulnerable."""
    # 3.5.0 == below bound -> not vulnerable for that entry
    assert not any("CVE-2020-11022" in a.identifiers for a in provider.match("jquery", "3.5.0"))


def test_first_safe_version(provider: RetireJsProvider) -> None:
    """``first_safe_version`` is the lowest ``below`` bound of the matched ranges."""
    assert provider.match("jquery", "3.4.1")[0].first_safe_version == "3.5.0"
    assert provider.match("jquery", "1.4.0")[0].first_safe_version == "1.6.3"


def test_unknown_library_and_clean_version(provider: RetireJsProvider) -> None:
    """An unknown library, or a version above every range, yields no advisories."""
    assert provider.match("react", "16.0.0") == []
    assert provider.match("lodash", "5.0.0") == []


def test_loose_version_string_does_not_crash(provider: RetireJsProvider) -> None:
    """A non-PEP-440 version still compares via the numeric fallback."""
    assert provider.match("jquery", "1.4.0-custom.build")


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def test_severity_maps_and_defaults(provider: RetireJsProvider) -> None:
    """A named upstream severity is mapped; a missing one falls back to MEDIUM."""
    jquery = provider.match("jquery", "1.4.0")[0]
    assert jquery.severity is Severity.MEDIUM
    assert jquery.severity_from_upstream is True

    lodash = provider.match("lodash", "4.0.0")[0]  # mini DB entry has no severity
    assert lodash.severity is Severity.MEDIUM
    assert lodash.severity_from_upstream is False


# ---------------------------------------------------------------------------
# merge_advisories
# ---------------------------------------------------------------------------


def _adv(
    *ids: str,
    severity: Severity = Severity.MEDIUM,
    from_upstream: bool = True,
    safe: str | None = None,
    urls: tuple[str, ...] = (),
    cwe: tuple[int, ...] = (),
    summary: str = "s",
) -> Advisory:
    """
    Args:
        *ids (str): Advisory identifiers.
        severity (Severity): Severity. Defaults to ``MEDIUM``.
        from_upstream (bool): The ``severity_from_upstream`` flag. Defaults to
            ``True``.
        safe (str | None): First safe version.
        urls (tuple[str, ...]): Info URLs.
        cwe (tuple[int, ...]): CWE ids.
        summary (str): One-line summary. Defaults to ``"s"``.

    Returns:
        Advisory: The assembled advisory.
    """
    return Advisory(
        identifiers=ids,
        summary=summary,
        severity=severity,
        severity_from_upstream=from_upstream,
        first_safe_version=safe,
        info_urls=urls,
        cwe=cwe,
    )


def test_merge_coalesces_advisories_that_share_an_identifier() -> None:
    """Two advisories sharing a CVE merge into one (unions, max severity)."""
    retire = _adv("CVE-2020-11022", severity=Severity.MEDIUM, safe="3.5.0", urls=("r",), cwe=(79,))
    osv = _adv(
        "GHSA-gxr4-xjj5-5px2",
        "CVE-2020-11022",
        severity=Severity.HIGH,
        safe="3.5.1",
        urls=("o", "r"),
        cwe=(80,),
        summary="osv",
    )
    merged = merge_advisories([retire], [osv])
    assert len(merged) == 1
    only = merged[0]
    assert only.identifiers == ("CVE-2020-11022", "GHSA-gxr4-xjj5-5px2")
    assert only.severity is Severity.HIGH
    assert only.first_safe_version == "3.5.1"  # the higher of the two
    assert only.info_urls == ("r", "o")
    assert set(only.cwe) == {79, 80}
    assert only.summary == "s / osv"


def test_merge_keeps_disjoint_advisories_separate() -> None:
    """Advisories with no shared identifier stay separate."""
    a = _adv("CVE-1111-1")
    b = _adv("CVE-2222-2")
    assert len(merge_advisories([a, b])) == 2


def test_merge_follows_a_transitive_identifier_chain() -> None:
    """A -> B, B -> C collapses all three into one bucket."""
    a = _adv("CVE-A", "CVE-B")
    b = _adv("CVE-B", "CVE-C")
    c = _adv("CVE-C")
    merged = merge_advisories([a], [b], [c])
    assert len(merged) == 1
    assert merged[0].identifiers == ("CVE-A", "CVE-B", "CVE-C")


def test_merge_single_source_passthrough_is_identity() -> None:
    """A lone advisory comes back unchanged, not re-wrapped."""
    a = _adv("CVE-1")
    assert merge_advisories([a]) == [a]


def test_merge_is_order_stable_for_non_overlapping_input() -> None:
    """The output order tracks the input order."""
    a, b, c = _adv("CVE-1"), _adv("CVE-2"), _adv("CVE-3")

    def ids(group: list[Advisory]) -> list[tuple[str, ...]]:
        return [x.identifiers for x in merge_advisories(group)]

    assert ids([a, b, c]) == [("CVE-1",), ("CVE-2",), ("CVE-3",)]
    assert ids([c, a, b]) == [("CVE-3",), ("CVE-1",), ("CVE-2",)]

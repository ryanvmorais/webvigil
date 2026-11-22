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
from webvigil.checks.deps.advisories import (
    Advisory,
    RetireJsProvider,
    _pep440,
    merge_advisories,
)
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


def _ids(provider: RetireJsProvider, name: str, version: str) -> list[tuple[str, ...]]:
    """
    Args:
        provider (RetireJsProvider): The provider under test.
        name (str): The library name.
        version (str): The detected version.

    Returns:
        list[tuple[str, ...]]: The identifiers of every advisory matched, in order.
    """
    return [a.identifiers for a in provider.match(name, version)]


_OLD_XSS = ("CVE-2011-4969", "GHSA-579v-mp3v-rrw5")  # below 1.6.3
_HTML_XSS = ("CVE-2020-11022", "CVE-2020-11023")  # [1.0.0, 3.5.0)


def test_at_or_above_and_below_range(provider: RetireJsProvider) -> None:
    """A half-open ``[atOrAbove, below)`` range holds what is inside it, nothing past ``below``."""
    assert _ids(provider, "jquery", "3.4.1") == [_HTML_XSS]
    assert _ids(provider, "jquery", "3.6.0") == []


def test_a_version_under_at_or_above_is_outside_the_range(provider: RetireJsProvider) -> None:
    """The lower bound counts: 0.9.0 is under ``atOrAbove`` 1.0.0, so only the older entry fits."""
    assert _ids(provider, "jquery", "0.9.0") == [_OLD_XSS]
    assert _ids(provider, "jquery", "1.0.0") == [_OLD_XSS, _HTML_XSS]  # the bound is inclusive


def test_boundary_is_exclusive(provider: RetireJsProvider) -> None:
    """The ``below`` bound itself is not vulnerable."""
    # 3.5.0 == below bound -> not vulnerable for that entry
    assert not any("CVE-2020-11022" in a.identifiers for a in provider.match("jquery", "3.5.0"))


def test_first_safe_version(provider: RetireJsProvider) -> None:
    """``first_safe_version`` is the lowest ``below`` bound of the matched ranges."""
    assert provider.match("jquery", "3.4.1")[0].first_safe_version == "3.5.0"
    assert provider.match("jquery", "1.4.0")[0].first_safe_version == "1.6.3"


def test_first_safe_version_is_the_lowest_bound_of_overlapping_ranges() -> None:
    """
    Two ranges of one entry can both hold the version (the vendored ember entries do: a
    backport fix and a ``below`` for the whole line); the lower ``below`` is the one reported.
    """
    raw = json.loads(_MINI.read_text("utf-8"))
    raw["components"]["lodash"]["vulnerabilities"][0]["ranges"] = [
        {"below": "1.5.0"},
        {"atOrAbove": "1.2.0", "below": "1.2.2"},
    ]
    provider = RetireJsProvider(RetireJsRules.from_raw(raw, _PROVENANCE))
    assert [a.first_safe_version for a in provider.match("lodash", "1.2.1")] == ["1.2.2"]


def test_unknown_library_and_clean_version(provider: RetireJsProvider) -> None:
    """An unknown library, or a version above every range, yields no advisories."""
    assert provider.match("react", "16.0.0") == []
    assert provider.match("lodash", "5.0.0") == []


def test_loose_version_string_compares_by_its_numbers(provider: RetireJsProvider) -> None:
    """A non-PEP-440 version compares by its leading numbers, inside a range and past every one."""
    assert _ids(provider, "jquery", "1.4.0-custom.build") == [_OLD_XSS, _HTML_XSS]
    assert _ids(provider, "jquery", "9.0.0-custom.build") == []


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


def test_a_severity_other_than_the_default_is_read_from_the_entry() -> None:
    """The mini DB only says ``medium``, which is also the default: ``High`` must come out HIGH."""
    raw = json.loads(_MINI.read_text("utf-8"))
    raw["components"]["lodash"]["vulnerabilities"][0]["severity"] = "High"
    provider = RetireJsProvider(RetireJsRules.from_raw(raw, _PROVENANCE))
    (lodash,) = provider.match("lodash", "4.0.0")
    assert lodash.severity is Severity.HIGH
    assert lodash.severity_from_upstream is True


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


def test_merge_keeps_the_earliest_bucket_when_an_advisory_bridges_two() -> None:
    """An advisory sharing ids with two buckets joins the earlier one; the buckets stay apart."""
    a = _adv("A", "CVE-1")
    b = _adv("B", "CVE-2")
    bridge = _adv("C", "CVE-2", "CVE-1")
    merged = merge_advisories([a, b, bridge])
    assert [m.identifiers for m in merged] == [("A", "CVE-1", "C", "CVE-2"), ("B", "CVE-2")]


def test_a_version_past_the_int_string_limit_does_not_raise() -> None:
    """PEP 440 parsing of a 5000-digit release segment falls back instead of raising."""
    assert _pep440("1." + "9" * 5000) is None

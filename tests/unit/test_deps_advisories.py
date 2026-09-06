"""RetireJsProvider: range semantics, severity mapping, first safe version — RF-07, RF-08."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from webvigil.checks.deps._data import Provenance
from webvigil.checks.deps.advisories import RetireJsProvider
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
    return RetireJsProvider(
        RetireJsRules.from_raw(json.loads(_MINI.read_text("utf-8")), _PROVENANCE)
    )


def test_below_only_range_matches_old_version(provider: RetireJsProvider) -> None:
    hits = provider.match("jquery", "1.4.0")
    assert any("CVE-2011-4969" in a.identifiers for a in hits)


def test_at_or_above_and_below_range(provider: RetireJsProvider) -> None:
    assert provider.match("jquery", "3.4.1")  # inside [1.0.0, 3.5.0)
    assert not any(  # 3.6.0 is above every jquery range in the mini DB
        "CVE-2020-11022" in a.identifiers for a in provider.match("jquery", "3.6.0")
    )


def test_boundary_is_exclusive(provider: RetireJsProvider) -> None:
    # 3.5.0 == below bound -> not vulnerable for that entry
    assert not any("CVE-2020-11022" in a.identifiers for a in provider.match("jquery", "3.5.0"))


def test_severity_maps_and_defaults(provider: RetireJsProvider) -> None:
    jquery = provider.match("jquery", "1.4.0")[0]
    assert jquery.severity is Severity.MEDIUM
    assert jquery.severity_from_upstream is True

    lodash = provider.match("lodash", "4.0.0")[0]  # mini DB entry has no severity
    assert lodash.severity is Severity.MEDIUM
    assert lodash.severity_from_upstream is False


def test_first_safe_version(provider: RetireJsProvider) -> None:
    assert provider.match("jquery", "3.4.1")[0].first_safe_version == "3.5.0"
    assert provider.match("jquery", "1.4.0")[0].first_safe_version == "1.6.3"


def test_unknown_library_and_clean_version(provider: RetireJsProvider) -> None:
    assert provider.match("react", "16.0.0") == []
    assert provider.match("lodash", "5.0.0") == []


def test_loose_version_string_does_not_crash(provider: RetireJsProvider) -> None:
    # A non-PEP-440 string still compares via the numeric fallback.
    assert provider.match("jquery", "1.4.0-custom.build")

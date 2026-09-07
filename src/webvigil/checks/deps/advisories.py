"""Match a detected ``(library, version)`` against advisories (spec 004, RF-07, RF-08, RF-11).

``AdvisoryProvider`` is the seam an online provider (OSV, GitHub Advisories) would implement
in a later spec; nothing in the fingerprinter or the checks would change. 004 ships one
implementation, :class:`RetireJsProvider`, backed entirely by the vendored file — no network.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from packaging.version import InvalidVersion, Version

from webvigil.checks.deps.rules import RetireJsRules, VulnerabilityEntry
from webvigil.core.findings import Severity

_SEVERITY_BY_NAME = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_DEFAULT_SEVERITY = Severity.MEDIUM
_NUMERIC_RE = re.compile(r"\d+")


@dataclass(frozen=True)
class Advisory:
    """One vulnerability affecting the detected version, in WebVigil's native shape."""

    identifiers: tuple[str, ...]
    summary: str
    severity: Severity
    severity_from_upstream: bool
    first_safe_version: str | None
    info_urls: tuple[str, ...]
    cwe: tuple[int, ...]


class AdvisoryProvider(Protocol):
    def match(self, name: str, version: str) -> list[Advisory]: ...


def _pep440(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def numeric_version_key(raw: str) -> tuple[int, ...]:
    """Leading dotted-numeric parts of a version, for a loose fallback comparison."""
    return tuple(int(n) for n in _NUMERIC_RE.findall(raw)[:4]) or (0,)


def _lt(left: str, right: str) -> bool:
    a, b = _pep440(left), _pep440(right)
    if a is not None and b is not None:
        return a < b
    return numeric_version_key(left) < numeric_version_key(right)


def _in_range(version: str, at_or_above: str | None, below: str | None) -> bool:
    if at_or_above is not None and _lt(version, at_or_above):
        return False
    return not (below is not None and not _lt(version, below))


class RetireJsProvider:
    """Reads the compiled rules only. No network I/O (RF-11)."""

    def __init__(self, rules: RetireJsRules) -> None:
        self._rules = rules

    def match(self, name: str, version: str) -> list[Advisory]:
        advisories: list[Advisory] = []
        for entry in self._rules.vulnerabilities_for(name):
            matched = [
                (above, below) for above, below in entry.ranges if _in_range(version, above, below)
            ]
            if not matched:
                continue
            advisories.append(_advisory(entry, matched))
        return advisories


def _advisory(
    entry: VulnerabilityEntry, matched_ranges: list[tuple[str | None, str | None]]
) -> Advisory:
    severity_name = (entry.severity or "").lower()
    severity = _SEVERITY_BY_NAME.get(severity_name, _DEFAULT_SEVERITY)
    safe_bounds = sorted((below for _, below in matched_ranges if below), key=numeric_version_key)
    return Advisory(
        identifiers=entry.identifiers,
        summary=entry.summary,
        severity=severity,
        severity_from_upstream=severity_name in _SEVERITY_BY_NAME,
        first_safe_version=safe_bounds[0] if safe_bounds else None,
        info_urls=entry.info,
        cwe=entry.cwe,
    )


def default_provider() -> RetireJsProvider:
    """The process-wide provider over the vendored database."""
    return RetireJsProvider(RetireJsRules.load())


def merge_advisories(*groups: Iterable[Advisory]) -> list[Advisory]:
    """Coalesce advisories that share any identifier into one (spec 010, RF-08).

    Two advisories describe the same vulnerability when their identifier sets intersect (a
    shared CVE / GHSA / OSV id). Such advisories — typically the vendored Retire.js entry
    and the OSV record for the same CVE — are merged: the union of identifiers, info URLs
    and CWE ids, the higher severity, and the most conservative safe version. Advisories
    with disjoint identifiers stay separate. Deterministic: input order is preserved.
    """
    buckets: list[list[Advisory]] = []
    for advisory in itertools.chain.from_iterable(groups):
        ids = set(advisory.identifiers)
        bucket = next((b for b in buckets if ids & {i for a in b for i in a.identifiers}), None)
        if bucket is None:
            buckets.append([advisory])
        else:
            bucket.append(advisory)
    return [_coalesce(bucket) for bucket in buckets]


def _coalesce(bucket: list[Advisory]) -> Advisory:
    if len(bucket) == 1:
        return bucket[0]
    identifiers = tuple(dict.fromkeys(i for a in bucket for i in a.identifiers))
    info_urls = tuple(dict.fromkeys(u for a in bucket for u in a.info_urls))
    cwe = tuple(dict.fromkeys(c for a in bucket for c in a.cwe))
    summaries = list(dict.fromkeys(a.summary for a in bucket if a.summary))
    safe = [a.first_safe_version for a in bucket if a.first_safe_version]
    return Advisory(
        identifiers=identifiers,
        summary=" / ".join(summaries),
        severity=max(a.severity for a in bucket),
        severity_from_upstream=any(a.severity_from_upstream for a in bucket),
        first_safe_version=max(safe, key=numeric_version_key) if safe else None,
        info_urls=info_urls,
        cwe=cwe,
    )

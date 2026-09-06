"""Deterministic finding ordering shared by every reporter (RNF-04)."""

from __future__ import annotations

from webvigil.core.findings import Finding


def sort_findings(findings: tuple[Finding, ...]) -> list[Finding]:
    """Severity descending, then check id, URL, sub-location."""
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), f.check_id, f.location.url, f.location.key),
    )

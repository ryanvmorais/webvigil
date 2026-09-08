"""Deterministic finding ordering shared by every reporter (RNF-04)."""

from __future__ import annotations

from webvigil.core.findings import Finding


def sort_findings(findings: tuple[Finding, ...]) -> list[Finding]:
    """
    Order findings for display.

    Args:
        findings (tuple[Finding, ...]): The findings to order.

    Returns:
        list[Finding]: Sorted by severity descending, then check id, URL, and
            sub-location — a total order, so every reporter renders the same
            sequence.
    """
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), f.check_id, f.location.url, f.location.key),
    )

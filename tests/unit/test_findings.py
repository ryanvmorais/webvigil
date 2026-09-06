"""Finding model, fingerprinting, and severity ordering — RF-12, RF-13."""

from __future__ import annotations

from webvigil.core import Confidence, EvidenceItem, Finding, Location, Severity, compute_fingerprint


def _finding(url: str = "https://example.com/", dedup_key: str = "missing") -> Finding:
    location = Location(url=url, header="Content-Security-Policy")
    return Finding(
        check_id="http.headers.csp",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="CSP missing",
        description="No Content-Security-Policy header.",
        location=location,
        remediation="Add a Content-Security-Policy header.",
        fingerprint=compute_fingerprint("http.headers.csp", location, dedup_key),
    )


def test_severity_is_ordered() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.from_name("high") is Severity.HIGH


def test_fingerprint_is_stable_across_calls() -> None:
    loc = Location(url="https://example.com/", header="X")
    assert compute_fingerprint("c", loc, "k") == compute_fingerprint("c", loc, "k")
    assert len(compute_fingerprint("c", loc, "k")) == 16


def test_fingerprint_varies_with_inputs() -> None:
    loc = Location(url="https://example.com/", header="X")
    other = Location(url="https://example.com/other", header="X")
    assert compute_fingerprint("c", loc, "k") != compute_fingerprint("c", loc, "k2")
    assert compute_fingerprint("c", loc, "k") != compute_fingerprint("c", other, "k")
    assert compute_fingerprint("c", loc, "k") != compute_fingerprint("c2", loc, "k")


def test_equal_findings_share_a_fingerprint() -> None:
    assert _finding().fingerprint == _finding().fingerprint
    assert _finding(dedup_key="a").fingerprint != _finding(dedup_key="b").fingerprint


def test_finding_is_frozen() -> None:
    finding = _finding()
    try:
        finding.title = "changed"  # type: ignore[misc]
    except (AttributeError, TypeError, ValueError):
        return
    raise AssertionError("Finding should be immutable")


def test_evidence_item_trims_long_content() -> None:
    item = EvidenceItem.of("body", "x" * 5000)
    assert len(item.content) < 5000
    assert item.content.endswith("[truncated]")

"""
Finding model, fingerprinting, and severity ordering — RF-12, RF-13.
"""

from __future__ import annotations

from webvigil.core import Confidence, EvidenceItem, Finding, Location, Severity, compute_fingerprint
from webvigil.core.findings import Category


def _finding(url: str = "https://example.com/", dedup_key: str = "missing") -> Finding:
    """
    Build a minimal CSP finding for the fingerprint / immutability tests.

    Args:
        url (str): The location URL.
        dedup_key (str): The fingerprint dedup key.

    Returns:
        Finding: The assembled finding.
    """
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


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_is_ordered() -> None:
    """Severity compares INFO < LOW < ... < CRITICAL and resolves from its name."""
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.from_name("high") is Severity.HIGH


def test_category_http_is_a_plain_string_member() -> None:
    """``Category.HTTP`` (spec 012) is a ``StrEnum`` value that serialises to ``"HTTP"``."""
    assert Category.HTTP == "HTTP"
    assert str(Category.HTTP) == "HTTP"
    assert Category("HTTP") is Category.HTTP


def test_category_content_is_a_plain_string_member() -> None:
    """``Category.CONTENT`` (spec 013) is a ``StrEnum`` value that serialises to ``"CONTENT"``."""
    assert Category.CONTENT == "CONTENT"
    assert str(Category.CONTENT) == "CONTENT"
    assert Category("CONTENT") is Category.CONTENT


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


def test_fingerprint_is_stable_across_calls() -> None:
    """The same inputs always hash to the same 16-char digest."""
    loc = Location(url="https://example.com/", header="X")
    assert compute_fingerprint("c", loc, "k") == compute_fingerprint("c", loc, "k")
    assert len(compute_fingerprint("c", loc, "k")) == 16


def test_fingerprint_varies_with_inputs() -> None:
    """Changing the check id, the location, or the dedup key changes the fingerprint."""
    loc = Location(url="https://example.com/", header="X")
    other = Location(url="https://example.com/other", header="X")
    assert compute_fingerprint("c", loc, "k") != compute_fingerprint("c", loc, "k2")
    assert compute_fingerprint("c", loc, "k") != compute_fingerprint("c", other, "k")
    assert compute_fingerprint("c", loc, "k") != compute_fingerprint("c2", loc, "k")


def test_equal_findings_share_a_fingerprint() -> None:
    """Two findings built identically collapse; a different dedup key keeps them apart."""
    assert _finding().fingerprint == _finding().fingerprint
    assert _finding(dedup_key="a").fingerprint != _finding(dedup_key="b").fingerprint


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


def test_finding_is_frozen() -> None:
    """A ``Finding`` rejects attribute assignment."""
    finding = _finding()
    try:
        finding.title = "changed"  # type: ignore[misc]
    except (AttributeError, TypeError, ValueError):
        return
    raise AssertionError("Finding should be immutable")


def test_evidence_item_trims_long_content() -> None:
    """``EvidenceItem.of`` bounds the content and appends a truncation marker."""
    item = EvidenceItem.of("body", "x" * 5000)
    assert len(item.content) < 5000
    assert item.content.endswith("[truncated]")

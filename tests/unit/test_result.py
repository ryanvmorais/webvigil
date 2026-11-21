"""ScanResult JSON round-trip — RF-21 — and the counts it keeps in step with its findings."""

from __future__ import annotations

import warnings
from datetime import UTC, datetime

from webvigil.core import (
    CheckError,
    Confidence,
    Finding,
    Location,
    ScanMetadata,
    ScanMode,
    ScanResult,
    Scope,
    Severity,
    compute_fingerprint,
)


def _result() -> ScanResult:
    """
    Returns:
        ScanResult: A result with one finding, one check error and one warning —
            enough to exercise every branch of the JSON serialisation.
    """
    loc = Location(url="https://example.com/", header="Strict-Transport-Security")
    finding = Finding(
        check_id="http.headers.hsts",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="HSTS missing",
        description="No Strict-Transport-Security header on an HTTPS response.",
        location=loc,
        remediation="Send Strict-Transport-Security with a long max-age.",
        cwe=(319,),
        references=("https://owasp.org/",),
        fingerprint=compute_fingerprint("http.headers.hsts", loc, ""),
    )
    findings = (finding,)
    metadata = ScanMetadata(
        target="https://example.com/",
        mode=ScanMode.PASSIVE,
        scope=Scope.HOST,
        tool_version="0.0.0.dev0",
        started_at=datetime(2026, 9, 6, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 6, 12, 0, 3, tzinfo=UTC),
        pages_scanned=1,
        counts=ScanResult.severity_counts(findings),
    )
    return ScanResult(
        metadata=metadata,
        findings=findings,
        errors=(CheckError(check_id="tls.https", message="boom", traceback="..."),),
        warnings=("unknown disabled check id: nope",),
    )


def test_json_round_trip_is_lossless() -> None:
    """Serialising a result to JSON and back reproduces it exactly (the canonical format)."""
    original = _result()
    restored = ScanResult.model_validate_json(original.model_dump_json())
    assert restored == original


def test_severity_counts_has_all_buckets() -> None:
    """Every severity name is present in the counts, at zero, even with no findings."""
    counts = ScanResult.severity_counts(())
    assert counts == {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def test_constructor_recomputes_counts_that_disagree_with_the_findings() -> None:
    """
    ``ScanResult(...)`` gets the same recount as ``model_validate``, without a Pydantic warning.

    A model validator that returns a copy is dropped when the model is built through its
    constructor (#313), so the recount has to land on the instance itself.
    """
    findings = _result().findings
    stale = _result().metadata.model_copy(update={"counts": ScanResult.severity_counts(())})

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        built = ScanResult(metadata=stale, findings=findings)

    assert built.metadata.counts[Severity.MEDIUM.name] == 1
    assert built == ScanResult.model_validate({"metadata": stale, "findings": findings})
    assert stale.counts[Severity.MEDIUM.name] == 0, "the caller's metadata is not changed"

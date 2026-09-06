"""ScanResult JSON round-trip — RF-21."""

from __future__ import annotations

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
    original = _result()
    restored = ScanResult.model_validate_json(original.model_dump_json())
    assert restored == original


def test_severity_counts_has_all_buckets() -> None:
    counts = ScanResult.severity_counts(())
    assert counts == {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

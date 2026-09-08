"""
The unrestricted-file-upload check — spec 014 RF-07, RF-17.

``_hit`` builds an :class:`~webvigil.checks.upload.scanner.UploadHit` as the
:class:`~webvigil.checks.upload.scanner.UploadScanner` pass would leave it on
``Observations.upload_hits``; the check issues no HTTP.
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.upload.checks import UnrestrictedUploadCheck
from webvigil.checks.upload.scanner import UploadHit
from webvigil.core.context import Observations
from webvigil.core.findings import Category, Confidence, ScanMode, Severity


def _hit(outcome: str, *, severity: Severity, field: str | None = "avatar") -> UploadHit:
    return UploadHit(
        outcome=outcome,
        url="https://example.com/upload",
        method="PUT" if field is None else "POST",
        field=field,
        retrieved_from="https://example.com/files/wvabc.php",
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"{outcome} at /upload",
        payload_name="wvabc.php",
        evidence=(
            ("Upload endpoint", "POST https://example.com/upload"),
            ("Payload file", "wvabc.php"),
        ),
    )


def test_check_metadata() -> None:
    """``upload.unrestricted`` is an Active ``Category.UPLOAD`` check, HIGH, CWE-434."""
    assert UnrestrictedUploadCheck.id == "upload.unrestricted"
    assert UnrestrictedUploadCheck.category is Category.UPLOAD
    assert UnrestrictedUploadCheck.mode is ScanMode.ACTIVE
    assert UnrestrictedUploadCheck.default_severity is Severity.HIGH
    assert 434 in UnrestrictedUploadCheck.cwe


async def test_one_finding_per_hit_with_the_hit_severity() -> None:
    """Each ``UploadHit`` becomes one finding carrying the hit's severity."""
    hits = (
        _hit("server-exec", severity=Severity.CRITICAL),
        _hit("inline-html", severity=Severity.HIGH),
        _hit("put-upload", severity=Severity.HIGH, field=None),
    )
    ctx = make_context(make_page(), observations=Observations(upload_hits=hits))
    findings = await UnrestrictedUploadCheck().run(ctx)
    assert len(findings) == 3
    assert {f.severity for f in findings} == {Severity.CRITICAL, Severity.HIGH}
    assert findings[0].location.url == "https://example.com/upload"
    assert findings[2].location.method == "PUT"


async def test_distinct_outcomes_on_one_field_are_distinct_findings() -> None:
    """The per-(field, outcome) dedup key keeps two outcomes on one field separate."""
    ctx = make_context(
        make_page(),
        observations=Observations(
            upload_hits=(
                _hit("server-exec", severity=Severity.CRITICAL),
                _hit("inert-accept", severity=Severity.MEDIUM),
                _hit("put-upload", severity=Severity.HIGH, field=None),
            )
        ),
    )
    findings = await UnrestrictedUploadCheck().run(ctx)
    assert len({f.fingerprint for f in findings}) == 3


async def test_no_hits_means_no_findings() -> None:
    """With no upload hits the check is silent."""
    ctx = make_context(make_page(), observations=Observations())
    assert await UnrestrictedUploadCheck().run(ctx) == []

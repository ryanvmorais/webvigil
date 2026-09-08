"""
The injection checks filter hits by kind into findings — spec 006 RF-08..RF-11,
plus stored XSS (spec 008) and SSRF (spec 009).

``_hit`` builds an :class:`~webvigil.checks.injection.models.InjectionHit` as the
scanner passes would leave it on ``Observations.injection_hits``; the checks
issue no HTTP.
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.injection.checks import (
    OpenRedirectCheck,
    OsCommandInjectionCheck,
    PathTraversalCheck,
    ReflectedXssCheck,
    SqliBooleanBasedCheck,
    SqliErrorBasedCheck,
    SqliTimeBasedCheck,
    SsrfInternalCheck,
    SsrfMetadataCheck,
    StoredXssCheck,
    TemplateInjectionCheck,
)
from webvigil.checks.injection.models import InjectionHit
from webvigil.core.context import Observations
from webvigil.core.findings import Category, Confidence, ScanMode, Severity


def _hit(kind: str) -> InjectionHit:
    """
    Args:
        kind (str): The detector kind the hit carries.

    Returns:
        InjectionHit: A HIGH-severity hit at ``POST https://example.com/s`` on
            parameter ``q``.
    """
    return InjectionHit(
        kind=kind,
        check_id="x",
        method="POST",
        url="https://example.com/s",
        param="q",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title=f"{kind} via the 'q' parameter",
        payload="payload",
        evidence=(("Injection point", "POST https://example.com/s"), ("Payload", "payload")),
    )


_ALL = [
    (ReflectedXssCheck, "xss"),
    (SqliErrorBasedCheck, "sqli-error"),
    (SqliBooleanBasedCheck, "sqli-boolean"),
    (SqliTimeBasedCheck, "sqli-time"),
    (PathTraversalCheck, "traversal"),
    (OpenRedirectCheck, "redirect"),
    (StoredXssCheck, "xss-stored"),
    (SsrfMetadataCheck, "ssrf-metadata"),
    (SsrfInternalCheck, "ssrf-internal"),
    (OsCommandInjectionCheck, "cmdi"),
    (TemplateInjectionCheck, "ssti"),
]


async def test_each_check_emits_only_its_own_kind() -> None:
    """Given one hit of every kind, each check turns exactly its own into a finding."""
    hits = tuple(_hit(kind) for _, kind in _ALL)
    ctx = make_context(make_page(), observations=Observations(injection_hits=hits))
    for check_cls, kind in _ALL:
        findings = await check_cls().run(ctx)
        assert len(findings) == 1, kind
        finding = findings[0]
        assert finding.check_id == check_cls.id
        assert finding.location.param == "q"
        assert finding.location.method == "POST"
        assert finding.location.url == "https://example.com/s"
        assert finding.evidence[1].label == "Payload"


async def test_checks_are_active_injection_category() -> None:
    """Every injection check is ``Category.INJECTION`` and Active-only."""
    for check_cls, _ in _ALL:
        assert check_cls.category is Category.INJECTION
        assert check_cls.mode is ScanMode.ACTIVE


async def test_no_hits_means_no_findings() -> None:
    """With no hits on the context, every injection check is silent."""
    ctx = make_context(make_page(), observations=Observations())
    for check_cls, _ in _ALL:
        assert await check_cls().run(ctx) == []


async def test_stored_xss_check_metadata_and_finding() -> None:
    """The stored-XSS finding is located at the injection point; the render page is evidence."""
    assert StoredXssCheck.id == "injection.xss.stored"
    assert StoredXssCheck.default_severity is Severity.HIGH
    hit = InjectionHit(
        kind="xss-stored",
        check_id="injection.xss.stored",
        method="POST",
        url="https://example.com/guestbook",
        param="body",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Stored XSS: the 'body' field of POST https://example.com/guestbook renders …",
        payload="<wvstoredabc>",
        evidence=(
            ("Injection point", "POST https://example.com/guestbook — parameter 'body'"),
            ("Rendered on", "https://example.com/guestbook/e/0"),
        ),
    )
    ctx = make_context(make_page(), observations=Observations(injection_hits=(hit,)))
    findings = await StoredXssCheck().run(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.location.url == "https://example.com/guestbook"  # the injection point
    assert finding.location.method == "POST"
    assert finding.location.param == "body"
    rendered_on = {e.label: e.content for e in finding.evidence}["Rendered on"]
    assert rendered_on.endswith("/e/0")


async def test_ssrf_checks_metadata_and_finding_shape() -> None:
    """The metadata check emits a CRITICAL CWE-918 finding; the internal check ignores that kind."""
    assert SsrfMetadataCheck.id == "injection.ssrf.metadata"
    assert SsrfMetadataCheck.default_severity is Severity.CRITICAL
    assert SsrfInternalCheck.default_severity is Severity.HIGH
    assert 918 in SsrfMetadataCheck.cwe and 918 in SsrfInternalCheck.cwe

    hit = InjectionHit(
        kind="ssrf-metadata",
        check_id="injection.ssrf.metadata",
        method="GET",
        url="https://example.com/fetch",
        param="url",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="SSRF to the AWS instance metadata service via the 'url' parameter",
        payload="http://169.254.169.254/latest/meta-data/",
        evidence=(
            ("Injection point", "GET https://example.com/fetch — parameter 'url'"),
            ("Payload", "http://169.254.169.254/latest/meta-data/"),
            ("AWS metadata marker", '{"AccessKeyId":"ASIA...'),
        ),
    )
    ctx = make_context(make_page(), observations=Observations(injection_hits=(hit,)))
    findings = await SsrfMetadataCheck().run(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.location.url == "https://example.com/fetch"
    assert finding.location.param == "url"
    assert "AccessKeyId" in {e.label: e.content for e in finding.evidence}["AWS metadata marker"]
    assert any("Server_Side_Request_Forgery" in r for r in finding.references)
    # the internal check ignores a metadata-kind hit
    assert await SsrfInternalCheck().run(ctx) == []


async def test_cmdi_and_ssti_check_metadata_and_finding_shape() -> None:
    """``injection.cmdi.os`` is a CRITICAL CWE-78 finding; ``injection.ssti`` is HIGH CWE-1336."""
    assert OsCommandInjectionCheck.id == "injection.cmdi.os"
    assert OsCommandInjectionCheck.default_severity is Severity.CRITICAL
    assert 78 in OsCommandInjectionCheck.cwe
    assert TemplateInjectionCheck.id == "injection.ssti"
    assert TemplateInjectionCheck.default_severity is Severity.HIGH
    assert 1336 in TemplateInjectionCheck.cwe

    hit = InjectionHit(
        kind="cmdi",
        check_id="injection.cmdi.os",
        method="GET",
        url="https://example.com/ping",
        param="host",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="OS command injection via the 'host' parameter",
        payload="localhost;echo wvabc=221",
        evidence=(
            ("Injection point", "GET https://example.com/ping — parameter 'host'"),
            ("Payload", "localhost;echo wvabc=221"),
            ("Command output", "wvabc=221"),
        ),
    )
    ctx = make_context(make_page(), observations=Observations(injection_hits=(hit,)))
    findings = await OsCommandInjectionCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].location.param == "host"
    assert await TemplateInjectionCheck().run(ctx) == []  # ignores a cmdi-kind hit

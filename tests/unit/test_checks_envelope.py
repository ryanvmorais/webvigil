"""
The request-envelope checks filter ``EnvelopeHit``s into findings — spec 012 RF-08, RF-10.

``_hit`` builds an :class:`~webvigil.checks.envelope.scanner.EnvelopeHit` as the
pass would leave it on ``Observations.envelope_hits``; the checks issue no HTTP.
"""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.envelope.checks import HostHeaderCheck, HttpMethodsCheck
from webvigil.checks.envelope.scanner import EnvelopeHit
from webvigil.core.context import Observations
from webvigil.core.findings import Category, Confidence, ScanMode, Severity


def _hit(check_id: str, **kw: object) -> EnvelopeHit:
    base: dict[str, object] = {
        "check_id": check_id,
        "url": "https://example.com/reset",
        "method": "GET",
        "param": "X-Forwarded-Host",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "title": f"{check_id} finding",
        "evidence": (("Poisoned header", "X-Forwarded-Host: webvigil.invalid"),),
    }
    base.update(kw)
    return EnvelopeHit(**base)  # type: ignore[arg-type]


async def test_host_header_check_metadata_and_finding() -> None:
    assert HostHeaderCheck.id == "injection.host-header"
    assert HostHeaderCheck.category is Category.INJECTION
    assert HostHeaderCheck.mode is ScanMode.ACTIVE
    assert 644 in HostHeaderCheck.cwe

    hit = _hit("injection.host-header", severity=Severity.HIGH)
    ctx = make_context(make_page(), observations=Observations(envelope_hits=(hit,)))
    findings = await HostHeaderCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.param == "X-Forwarded-Host"
    # the methods check ignores a host-header hit
    assert await HttpMethodsCheck().run(ctx) == []


async def test_http_methods_check_metadata_and_finding() -> None:
    assert HttpMethodsCheck.id == "http.methods.unsafe"
    assert HttpMethodsCheck.category is Category.HTTP
    assert {650, 693, 16} <= set(HttpMethodsCheck.cwe)

    hit = _hit("http.methods.unsafe", method="TRACE", param=None, confidence=Confidence.HIGH)
    ctx = make_context(make_page(), observations=Observations(envelope_hits=(hit,)))
    findings = await HttpMethodsCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].location.method == "TRACE"
    assert await HostHeaderCheck().run(ctx) == []


async def test_no_hits_means_no_findings() -> None:
    ctx = make_context(make_page(), observations=Observations())
    assert await HostHeaderCheck().run(ctx) == []
    assert await HttpMethodsCheck().run(ctx) == []

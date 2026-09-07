"""The six injection checks filter hits by kind into findings — spec 006 RF-08..RF-11."""

from __future__ import annotations

from tests.support import make_context, make_page
from webvigil.checks.injection.checks import (
    OpenRedirectCheck,
    PathTraversalCheck,
    ReflectedXssCheck,
    SqliBooleanBasedCheck,
    SqliErrorBasedCheck,
    SqliTimeBasedCheck,
    StoredXssCheck,
)
from webvigil.checks.injection.models import InjectionHit
from webvigil.core.context import Observations
from webvigil.core.findings import Category, Confidence, ScanMode, Severity


def _hit(kind: str) -> InjectionHit:
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
]


async def test_each_check_emits_only_its_own_kind() -> None:
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
    for check_cls, _ in _ALL:
        assert check_cls.category is Category.INJECTION
        assert check_cls.mode is ScanMode.ACTIVE


async def test_no_hits_means_no_findings() -> None:
    ctx = make_context(make_page(), observations=Observations())
    for check_cls, _ in _ALL:
        assert await check_cls().run(ctx) == []


async def test_stored_xss_check_metadata_and_finding() -> None:
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
